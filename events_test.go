package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func loginRule(t *testing.T) *Rule {
	t.Helper()
	r, err := newRule(RuleConfig{
		Name:     "ssh_login",
		Journald: []string{"ssh.service"},
		Patterns: []string{`Accepted (?P<method>\S+) for (?P<user>\S+) from <ip> port \d+ ssh2(?:: \S+ (?P<key>SHA256:\S+))?`},
		Report:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportRuleConfig(t *testing.T) {
	_, err := newRule(RuleConfig{Name: "x", Journald: []string{"ssh.service"}, Patterns: []string{"from <ip>"}, Report: true, Threshold: 5})
	if err == nil || !strings.Contains(err.Error(), "never bans") {
		t.Fatalf("a report rule with a threshold: %v", err)
	}
	if _, err := newRule(RuleConfig{Name: "x", Journald: []string{"ssh.service"}, Patterns: []string{"from <ip>"}}); err == nil {
		t.Fatal("a ban rule without threshold must still fail")
	}
}

func TestMatchFields(t *testing.T) {
	r := loginRule(t)
	ip, _, f, ok := r.matchFields("Accepted publickey for deploy from 203.0.113.9 port 50000 ssh2: ED25519 SHA256:abcDEF123")
	if !ok || ip.String() != "203.0.113.9" || f["user"] != "deploy" || f["method"] != "publickey" || f["key"] != "SHA256:abcDEF123" {
		t.Fatalf("got %v %v %v", ip, f, ok)
	}
	_, _, f, _ = r.matchFields("Accepted password for sysop from 203.0.113.9 port 50000 ssh2")
	if _, has := f["key"]; has || len(f) != 2 {
		t.Fatalf("an empty group must be left out: %v", f)
	}
}

// eventServer records the /events POSTs; status 0 answers 204.
func eventServer(t *testing.T, status int) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/bans/events" || r.Header.Get("X-Signature") != sign(r.Header.Get("X-Timestamp"), string(body), "s") {
			w.WriteHeader(403)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return got }
}

func TestEventsDeduplicatedAndSent(t *testing.T) {
	srv, got := eventServer(t, 0)
	r := loginRule(t)
	cfg := &Config{rules: []*Rule{r}, ignore: []netip.Prefix{mustTarget("10.0.0.0/8")}}
	a := newAgent(cfg, fakeFirewall{}, newState())
	a.central = &Central{url: srv.URL + "/bans", source: "vps-01", secret: "s", client: srv.Client()}

	t0 := time.Unix(1_700_000_000, 0).UTC()
	line := "Accepted publickey for deploy from 203.0.113.9 port 50000 ssh2: ED25519 SHA256:abc"
	send := func(line string, at time.Time) {
		ip, p, f, ok := r.matchFields(line)
		if !ok {
			t.Fatalf("no match: %s", line)
		}
		a.event(context.Background(), Event{Rule: r.Name, Pattern: p, IP: ip, Fields: f, Line: line, At: at})
	}
	send(line, t0)
	send(line, t0.Add(time.Hour))                                                // same event: skipped
	send(strings.Replace(line, "deploy", "root", 1), t0.Add(time.Hour))          // other user: sent
	send(strings.Replace(line, "203.0.113.9", "10.1.2.3", 1), t0.Add(time.Hour)) // ignored IP: sent, marked
	send(line, t0.Add(eventEvery))                                               // a day later: sent again
	a.reports.Wait()

	events := got()
	if len(events) != 4 {
		t.Fatalf("sent %d events, want 4: %v", len(events), events)
	}
	var e map[string]any // the first one; sends are concurrent, so look it up
	for _, ev := range events {
		if ev["at"] == "2023-11-14T22:13:20Z" {
			e = ev
		}
	}
	fields, _ := e["fields"].(map[string]any)
	if e["source"] != "vps-01" || e["rule"] != "ssh_login" || e["ip"] != "203.0.113.9" || fields["user"] != "deploy" || fields["key"] != "SHA256:abc" || e["ignored"] != false || e["at"] != "2023-11-14T22:13:20Z" {
		t.Errorf("event = %v", e)
	}
	if line, _ := e["line"].(string); strings.Contains(line, "203.0.113.9") || !strings.Contains(line, "from <ip> port") {
		t.Errorf("the line must not carry the IP: %q", line)
	}
	var ignored int
	for _, e := range events {
		if e["ignored"] == true {
			ignored++
		}
	}
	if ignored != 1 {
		t.Errorf("want one event marked ignored, got %d", ignored)
	}
	if n := a.heartbeat().Matches["ssh_login"]; n != 5 {
		t.Errorf("matches = %d, want 5 (skipped ones count too)", n)
	}
}

func TestEventsStopOnOldCentral(t *testing.T) {
	srv, got := eventServer(t, 404)
	r := loginRule(t)
	a := newAgent(&Config{rules: []*Rule{r}}, fakeFirewall{}, newState())
	a.central = &Central{url: srv.URL + "/bans", source: "vps-01", secret: "s", client: srv.Client()}

	t0 := time.Unix(1_700_000_000, 0)
	for i := range 3 {
		ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		a.event(context.Background(), Event{Rule: r.Name, IP: ip, At: t0})
		a.reports.Wait()
	}
	if n := len(got()); n != 1 {
		t.Fatalf("after a 404 the agent must stop sending events: sent %d", n)
	}
}

func TestHeartbeatMatchesKeptUntilSent(t *testing.T) {
	r := sshRule(t)
	a := newAgent(&Config{rules: []*Rule{r}}, fakeFirewall{}, newState())
	r.matched.Add(7)

	hb := a.heartbeat()
	if hb.Matches["ssh_bruteforce"] != 7 || r.matched.Load() != 0 {
		t.Fatalf("heartbeat took %v, left %d", hb.Matches, r.matched.Load())
	}
	r.matched.Add(2) // while the heartbeat was failing
	a.unsend(hb)
	if got := a.heartbeat().Matches["ssh_bruteforce"]; got != 9 {
		t.Fatalf("after a failed heartbeat: %d, want 9", got)
	}
}

func TestReportRuleNeverBansInJudge(t *testing.T) {
	r := loginRule(t)
	tl := newTally()
	for range 50 {
		tl.add(r, "Accepted password for sysop from 203.0.113.9 port 1 ssh2", false)
	}
	var out strings.Builder
	bans, _ := judge(&out, []*Rule{r}, map[*Rule]*tally{r: tl}, func(netip.Prefix) bool { return false }, nil, time.Now())
	if bans != 0 || strings.Contains(out.String(), "would ban") || !strings.Contains(out.String(), "report only") {
		t.Fatalf("bans=%d\n%s", bans, out.String())
	}
}
