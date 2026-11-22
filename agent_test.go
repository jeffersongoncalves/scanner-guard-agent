package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func sshRule(t *testing.T) *Rule {
	t.Helper()
	r, err := newRule(RuleConfig{
		Name:     "ssh_bruteforce",
		Journald: []string{"ssh.service"},
		Patterns: []string{
			`Failed password for (invalid user )?\S+ from <ip> port`,
			`Invalid user \S* from <ip> port`,
		},
		Threshold: 3,
		Window:    Duration(10 * time.Minute),
		Ban:       []Duration{Duration(time.Hour), Duration(24 * time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMatch(t *testing.T) {
	r := sshRule(t)
	cases := map[string]string{
		"Failed password for root from 203.0.113.7 port 51234 ssh2":            "203.0.113.7",
		"Failed password for invalid user admin from 2001:db8::1 port 22 ssh2": "2001:db8::1",
		"Invalid user oracle from ::ffff:198.51.100.2 port 4242":               "198.51.100.2",
		"Accepted publickey for deploy from 203.0.113.9 port 50000 ssh2":       "",
		"Failed password for root from 999.1.1.1 port 22 ssh2":                 "",
	}
	for line, want := range cases {
		ip, _, ok := r.Match(line)
		got := ""
		if ok {
			got = ip.String()
		}
		if got != want {
			t.Errorf("Match(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestHitThresholdAndWindow(t *testing.T) {
	r := sshRule(t)
	ip := netip.MustParseAddr("203.0.113.7")
	t0 := time.Unix(1_700_000_000, 0)

	r.Hit(ip, t0)
	r.Hit(ip, t0.Add(5*time.Minute))
	if _, trip := r.Hit(ip, t0.Add(11*time.Minute)); trip {
		t.Fatal("first hit fell out of the window, must not trip yet")
	}
	if hits, trip := r.Hit(ip, t0.Add(12*time.Minute)); !trip || hits != 3 {
		t.Fatalf("Hit = %d, %v; want 3, true", hits, trip)
	}
	if _, trip := r.Hit(ip, t0.Add(13*time.Minute)); trip {
		t.Fatal("counter must restart after tripping")
	}
}

func TestEscalationSurvivesRestart(t *testing.T) {
	r := sshRule(t) // ban: [1h, 24h]
	path := t.TempDir() + "/state.json"
	cfg := &Config{rules: []*Rule{r}, StateFile: path, EscalationLookback: Duration(30 * 24 * time.Hour)}
	ip := netip.MustParseAddr("203.0.113.7")
	t0 := time.Unix(1_700_000_000, 0)

	a := newAgent(cfg, fakeFirewall{}, newState())
	if b, _ := a.decide(r, ip, "p", 3, t0); b.Offense != 1 || b.Duration != time.Hour {
		t.Fatalf("first ban = %+v", b)
	}
	if _, ok := a.decide(r, ip, "p", 3, t0.Add(time.Minute)); ok {
		t.Fatal("already banned IP must not be banned again")
	}

	// Restart: state comes back from disk, the running ban is re-applied.
	st, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	fw := fakeFirewall{}
	a = newAgent(cfg, fw, st)
	a.restore(t0.Add(30 * time.Minute))
	if fw[hostPrefix(ip)] != 30*time.Minute {
		t.Fatalf("restored ban = %v, want the remaining 30m", fw[hostPrefix(ip)])
	}

	for i, want := range []time.Duration{24 * time.Hour, 24 * time.Hour} { // last step repeats
		at := t0.Add(time.Duration(i+1) * 48 * time.Hour)
		b, ok := a.decide(r, ip, "p", 3, at)
		if !ok || b.Offense != i+2 || b.Duration != want {
			t.Fatalf("ban %d = %+v", i+2, b)
		}
	}

	// Past the lookback, the ladder starts over.
	if b, _ := a.decide(r, ip, "p", 3, t0.Add(200*24*time.Hour)); b.Offense != 1 || b.Duration != time.Hour {
		t.Fatalf("ban after lookback = %+v", b)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	cfg, err := loadConfig("packaging/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.rules[0]
	for _, line := range []string{
		"Connection closed by authenticating user root 203.0.113.7 port 50022 [preauth]",
		"Unable to negotiate with 203.0.113.7 port 41234: no matching key exchange method found.",
		"Failed publickey for git from 203.0.113.7 port 22 ssh2",
	} {
		if ip, _, ok := r.Match(line); !ok || ip.String() != "203.0.113.7" {
			t.Errorf("example sshd rule missed %q", line)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"1d": 24 * time.Hour, "90s": 90 * time.Second, "10m": 10 * time.Minute} {
		if got, err := parseDuration(in); err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := parseDuration("xd"); err == nil {
		t.Error("want error for xd")
	}
}

// Reference values computed with PHP's hash_hmac (ScannerGuard::sign).
func TestSignMatchesPHP(t *testing.T) {
	if got := sign("1700000000", `{"ip":"203.0.113.7"}`, "secret"); got != "c0571e7a7e4376fc8222991dc7da4117defe06b9e6411edc87e9f7823d1a856c" {
		t.Errorf("POST signature = %s", got)
	}
	if got := sign("1700000000", "vps-01", "secret"); got != "67203b2a22b885d66e6ca82be3de0f48bcd9b64994ee0ee4600e539bd07231a2" {
		t.Errorf("GET signature = %s", got)
	}
}

func TestReportPullAndHeartbeat(t *testing.T) {
	var posted, beat map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts := r.Header.Get("X-Timestamp")
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("X-Signature") != sign(ts, string(body), "s3cret") {
				w.WriteHeader(403)
				return
			}
			if r.URL.Path == "/bans/heartbeat" {
				_ = json.Unmarshal(body, &beat)
				w.WriteHeader(204)
				return
			}
			_ = json.Unmarshal(body, &posted)
			w.WriteHeader(201)
		case http.MethodGet:
			if r.Header.Get("X-Signature") != sign(ts, "vps-01", "s3cret") {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"bans":[{"ip":"198.51.100.2","reason":"scanner_path","expires_at":"2030-01-01T00:00:00+00:00"}],"ip_blocklist":["192.0.2.0/24"],"user_agent_patterns":[]}`))
		}
	}))
	defer srv.Close()

	c := &Central{url: srv.URL + "/bans", source: "vps-01", secret: "s3cret", client: srv.Client()}
	at := time.Unix(1_700_000_000, 0).UTC()
	err := c.Report(context.Background(), Ban{IP: netip.MustParseAddr("203.0.113.7"), Reason: "ssh_bruteforce", Pattern: "Invalid user <ip>", Hits: 5, Offense: 2, Duration: time.Hour, At: at})
	if err != nil {
		t.Fatal(err)
	}
	if posted["ip"] != "203.0.113.7" || posted["source"] != "vps-01" || posted["expires_at"] != "2023-11-14T23:13:20Z" || posted["matched_value"] != "Invalid user <ip>" {
		t.Errorf("posted = %v", posted)
	}

	dl, err := c.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dl.Bans) != 1 || dl.Bans[0].IP != "198.51.100.2" || dl.IPBlocklist[0] != "192.0.2.0/24" {
		t.Errorf("denylist = %+v", dl)
	}

	err = c.Heartbeat(context.Background(), Heartbeat{Version: "1.2.3", Rules: []string{"ssh_bruteforce"}, ActiveBans: 4, StartedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if beat["source"] != "vps-01" || beat["version"] != "1.2.3" || beat["active_bans"] != float64(4) || beat["started_at"] != "2023-11-14T22:13:20Z" {
		t.Errorf("heartbeat = %v", beat)
	}
}

type failingFirewall struct{ fakeFirewall }

func (failingFirewall) Ban(netip.Prefix, time.Duration) error { return errors.New("nft: boom") }

func TestRestoreDropsIgnoredAndFailedBans(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ignored, kept := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("203.0.113.7")
	newSt := func() *state {
		st := newState()
		st.Banned[ignored] = now.Add(time.Hour)
		st.Banned[kept] = now.Add(time.Hour)
		return st
	}
	cfg := &Config{ignore: []netip.Prefix{mustTarget("10.0.0.0/8")}, EscalationLookback: Duration(time.Hour)}

	fw := fakeFirewall{}
	a := newAgent(cfg, fw, newSt())
	a.restore(now)
	if _, ok := fw[hostPrefix(ignored)]; ok || len(fw) != 1 {
		t.Fatalf("firewall = %v, the ignored IP must not be restored", fw)
	}
	if _, ok := a.state.Banned[ignored]; ok {
		t.Error("ignored IP must leave the ban state")
	}

	// A ban the firewall rejects leaves the state, so the rule can ban the IP again.
	a = newAgent(cfg, failingFirewall{fakeFirewall{}}, newSt())
	a.restore(now)
	if len(a.state.Banned) != 0 {
		t.Fatalf("state = %v, failed restores must not stay as banned", a.state.Banned)
	}
}

type fakeFirewall map[netip.Prefix]time.Duration

func (fakeFirewall) Init() error                                 { return nil }
func (f fakeFirewall) Ban(p netip.Prefix, d time.Duration) error { f[p] = d; return nil }
func (f fakeFirewall) Unban(p netip.Prefix) error                { delete(f, p); return nil }

func TestApplyDenylist(t *testing.T) {
	fw := fakeFirewall{}
	cfg := &Config{ignore: []netip.Prefix{mustTarget("10.0.0.0/8")}}
	a := newAgent(cfg, fw, newState())
	now := time.Unix(1_700_000_000, 0)
	applied := map[netip.Prefix]time.Time{}

	dl := &Denylist{IPBlocklist: []string{"192.0.2.0/24", "10.1.2.3", "not-an-ip; flush ruleset"}}
	dl.Bans = append(dl.Bans, struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expires_at"`
	}{IP: "198.51.100.2", ExpiresAt: now.Add(time.Hour)})
	a.apply(dl, applied, now)

	if len(fw) != 2 || fw[mustTarget("198.51.100.2")] != time.Hour || fw[mustTarget("192.0.2.0/24")] != 0 {
		t.Fatalf("firewall = %v (ignored and invalid entries must be skipped)", fw)
	}

	// 198.51.100.2 is also banned locally: dropping it from the central list must not lift it.
	a.state.Banned[netip.MustParseAddr("198.51.100.2")] = now.Add(time.Hour)
	a.apply(&Denylist{}, applied, now)
	if _, ok := fw[mustTarget("198.51.100.2")]; !ok {
		t.Error("local ban was lifted by the pull")
	}
	if _, ok := fw[mustTarget("192.0.2.0/24")]; ok {
		t.Error("entry no longer listed must be lifted")
	}
}
