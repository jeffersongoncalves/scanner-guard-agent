package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

	r.Hit(ip, t0, "a")
	r.Hit(ip, t0.Add(5*time.Minute), "b")
	if _, _, trip := r.Hit(ip, t0.Add(11*time.Minute), "c"); trip {
		t.Fatal("first hit fell out of the window, must not trip yet")
	}
	hits, lines, trip := r.Hit(ip, t0.Add(12*time.Minute), "d")
	if !trip || hits != 3 {
		t.Fatalf("Hit = %d, %v; want 3, true", hits, trip)
	}
	if strings.Join(lines, ",") != "b,c,d" {
		t.Errorf("evidence = %q, want the lines inside the window, oldest first", lines)
	}
	if _, _, trip := r.Hit(ip, t0.Add(13*time.Minute), "e"); trip {
		t.Fatal("counter must restart after tripping")
	}
}

func TestHitEvidenceIsCapped(t *testing.T) {
	r := sshRule(t)
	r.local.threshold = 30
	ip := netip.MustParseAddr("203.0.113.7")
	t0 := time.Unix(1_700_000_000, 0)

	long := strings.Repeat("x", 2*maxEvidenceLine)
	var lines []string
	for i := range 30 {
		_, lines, _ = r.Hit(ip, t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("%02d%s", i, long))
	}
	if len(lines) != maxEvidence || !strings.HasPrefix(lines[0], "10") || !strings.HasPrefix(lines[maxEvidence-1], "29") {
		t.Fatalf("evidence: %d lines, first %.2q; want the last %d", len(lines), lines[0], maxEvidence)
	}
	if len(lines[0]) != maxEvidenceLine {
		t.Errorf("line length %d, want %d", len(lines[0]), maxEvidenceLine)
	}
}

func TestRedact(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.7")
	got := redact([]string{`203.0.113.7 - [x] "GET /.env HTTP/2.0" 403 rule=dotfile`, "Invalid user hari from 203.0.113.7 port 1"}, v4)
	if got[0] != `<ip> - [x] "GET /.env HTTP/2.0" 403 rule=dotfile` || got[1] != "Invalid user hari from <ip> port 1" {
		t.Errorf("v4: %q", got)
	}
	v6 := netip.MustParseAddr("2001:db8::7")
	got = redact([]string{"from 2001:db8::7 port 1", "from 2001:DB8::7", "from 2001:0db8:0000:0000:0000:0000:0000:0007"}, v6)
	for _, l := range got {
		if strings.Contains(strings.ToLower(l), "2001") {
			t.Errorf("v6 left in %q", l)
		}
	}
	if got := redact(nil, v4); got == nil || len(got) != 0 {
		t.Errorf("redact(nil) = %#v, want an empty list (JSON [])", got)
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
		"Failed keyboard-interactive/pam for invalid user forge from 203.0.113.7 port 46230 ssh2",
		"Connection closed by invalid user forge 203.0.113.7 port 46230 [preauth]",
		"Disconnected from authenticating user root 203.0.113.7 port 46230 [preauth]",
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
	err := c.Report(context.Background(), Ban{IP: netip.MustParseAddr("203.0.113.7"), Reason: "ssh_bruteforce", Pattern: "Invalid user <ip>", Hits: 5, Offense: 2, Duration: time.Hour, At: at,
		Evidence: []string{"Invalid user marko from 203.0.113.7 port 43324", "Invalid user hari from 203.0.113.7 port 44372"}})
	if err != nil {
		t.Fatal(err)
	}
	if posted["ip"] != "203.0.113.7" || posted["source"] != "vps-01" || posted["expires_at"] != "2023-11-14T23:13:20Z" || posted["matched_value"] != "Invalid user <ip>" {
		t.Errorf("posted = %v", posted)
	}
	if ev := fmt.Sprint(posted["evidence"]); ev != "[Invalid user marko from <ip> port 43324 Invalid user hari from <ip> port 44372]" {
		t.Errorf("evidence = %s", ev)
	}

	dl, err := c.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dl.Bans) != 1 || dl.Bans[0].IP != "198.51.100.2" || dl.IPBlocklist[0] != "192.0.2.0/24" {
		t.Errorf("denylist = %+v", dl)
	}

	err = c.Heartbeat(context.Background(), Heartbeat{Version: "1.2.3", Rules: []string{"ssh_bruteforce"}, ActiveBans: 4, StartedAt: at,
		OS: "Ubuntu 22.04.5 LTS", Addresses: []string{"10.2.0.251"}})
	if err != nil {
		t.Fatal(err)
	}
	if beat["source"] != "vps-01" || beat["version"] != "1.2.3" || beat["active_bans"] != float64(4) || beat["started_at"] != "2023-11-14T22:13:20Z" ||
		beat["os"] != "Ubuntu 22.04.5 LTS" || fmt.Sprint(beat["addresses"]) != "[10.2.0.251]" {
		t.Errorf("heartbeat = %v", beat)
	}
}

func TestOSName(t *testing.T) {
	p := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(p, []byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 20.04.5 LTS\"\nID=ubuntu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := osName(p); got != "Ubuntu 20.04.5 LTS" {
		t.Errorf("osName = %q", got)
	}
	if got := osName(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Errorf("missing file: %q", got)
	}
	for _, a := range hostAddresses() {
		if ip, err := netip.ParseAddr(a); err != nil || ip.IsLoopback() {
			t.Errorf("hostAddresses: %q", a)
		}
	}
}

// test -ban exits right after enforce: reports.Wait must cover the central POST.
func TestEnforceReportsCanBeAwaited(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- body["ip"].(string)
		w.WriteHeader(201)
	}))
	defer srv.Close()

	r := sshRule(t)
	fw := fakeFirewall{}
	a := newAgent(&Config{rules: []*Rule{r}, EscalationLookback: Duration(time.Hour)}, fw, newState())
	a.central = &Central{url: srv.URL, source: "vps-01", secret: "s", client: srv.Client()}

	ip := netip.MustParseAddr("203.0.113.7")
	b, ok := a.decide(r, ip, "p", 12, time.Now())
	if !ok {
		t.Fatal("decide refused a fresh IP")
	}
	a.enforce(context.Background(), b)
	a.reports.Wait()

	select {
	case sent := <-got:
		if sent != "203.0.113.7" || fw[hostPrefix(ip)] != time.Hour {
			t.Fatalf("reported %s, firewall %v", sent, fw)
		}
	default:
		t.Fatal("Wait returned before the report reached the central app")
	}
}

type failingFirewall struct{ fakeFirewall }

func (failingFirewall) Ban(netip.Prefix, time.Duration) error { return errors.New("nft: boom") }

func TestFailedBanCanRetry(t *testing.T) {
	r := sshRule(t) // ban: [1h, 24h]
	a := newAgent(&Config{rules: []*Rule{r}, EscalationLookback: Duration(time.Hour)}, failingFirewall{fakeFirewall{}}, newState())
	ip := netip.MustParseAddr("203.0.113.7")
	now := time.Unix(1_700_000_000, 0)

	b, _ := a.decide(r, ip, "p", 3, now)
	if err := a.enforce(context.Background(), b); err == nil {
		t.Fatal("enforce must return the firewall error")
	}
	b, ok := a.decide(r, ip, "p", 3, now.Add(time.Minute))
	if !ok || b.Offense != 2 {
		t.Fatalf("retry = %+v, %v; want a new ban with the escalation kept", b, ok)
	}
}

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

func TestCentralURLMustBeHTTPS(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.ToSlash(filepath.Join(dir, "secret"))
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(url string) error {
		f := filepath.Join(dir, "agent.yaml")
		yaml := "central: {url: '" + url + "', secret_file: '" + secret + "'}\nrules:\n  - {name: r, file: /x, patterns: ['<ip>'], threshold: 1, window: 1m, ban: [1h]}\n"
		if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(f)
		return err
	}

	for _, ok := range []string{
		"", // standalone
		"https://central.example.com/bans",
		"HTTPS://central.example.com/bans",
		"http://localhost:8000/bans",
		"http://LOCALHOST/bans",
		"http://127.0.0.1/bans",
		"http://[::1]:8000/bans",
	} {
		if err := load(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://central.example.com/bans",
		"http://10.0.0.5/bans",
		"http://localhost.example.com/bans",
		"http://127.0.0.1.example.com/bans",
		"http://localhost@central.example.com/bans",
		"ftp://localhost/bans",
		"central.example.com/bans",
		"https:///bans",
	} {
		if err := load(bad); err == nil || !strings.Contains(err.Error(), "central.url") {
			t.Errorf("%q: err = %v, want it refused", bad, err)
		}
	}
}

// The Go client follows https -> http redirects, which would undo the check.
func TestCentralRefusesInsecureRedirect(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/insecure":
			http.Redirect(w, r, "http://central.example.com/bans", http.StatusFound)
		case "/secure":
			http.Redirect(w, r, "/bans", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	pull := func(path string) error {
		cfg := &Config{Source: "vps-01", Central: CentralConfig{URL: srv.URL + path, Timeout: Duration(5 * time.Second)}}
		c := newAgent(cfg, fakeFirewall{}, newState()).central
		c.client.Transport = srv.Client().Transport
		_, err := c.Pull(context.Background())
		return err
	}

	if err := pull("/secure"); err != nil {
		t.Errorf("https redirect: %v", err)
	}
	var uerr *url.Error
	if err := pull("/insecure"); !errors.As(err, &uerr) || !strings.Contains(err.Error(), "must be https") {
		t.Errorf("http redirect: err = %v, want it refused", err)
	}
	if err := pull("/loop"); err == nil {
		t.Error("a redirect loop must still stop")
	}
}

func TestCentralIgnore(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "state.json")
	mine, other := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.99")
	body := `{"bans":[{"ip":"203.0.113.11","expires_at":"2099-01-01T00:00:00Z"}],"ip_blocklist":["198.51.100.0/24"],
		"ignore":["203.0.113.0/28","198.51.100.7","0.0.0.0/0","::/0","nope","203.0.113.0/28"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()

	fw := fakeFirewall{}
	cfg := &Config{StateFile: path, EscalationLookback: Duration(time.Hour), rules: []*Rule{sshRule(t)}}
	a := newAgent(cfg, fw, newState())
	a.central = &Central{url: srv.URL, client: srv.Client()}
	for _, ip := range []netip.Addr{mine, other} {
		a.state.Banned[ip] = now.Add(time.Hour)
		fw[hostPrefix(ip)] = time.Hour
	}

	// A ban from before the list is lifted, the others stay.
	dl := a.pull(context.Background())
	if _, ok := fw[hostPrefix(mine)]; ok {
		t.Error("an ignored IP stayed banned")
	}
	if _, ok := fw[hostPrefix(other)]; !ok {
		t.Error("a ban outside the list was lifted (is 0.0.0.0/0 refused?)")
	}
	if n := len(a.state.Ignore); n != 2 {
		t.Errorf("ignore = %v, want the 2 valid entries", a.state.Ignore)
	}

	// Neither the denylist nor a rule bans it again.
	if want := a.apply(dl, map[netip.Prefix]time.Time{}, now); len(want) != 0 {
		t.Errorf("applied %v, both overlap the list", want)
	}
	if _, ok := a.decide(cfg.rules[0], mine, "p", 5, now); ok {
		t.Error("banned an ignored IP")
	}

	// A restart honors it before the central app answers.
	st, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if b := newAgent(cfg, fw, st); !b.ignored(hostPrefix(mine)) || b.ignored(hostPrefix(other)) {
		t.Errorf("after a restart ignore = %v", st.Ignore)
	}

	// No key: an older central app, keep the list. An empty list clears it.
	body = `{"bans":[]}`
	a.pull(context.Background())
	if !a.ignored(hostPrefix(mine)) {
		t.Error("a response without ignore cleared the list")
	}
	body = `{"bans":[],"ignore":[]}`
	a.pull(context.Background())
	if a.ignored(hostPrefix(mine)) {
		t.Error("an empty list must clear it")
	}
}

// The config's ignore is not the central app's to remove.
func TestCentralIgnoreKeepsConfig(t *testing.T) {
	a := newAgent(&Config{ignore: []netip.Prefix{mustTarget("10.0.0.0/8")}}, fakeFirewall{}, newState())
	a.setIgnore([]string{})
	if !a.ignored(mustTarget("10.1.2.3")) {
		t.Error("config ignore lost")
	}
}

func TestCentralRuleSettings(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "state.json")
	body := `{"bans":[],"agent_rules":{"ssh_bruteforce":{"threshold":2,"window":60,"ban":[86400,604800]},"other":{"threshold":1,"window":1,"ban":[1]}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()

	r := sshRule(t)
	cfg := &Config{StateFile: path, EscalationLookback: Duration(time.Hour), rules: []*Rule{r}}
	a := newAgent(cfg, fakeFirewall{}, newState())
	a.central = &Central{url: srv.URL, client: srv.Client()}
	ip := netip.MustParseAddr("203.0.113.7")

	a.pull(context.Background())
	if got := r.limits().String(); got != "2 in 1m, ban 1d/7d" || !r.limits().central {
		t.Fatalf("limits = %s, want the central app's", got)
	}
	if _, _, trip := r.Hit(ip, now, "a"); trip {
		t.Fatal("tripped on the first hit")
	}
	if _, _, trip := r.Hit(ip, now.Add(30*time.Second), "b"); !trip {
		t.Fatal("the central threshold of 2 did not trip")
	}
	if b, ok := a.decide(r, ip, "p", 2, now); !ok || b.Duration != 24*time.Hour {
		t.Errorf("ban = %v, want the central app's first step", b.Duration)
	}

	// A restart with the central app down keeps them.
	st, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	r2 := sshRule(t)
	newAgent(&Config{rules: []*Rule{r2}}, fakeFirewall{}, st).restore(now)
	if !r2.limits().central {
		t.Error("lost the central settings on restart")
	}

	// No key keeps them, invalid or an empty object puts agent.yaml's back.
	for _, c := range []struct {
		body    string
		central bool
	}{
		{`{"bans":[]}`, true},
		{`{"bans":[],"agent_rules":{"ssh_bruteforce":{"threshold":0,"window":60,"ban":[60]}}}`, false},
		{`{"bans":[],"agent_rules":{"ssh_bruteforce":{"threshold":2,"window":60,"ban":[]}}}`, false},
		{`{"bans":[],"agent_rules":{"ssh_bruteforce":{"threshold":4,"window":60,"ban":[60]}}}`, true},
		{`{"bans":[],"agent_rules":{}}`, false},
	} {
		body = c.body
		a.pull(context.Background())
		if r.limits().central != c.central {
			t.Errorf("%s: central = %v", c.body, r.limits().central)
		}
	}
	if got := r.limits().String(); got != "3 in 10m, ban 1h/1d" {
		t.Errorf("limits = %s, want agent.yaml's", got)
	}
}

// On a fresh install the list must be in place before the first line is read.
func TestRunPullsIgnoreFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := newAgent(&Config{Central: CentralConfig{PullInterval: Duration(time.Hour)}}, fakeFirewall{}, newState())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost { // the heartbeat comes after the first apply
			cancel()
			return
		}
		_, _ = io.WriteString(w, `{"bans":[{"ip":"203.0.113.11","expires_at":"2099-01-01T00:00:00Z"}],"ignore":["203.0.113.10"]}`)
	}))
	defer srv.Close()
	a.central = &Central{url: srv.URL, client: srv.Client()}
	a.run(ctx)
	if !a.ignored(mustTarget("203.0.113.10")) || len(a.pulled) != 1 {
		t.Errorf("ignore = %v, pulled = %v", a.state.Ignore, a.pulled)
	}
}

// nft 0.8 (Ubuntu 18.04) rejects a last statement with no newline after it.
func TestNftScriptEndsWithANewline(t *testing.T) {
	for in, want := range map[string]string{
		"add element inet scanner_guard ban4 { 192.0.2.1 timeout 60s }": "add element inet scanner_guard ban4 { 192.0.2.1 timeout 60s }\n",
		nftSetup: nftSetup,
	} {
		if got := nftScript(in); got != want {
			t.Errorf("nftScript(%q) = %q, want %q", in, got, want)
		}
	}
}
