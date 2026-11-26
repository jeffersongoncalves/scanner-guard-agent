package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func denylistAgent(t0 time.Time) *Agent {
	a := newAgent(&Config{}, fakeFirewall{}, newState())
	a.started = t0
	a.state.Banned[netip.MustParseAddr("203.0.113.7")] = t0.Add(time.Hour)
	a.state.Banned[netip.MustParseAddr("2001:db8::1")] = t0.Add(time.Hour)
	a.state.Banned[netip.MustParseAddr("203.0.113.8")] = t0.Add(-time.Second) // expired
	a.setPulled(map[netip.Prefix]time.Time{
		mustTarget("192.0.2.0/24"): {},
		mustTarget("203.0.113.7"):  t0.Add(time.Minute), // the longer local ban wins
		mustTarget("198.51.100.9"): t0,                  // expired
	})
	return a
}

func TestDenylistFormats(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	entries, ready := denylistAgent(t0).denied(t0)
	if !ready {
		t.Fatal("standalone agent must not wait for a pull")
	}

	for format, want := range map[string]string{
		"nginx": denylistHeader +
			"deny 192.0.2.0/24; # static\n" +
			"deny 203.0.113.7; # expires 2023-11-14T23:13:20Z\n" +
			"deny 2001:db8::1; # expires 2023-11-14T23:13:20Z\n",
		"apache": denylistHeader +
			"<RequireAll>\n\tRequire all granted\n" +
			"\t# static\n\tRequire not ip 192.0.2.0/24\n" +
			"\t# expires 2023-11-14T23:13:20Z\n\tRequire not ip 203.0.113.7\n" +
			"\t# expires 2023-11-14T23:13:20Z\n\tRequire not ip 2001:db8::1\n" +
			"</RequireAll>\n",
	} {
		if got := denylistFormats[format](entries); got != want {
			t.Errorf("%s:\n%s\nwant:\n%s", format, got, want)
		}
	}
}

func TestHeartbeatCountsLocalAndPulledBans(t *testing.T) {
	a := denylistAgent(time.Now())
	// 192.0.2.0/24, 203.0.113.7 (local and pulled, counted once), 2001:db8::1; the expired ones not.
	if got := a.heartbeat().ActiveBans; got != 3 {
		t.Errorf("active_bans = %d, want 3", got)
	}
}

func TestDenylistStaticBeatsLocalBan(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	a := denylistAgent(t0)
	a.setPulled(map[netip.Prefix]time.Time{mustTarget("203.0.113.7"): {}})

	entries, _ := a.denied(t0)
	if len(entries) != 2 || entries[0].prefix != mustTarget("203.0.113.7") || !entries[0].expires.IsZero() {
		t.Fatalf("entries = %v, want 203.0.113.7 as static", entries)
	}
}

func TestWriteDenylistOnlyOnChange(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	a := denylistAgent(t0)
	d := DenylistConfig{Format: "nginx", Path: filepath.Join(t.TempDir(), "nginx-deny.conf")}

	for _, s := range []struct {
		name string
		at   time.Time
		want int
	}{
		{"first write", t0, 3},
		{"unchanged", t0.Add(10 * time.Second), -1},
		{"local bans expired", t0.Add(2 * time.Hour), 1},
	} {
		if n, err := a.writeDenylist(d, s.at); err != nil || n != s.want {
			t.Fatalf("%s = %d, %v; want %d", s.name, n, err, s.want)
		}
	}

	// Lifting the last ban must empty the file, not leave it behind.
	a.setPulled(map[netip.Prefix]time.Time{})
	if n, err := a.writeDenylist(d, t0.Add(2*time.Hour)); err != nil || n != 0 {
		t.Fatalf("lift = %d, %v; want 0", n, err)
	}
	if raw, _ := os.ReadFile(d.Path); string(raw) != denylistHeader {
		t.Fatalf("file = %q, want only the header", raw)
	}
}

func TestDenylistWaitsForFirstPull(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	a := denylistAgent(t0)
	a.central, a.pulled = &Central{}, nil
	d := DenylistConfig{Format: "nginx", Path: filepath.Join(t.TempDir(), "nginx-deny.conf")}

	if n, _ := a.writeDenylist(d, t0.Add(time.Minute)); n != -1 {
		t.Fatal("the previous list must survive until the first pull")
	}
	if n, _ := a.writeDenylist(d, t0.Add(denylistGrace)); n != 2 {
		t.Fatalf("wrote %d entries; with the central app down, local bans must land after the grace period", n)
	}

	a.setPulled(map[netip.Prefix]time.Time{}) // a pull of an empty list counts too
	if _, ready := a.denied(t0); !ready {
		t.Fatal("must be ready after the first pull")
	}
}

// The web denylist must hold central entries the firewall rejected, while
// applied leaves them out so the next pull retries them.
func TestDenylistKeepsEntriesTheFirewallRejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cfg := &Config{ignore: []netip.Prefix{mustTarget("10.0.0.0/8")}}
	a := newAgent(cfg, failingFirewall{fakeFirewall{}}, newState())
	applied := map[netip.Prefix]time.Time{}

	a.setPulled(a.apply(&Denylist{IPBlocklist: []string{"192.0.2.0/24", "10.1.2.3", "bad; entry"}}, applied, now))

	entries, _ := a.denied(now)
	if len(entries) != 1 || entries[0].prefix != mustTarget("192.0.2.0/24") {
		t.Errorf("entries = %v, want only 192.0.2.0/24", entries)
	}
	if len(applied) != 0 {
		t.Errorf("applied = %v, a rejected entry must be retried", applied)
	}
}

func TestApplyKeepsLatestExpiryOfDuplicates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var dl Denylist
	// Both spellings resolve to the same target; the order must not matter.
	raw := `{"bans":[
		{"ip":"203.0.113.7","expires_at":"2023-11-15T22:13:20Z"},
		{"ip":"::ffff:203.0.113.7","expires_at":"2023-11-14T23:13:20Z"},
		{"ip":"::ffff:203.0.113.8","expires_at":"2023-11-14T23:13:20Z"},
		{"ip":"203.0.113.8","expires_at":"2023-11-15T22:13:20Z"}]}`
	if err := json.Unmarshal([]byte(raw), &dl); err != nil {
		t.Fatal(err)
	}
	fw := fakeFirewall{}
	newAgent(&Config{}, fw, newState()).apply(&dl, map[netip.Prefix]time.Time{}, now)

	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		if fw[mustTarget(ip)] != 24*time.Hour {
			t.Errorf("%s banned for %s, want the latest expiry (24h)", ip, fw[mustTarget(ip)])
		}
	}
}

func TestDenylistConfig(t *testing.T) {
	load := func(denylists string) error {
		f := filepath.Join(t.TempDir(), "agent.yaml")
		yaml := "denylists: [" + denylists + "]\nrules:\n  - {name: r, file: /x, patterns: ['<ip>'], threshold: 1, window: 1m, ban: [1h]}\n"
		if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadConfig(f)
		return err
	}

	if err := load("{format: nginx, path: /a/nginx-deny.conf}, {format: apache, path: /a/apache2-deny.conf}"); err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{
		"{format: caddy, path: /a/b.conf}": "unknown format",
		"{format: nginx, path: b.conf}":    "must be absolute",
		"{format: nginx}":                  "must be absolute",
		"{format: nginx, path: /a/b.conf}, {format: apache, path: /a/c/../b.conf}": "already in use",
		"{format: nginx, path: /var/lib/scanner-guard/state.json}":                 "already in use",
		// The staging files of writeAtomic must not collide either.
		"{format: nginx, path: /var/lib/scanner-guard/state.json.tmp}":            "already in use",
		"{format: nginx, path: /a/b.conf}, {format: apache, path: /a/b.conf.tmp}": "already in use",
		"{format: nginx, path: /a/b.conf.tmp}, {format: apache, path: /a/b.conf}": "already in use",
	} {
		if err := load(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", in, err, want)
		}
	}
}
