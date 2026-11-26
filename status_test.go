package main

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// As nft 0.8.2 prints it (Ubuntu 18.04).
const nftTable = `table inet scanner_guard {
	set ban4 {
		type ipv4_addr
		flags timeout
		elements = { 203.0.113.7 expires 23h59m2s, 198.51.100.4 expires 6d23h,
			     192.0.2.33 expires 59m }
	}
	set ban6 {
		type ipv6_addr
		flags timeout
	}
	set static4 {
		type ipv4_addr
		flags interval
		elements = { 10.9.0.0/16, 172.16.0.1-172.16.0.9 }
	}
	set static6 {
		type ipv6_addr
		flags interval
	}
	chain prerouting {
		type filter hook prerouting priority -300; policy accept;
		ip saddr @static4 drop
	}
}
`

func TestParseNftElements(t *testing.T) {
	sets := parseNftElements(nftTable)
	if len(sets["ban4"]) != 3 || len(sets["ban6"]) != 0 || len(sets["static4"]) != 2 {
		t.Fatalf("sets = %q", sets)
	}
	for ip, want := range map[string]string{
		"198.51.100.4": "ban4 198.51.100.4 expires 6d23h",
		"192.0.2.33":   "ban4 192.0.2.33 expires 59m",
		"10.9.200.1":   "static4 10.9.0.0/16",
		"172.16.0.5":   "static4 172.16.0.1-172.16.0.9",
		"172.16.0.10":  " ",
		"2001:db8::1":  " ",
	} {
		set, elem := lookupElem(sets, netip.MustParseAddr(ip))
		if got := set + " " + elem; got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
}

func TestWriteStatus(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.Local)
	r, err := newRule(RuleConfig{Name: "ssh_bruteforce", Journald: []string{"ssh.service"}, Patterns: []string{`from <ip>`},
		Threshold: 5, Window: Duration(time.Hour), Ban: []Duration{Duration(24 * time.Hour), Duration(7 * 24 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Source: "adp2", Firewall: "nftables", rules: []*Rule{r}, ignore: []netip.Prefix{mustTarget("127.0.0.0/8"), mustTarget("::1/128"), mustTarget("10.0.0.0/8")},
		Central: CentralConfig{URL: "https://central.test/scanner-guard/bans", PullInterval: Duration(time.Minute), RequireSigned: true}}
	st := newState()
	ip := netip.MustParseAddr("203.0.113.7")
	st.Banned[ip] = now.Add(23 * time.Hour)
	st.Banned[netip.MustParseAddr("203.0.113.8")] = now.Add(-time.Hour) // expired
	st.Offenses["ssh_bruteforce"] = map[netip.Addr]offense{ip: {N: 2, Last: now.Add(-time.Hour)}}

	var out bytes.Buffer
	writeStatus(&out, cfg, st, "active", parseNftElements(nftTable), nil, 10, now)
	for _, want := range []string{
		"source:    adp2", "service:   active", "central:   central.test (pull every 1m, signed responses only)",
		"nftables, 5 blocked (ban4 3, ban6 0, static4 2, static6 0)", "ignore:    1 in agent.yaml, 0 from the central app",
		"ssh_bruteforce   5 in 1h, ban 1d/7d  <- journald ssh.service",
		"local bans: 1 active", "203.0.113.7", "ssh_bruteforce #2",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	writeStatus(&out, cfg, st, "", nil, errors.New("no table"), 10, now)
	if !strings.Contains(out.String(), "table not readable: no table") || !strings.Contains(out.String(), "unknown (no systemd?)") {
		t.Errorf("errors:\n%s", out.String())
	}
}

func TestNginxReport(t *testing.T) {
	log := strings.Join([]string{
		`203.0.113.7 - [25/Nov/2026:10:00:00 -0300] "GET /.env HTTP/1.1" 403 rule=dotfile host=a.test "curl/8"`,
		`203.0.113.7 - [26/Nov/2026:10:00:00 -0300] "GET /.git/config HTTP/1.1" 403 rule=dotfile host=a.test "curl/8"`,
		`203.0.113.7 - [26/Nov/2026:10:01:00 -0300] "GET /?id=1+union+select+1 HTTP/1.1" 403 rule=sqli-union host=b.test "curl/8"`,
		`198.51.100.4 - [26/Nov/2026:10:02:00 -0300] "GET /wp-config.php.bak HTTP/1.1" 403 rule=backup host=a.test "-"`,
		`not a scanner-guard line`,
	}, "\n")

	var out bytes.Buffer
	since := time.Date(2026, 11, 26, 0, 0, 0, 0, time.FixedZone("", -3*3600))
	if err := nginxReport(strings.NewReader(log), &out, since, "", 10); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"3 blocked requests since", "from 2 clients, on 2 sites",
		"2  203.0.113.7  (dotfile, sqli-union)", "1  backup", "2  a.test", "/wp-config.php.bak",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := nginxReport(strings.NewReader(log), &out, time.Time{}, "a.test", 10); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "3 blocked requests in the whole log, from 2 clients, on 1 sites") || strings.Contains(out.String(), "by site") {
		t.Errorf("host filter:\n%s", out.String())
	}
}
