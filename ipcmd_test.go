package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestDescribeIP(t *testing.T) {
	now := time.Date(2026, 11, 25, 20, 0, 0, 0, time.UTC)
	cfg := &Config{Firewall: "nftables", ignore: []netip.Prefix{mustTarget("127.0.0.0/8"), mustTarget("10.166.121.0/24")}}
	st := newState()
	banned := netip.MustParseAddr("203.0.113.7")
	st.Banned[banned] = now.Add(23 * time.Hour)
	st.Banned[netip.MustParseAddr("203.0.113.8")] = now.Add(-time.Hour) // expired
	st.Offenses["ssh_bruteforce"] = map[netip.Addr]offense{banned: {N: 2, Last: now.Add(-time.Hour)}}
	st.Offenses["web_attack"] = map[netip.Addr]offense{banned: {N: 1, Last: now.Add(-2 * time.Hour)}}
	st.Ignore = []netip.Prefix{mustTarget("198.51.100.0/24")}

	firewall := map[string][2]string{
		"203.0.113.7/32": {"ban4", "203.0.113.7 timeout 1d expires 22h59m"},
		"192.0.2.9/32":   {"static4", "192.0.2.0/24"},
	}
	lookup := func(p netip.Prefix) (string, string) { f := firewall[p.String()]; return f[0], f[1] }

	for ip, want := range map[string][]string{
		"203.0.113.7": {"blocked:   yes, ban4 { 203.0.113.7 timeout 1d expires 22h59m }", "local ban: until ", "(23h0m0s left)",
			"offense:   ssh_bruteforce #2", "offense:   web_attack #1", "ignored:   no"},
		"203.0.113.8":    {"blocked:   no", "local ban: no", "ignored:   no"},
		"192.0.2.9":      {"blocked:   yes, static4 { 192.0.2.0/24 }", "local ban: no, the block comes from the central app", "static entry"},
		"10.166.121.254": {"blocked:   no", "ignored:   yes, 10.166.121.0/24 in agent.yaml"},
		"198.51.100.4":   {"ignored:   yes, 198.51.100.0/24 from the central app"},
	} {
		var out bytes.Buffer
		describeIP(&out, cfg, st, netip.MustParseAddr(ip), lookup, now)
		for _, w := range want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%s: missing %q in:\n%s", ip, w, out.String())
			}
		}
		if ip != "203.0.113.7" && strings.Contains(out.String(), "offense:") {
			t.Errorf("%s: offenses of another IP:\n%s", ip, out.String())
		}
	}

	var out bytes.Buffer
	describeIP(&out, &Config{Firewall: "none"}, newState(), banned, nil, now)
	if !strings.Contains(out.String(), "blocked:   unknown (firewall: none)") {
		t.Errorf("dry run:\n%s", out.String())
	}
}
