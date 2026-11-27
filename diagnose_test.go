package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestContainsIP(t *testing.T) {
	for line, want := range map[string]bool{
		"203.0.113.9 - - [x] GET /":      true,
		"from 203.0.113.9 port 22":       true,
		"203.0.113.91 - - [x]":           false,
		"1203.0.113.9 x":                 false,
		"Ban 203.0.113.9":                true,
		"client: 203.0.113.9, server: x": true,
		"x203.0.113.9.5":                 false,
	} {
		if got := containsIP(line, "203.0.113.9"); got != want {
			t.Errorf("%q: %v", line, got)
		}
	}
}

func TestNftMentionsSkipsTheAgentTable(t *testing.T) {
	ruleset := `table inet scanner_guard {
	set static4 {
		elements = { 203.0.113.0/24 }
	}
}
table inet f2b-table {
	set addr-set-sshd {
		type ipv4_addr
		elements = { 198.51.100.1, 203.0.113.9 }
	}
	chain f2b-chain {
		ip saddr 0.0.0.0/0 accept
	}
}
table ip filter {
	chain INPUT {
		ip saddr 203.0.112.0/23 drop
	}
}`
	hits := nftMentions(ruleset, netip.MustParseAddr("203.0.113.9"))
	if len(hits) != 2 || !strings.Contains(hits[0], "f2b-table, set addr-set-sshd") || !strings.Contains(hits[1], "chain INPUT") {
		t.Fatalf("%q", hits)
	}
}

func TestMentionsRangesAndIptables(t *testing.T) {
	save := "-A INPUT -s 203.0.113.0/24 -j DROP\n-A INPUT -s 198.51.100.0/24 -j DROP\n-A f2b-sshd -s 203.0.113.9/32 -j REJECT --reject-with icmp-port-unreachable\n"
	if hits := mentions(save, netip.MustParseAddr("203.0.113.9"), ""); len(hits) != 2 {
		t.Fatalf("%q", hits)
	}
	ipset := "Name: blacklist\nType: hash:net\nMembers:\n203.0.113.0/24 timeout 100\n"
	if hits := ipsetMentions(ipset, netip.MustParseAddr("203.0.113.9")); len(hits) != 1 || !strings.HasPrefix(hits[0], "set blacklist:") {
		t.Fatalf("%q", hits)
	}
}

// fakeRun answers by command name; a missing name is "not installed".
func fakeRun(outs map[string]string, fail map[string]bool) func(time.Duration, string, ...string) (string, error) {
	return func(_ time.Duration, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		for k, v := range outs {
			if key == k || name == k {
				if fail[k] {
					return v, errors.New("exit status 1")
				}
				return v, nil
			}
		}
		return "", errNotInstalled
	}
}

func TestDiagnoseVerdict(t *testing.T) {
	run := func(outs map[string]string, fail map[string]bool, packets int) string {
		var b strings.Builder
		d := &diagnosis{w: &b, ip: netip.MustParseAddr("203.0.113.9"), run: fakeRun(outs, fail), packets: packets}
		d.firewalls()
		d.network()
		d.verdict()
		return b.String()
	}

	out := run(map[string]string{
		"fail2ban-client status":      "Status\n|- Number of jail: 1\n`- Jail list: sshd",
		"fail2ban-client status sshd": "   `- Banned IP list: 198.51.100.1 203.0.113.9",
		"iptables-save":               "-A INPUT -s 203.0.113.9/32 -j ACCEPT\n",
		"ping":                        "4 packets transmitted, 4 received, 0% packet loss, time 3004ms\nrtt min/avg/max/mdev = 1/2/3/0 ms",
	}, nil, -1)
	if !strings.Contains(out, "BLOCKED on this server by: fail2ban") || strings.Contains(out, "by: iptables") {
		t.Fatalf("fail2ban ban, iptables ACCEPT only:\n%s", out)
	}
	if !strings.Contains(out, "rule(s) or entries allow") || !strings.Contains(out, "0% packet loss") {
		t.Fatalf("output:\n%s", out)
	}

	out = run(map[string]string{"ping": "4 packets transmitted, 0 received, 100% packet loss"}, map[string]bool{"ping": true}, 0)
	if !strings.Contains(out, "Nothing on this server blocks") || !strings.Contains(out, "stops before this server") || !strings.Contains(out, "filter ICMP") {
		t.Fatalf("nothing here, no packet:\n%s", out)
	}

	out = run(nil, nil, 12)
	if !strings.Contains(out, "reach this server: look at the application") {
		t.Fatalf("packets arrive:\n%s", out)
	}
}
