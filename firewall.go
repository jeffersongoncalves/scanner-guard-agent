package main

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

type Firewall interface {
	Init() error
	// Ban blocks p for d; d == 0 means until unbanned (static entries).
	Ban(p netip.Prefix, d time.Duration) error
	Unban(p netip.Prefix) error
}

func newFirewall(name string) (Firewall, error) {
	switch name {
	case "nftables":
		return nftables{}, nil
	case "none":
		return logOnly{}, nil
	}
	return nil, fmt.Errorf("unknown firewall %q (nftables | none)", name)
}

// nftables keeps its own table, so it never touches the host's other rules.
// Timed bans (single IPs) and static entries (may be CIDRs) live in separate
// sets: timeouts on interval sets are not reliable on older kernels.
type nftables struct{}

const nftSetup = `table inet scanner_guard {}
delete table inet scanner_guard
table inet scanner_guard {
	set ban4 { type ipv4_addr; flags timeout; }
	set ban6 { type ipv6_addr; flags timeout; }
	set static4 { type ipv4_addr; flags interval; }
	set static6 { type ipv6_addr; flags interval; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @static4 drop
		ip6 saddr @static6 drop
		ip saddr @ban4 drop
		ip6 saddr @ban6 drop
	}
}
`

// Init recreates the table, so every start begins empty; the first pull
// restores whatever the central app still lists.
func (nftables) Init() error { return nft(nftSetup) }

func (nftables) Ban(p netip.Prefix, d time.Duration) error {
	set, elem := nftSet(p, d), nftElem(p)
	if strings.HasPrefix(set, "ban") {
		elem += fmt.Sprintf(" timeout %ds", max(1, int(d.Seconds())))
	}
	// Delete first so a re-ban refreshes the timeout; absent is fine.
	_ = nft(fmt.Sprintf("delete element inet scanner_guard %s { %s }", set, nftElem(p)))
	return nft(fmt.Sprintf("add element inet scanner_guard %s { %s }", set, elem))
}

func (nftables) Unban(p netip.Prefix) error {
	for _, d := range []time.Duration{0, 1} {
		_ = nft(fmt.Sprintf("delete element inet scanner_guard %s { %s }", nftSet(p, d), nftElem(p)))
	}
	return nil
}

func nftSet(p netip.Prefix, d time.Duration) string {
	fam := "6"
	if p.Addr().Is4() {
		fam = "4"
	}
	if d > 0 && p.IsSingleIP() {
		return "ban" + fam
	}
	return "static" + fam
}

// p comes from parseTarget, so it is a valid address or range: safe to splice
// into an nft script.
func nftElem(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// logOnly is a dry run: decide and report bans, block nothing.
type logOnly struct{}

func (logOnly) Init() error { return nil }

func (logOnly) Ban(p netip.Prefix, d time.Duration) error {
	log.Printf("dry-run: would block %s for %s", p, d)
	return nil
}

func (logOnly) Unban(p netip.Prefix) error {
	log.Printf("dry-run: would unblock %s", p)
	return nil
}
