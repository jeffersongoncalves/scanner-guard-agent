package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ipCmd tells what the agent does with an address: blocked or not, why, and
// whether it is ignored. Read-only.
func ipCmd(args []string) {
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	_ = fs.Parse(args)

	if fs.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		log.Printf("state %s: %v", cfg.StateFile, err)
	}

	lookup := nftLookup
	if cfg.Firewall != "nftables" {
		lookup = nil
	}
	for _, s := range fs.Args() {
		a, err := netip.ParseAddr(s)
		if err != nil {
			log.Fatalf("%q is not an IP address", s)
		}
		describeIP(os.Stdout, cfg, st, a.Unmap().WithZone(""), lookup, time.Now())
	}
}

// nftLookup returns the element of the agent's table that covers p, the set it
// is in, or "" when none does. A static set may hold a range containing p.
func nftLookup(p netip.Prefix) (set, elem string) {
	fam := "6"
	if p.Addr().Is4() {
		fam = "4"
	}
	for _, s := range []string{"ban" + fam, "static" + fam} {
		out, err := exec.Command("nft", "get", "element", "inet", "scanner_guard", s, "{ "+nftElem(p)+" }").CombinedOutput()
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if e, ok := strings.CutPrefix(strings.TrimSpace(line), "elements = {"); ok {
				return s, strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(e), "}"))
			}
		}
		return s, nftElem(p)
	}
	return "", ""
}

func describeIP(w io.Writer, cfg *Config, st *state, a netip.Addr, lookup func(netip.Prefix) (string, string), now time.Time) {
	p := hostPrefix(a)
	fmt.Fprintln(w, a)

	blocked := false
	switch {
	case lookup == nil:
		fmt.Fprintf(w, "  blocked:   unknown (firewall: %s)\n", cfg.Firewall)
	default:
		if set, elem := lookup(p); set != "" {
			blocked = true
			note := ""
			if strings.HasPrefix(set, "static") {
				note = " (static entry: a range or an ip_blocklist IP, shown by its first address on older nft)"
			}
			fmt.Fprintf(w, "  blocked:   yes, %s { %s }%s\n", set, elem, note)
		} else {
			fmt.Fprintln(w, "  blocked:   no")
		}
	}

	if until, ok := st.Banned[a]; ok && until.After(now) {
		fmt.Fprintf(w, "  local ban: until %s (%s left)\n", until.Local().Format("2006-01-02 15:04 -0700"), until.Sub(now).Round(time.Minute))
	} else if blocked {
		fmt.Fprintln(w, "  local ban: no, the block comes from the central app")
	} else {
		fmt.Fprintln(w, "  local ban: no")
	}

	rules := make([]string, 0, len(st.Offenses))
	for rule, ips := range st.Offenses {
		if _, ok := ips[a]; ok {
			rules = append(rules, rule)
		}
	}
	sort.Strings(rules)
	for _, rule := range rules {
		o := st.Offenses[rule][a]
		fmt.Fprintf(w, "  offense:   %s #%d, last %s\n", rule, o.N, o.Last.Local().Format("2006-01-02 15:04 -0700"))
	}

	switch {
	case prefixIn(cfg.ignore, p) != "":
		fmt.Fprintf(w, "  ignored:   yes, %s in agent.yaml (or always ignored)\n", prefixIn(cfg.ignore, p))
	case prefixIn(st.Ignore, p) != "":
		fmt.Fprintf(w, "  ignored:   yes, %s from the central app\n", prefixIn(st.Ignore, p))
	default:
		fmt.Fprintln(w, "  ignored:   no")
	}
}

// prefixIn returns the first entry of list that overlaps p, "" for none.
func prefixIn(list []netip.Prefix, p netip.Prefix) string {
	for _, e := range list {
		if e.Overlaps(p) {
			return nftElem(e)
		}
	}
	return ""
}
