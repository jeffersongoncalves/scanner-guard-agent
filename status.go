package main

import (
	"cmp"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// statusCmd shows what the agent is doing on this server, read-only: service,
// central app, what the firewall blocks, the rules and the last local bans.
func statusCmd(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	n := fs.Int("n", 10, "recent local bans to list")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		log.Printf("state %s: %v", cfg.StateFile, err)
	}
	var sets map[string][]string
	var nftErr error
	if cfg.Firewall == "nftables" {
		sets, nftErr = nftElements()
	}
	out, _ := exec.Command("systemctl", "is-active", "scanner-guard-agent").Output()
	writeStatus(os.Stdout, cfg, st, strings.TrimSpace(string(out)), sets, nftErr, *n, time.Now())
}

func writeStatus(w io.Writer, cfg *Config, st *state, service string, sets map[string][]string, nftErr error, n int, now time.Time) {
	fmt.Fprintf(w, "scanner-guard-agent %s\n", version)
	fmt.Fprintf(w, "  source:    %s\n", cfg.Source)
	fmt.Fprintf(w, "  service:   %s\n", cmp.Or(service, "unknown (no systemd?)"))

	if cfg.Central.URL == "" {
		fmt.Fprintln(w, "  central:   none (standalone)")
	} else {
		host := cfg.Central.URL
		if u, err := url.Parse(cfg.Central.URL); err == nil {
			host = u.Host
		}
		signed := ""
		if cfg.Central.RequireSigned {
			signed = ", signed responses only"
		}
		fmt.Fprintf(w, "  central:   %s (pull every %s%s)\n", host, shortDur(time.Duration(cfg.Central.PullInterval)), signed)
	}

	switch {
	case cfg.Firewall != "nftables":
		fmt.Fprintf(w, "  firewall:  %s (blocks nothing)\n", cfg.Firewall)
	case nftErr != nil:
		fmt.Fprintf(w, "  firewall:  nftables, table not readable: %v\n", nftErr)
	default:
		total, parts := 0, []string{}
		for _, s := range []string{"ban4", "ban6", "static4", "static6"} {
			total += len(sets[s])
			parts = append(parts, fmt.Sprintf("%s %d", s, len(sets[s])))
		}
		fmt.Fprintf(w, "  firewall:  nftables, %d blocked (%s)\n", total, strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, "  ignore:    %d in agent.yaml, %d from the central app\n", len(cfg.ignore)-len(alwaysIgnore), len(st.Ignore))

	fmt.Fprintln(w, "\nrules:")
	applyRuleSettings(cfg.rules, st.Rules, func(string, ...any) {}) // what the running agent uses
	for _, r := range cfg.rules {
		src := r.file
		if src == "" {
			src = "journald " + strings.Join(r.journald, ",")
		}
		if r.report {
			fmt.Fprintf(w, "  %-16s report only (events to the central app)  <- %s\n", r.Name, src)
			continue
		}
		l, from := r.limits(), ""
		if l.central {
			from = " (central app)"
		}
		fmt.Fprintf(w, "  %-16s %s%s  <- %s\n", r.Name, l, from, src)
	}
	if n := st.Nginx; n != nil {
		names := cmp.Or(strings.Join(n.Rules, ", "), "none")
		if n.Error == "" {
			fmt.Fprintf(w, "  nginx optional rules from the central app: %s (applied %s)\n", names, n.At.Local().Format("2006-01-02 15:04"))
		} else {
			fmt.Fprintf(w, "  nginx optional rules from the central app: %s FAILED %s, retried every %s:\n    %s\n",
				names, n.At.Local().Format("2006-01-02 15:04"), shortDur(nginxRetry), strings.ReplaceAll(strings.TrimSpace(n.Error), "\n", "\n    "))
		}
	}

	type local struct {
		ip    netip.Addr
		rule  string
		n     int
		at    time.Time
		until time.Time
	}
	var bans []local
	for ip, until := range st.Banned {
		if !until.After(now) {
			continue
		}
		b := local{ip: ip, until: until}
		for rule, offs := range st.Offenses {
			if o, ok := offs[ip]; ok && o.Last.After(b.at) {
				b.rule, b.n, b.at = rule, o.N, o.Last
			}
		}
		bans = append(bans, b)
	}
	sort.Slice(bans, func(i, j int) bool { return bans[i].at.After(bans[j].at) })
	fmt.Fprintf(w, "\nlocal bans: %d active (made by this server; the rest of the firewall comes from the central app)\n", len(bans))
	for _, b := range bans[:min(len(bans), n)] {
		fmt.Fprintf(w, "  %s  %-39s %s #%d, until %s\n", b.at.Local().Format("2006-01-02 15:04"), b.ip, b.rule, b.n, b.until.Local().Format("2006-01-02 15:04"))
	}
	if more := len(bans) - n; more > 0 {
		fmt.Fprintf(w, "  ... and %d more\n", more)
	}

	if len(cfg.Denylists) > 0 {
		fmt.Fprintln(w, "\ndenylists:")
		for _, d := range cfg.Denylists {
			fi, err := os.Stat(d.Path)
			if err != nil {
				fmt.Fprintf(w, "  %s: %v\n", d.Path, err)
				continue
			}
			fmt.Fprintf(w, "  %s: updated %s ago\n", d.Path, now.Sub(fi.ModTime()).Round(time.Second))
		}
	}
}

// shortDur prints 24h as 1d, 1h0m0s as 1h.
func shortDur(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d >= day && d%day == 0:
		return fmt.Sprintf("%dd", d/day)
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
