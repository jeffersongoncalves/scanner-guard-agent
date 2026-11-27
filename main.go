// Command scanner-guard-agent watches server logs (sshd, nginx, postfix, ...)
// for abusive IPs, bans them in nftables and reports every ban to a central
// laravel-scanner-guard app, pulling the central denylist back.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
)

var version = "dev"

const defaultConfig = "/etc/scanner-guard/agent.yaml"

func main() {
	log.SetFlags(0) // systemd/journald already timestamps every line

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "test":
		testCmd(os.Args[2:])
	case "replay":
		replayCmd(os.Args[2:])
	case "status":
		statusCmd(os.Args[2:])
	case "ip":
		ipCmd(os.Args[2:])
	case "monitor":
		monitorCmd(os.Args[2:])
	case "nginx-init":
		nginxInitCmd(os.Args[2:])
	case "nginx-test":
		nginxTestCmd(os.Args[2:])
	case "nginx-sites":
		nginxSitesCmd(os.Args[2:])
	case "nginx-enable":
		nginxEnableCmd(os.Args[2:])
	case "nginx-disable":
		nginxDisableCmd(os.Args[2:])
	case "nginx-report":
		nginxReportCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `scanner-guard-agent %s

Usage:
  scanner-guard-agent run    [-config FILE]
  scanner-guard-agent status [-config FILE] [-n 10]               what is blocked, the rules, the last bans
  scanner-guard-agent ip     [-config FILE] IP...                  why an IP is blocked, or not
  scanner-guard-agent replay [-config FILE] [-since 7d] [-rule NAME] [-ban]
                                                                   the rules over the past logs: who would be banned (-ban: ban them)
  scanner-guard-agent test   [-config FILE] [-rule NAME] [-ban] LOGFILE|-
  scanner-guard-agent monitor [-config FILE] [-no-restart] [NAME on|off]
                                                                   ready-made monitors (ssh-logins), on or off

  scanner-guard-agent nginx-init    [-dir DIR] [-proxy cloudflare,CIDR,...]
  scanner-guard-agent nginx-test    [-dir DIR] ACCESSLOG|-        what the 403 rules would block in a log
  scanner-guard-agent nginx-sites   [-dir DIR]                     every site, 403 on or off
  scanner-guard-agent nginx-enable  [-dir DIR] SITE...             403 on (tested, reverted if nginx -t fails)
  scanner-guard-agent nginx-disable [-dir DIR] SITE...             403 off
  scanner-guard-agent nginx-report  [-since 24h] [-host SITE] [-n 10] [LOG|-]
                                                                   what the 403 rules blocked
  scanner-guard-agent version

FILE defaults to %s, DIR to %s, LOG to %s.
`, version, defaultConfig, defaultNginxDir, defaultGuardLog)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	_ = fs.Parse(args)

	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}

	fw, err := newFirewall(cfg.Firewall)
	if err != nil {
		log.Fatal(err)
	}
	if err := fw.Init(); err != nil {
		log.Fatalf("firewall init: %v", err)
	}

	st, err := loadState(cfg.StateFile)
	if err != nil {
		// A corrupt file must not keep the agent down: start over at step one.
		log.Printf("state %s: %v (starting empty)", cfg.StateFile, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("scanner-guard-agent %s started: source=%s firewall=%s rules=%d", version, cfg.Source, cfg.Firewall, len(cfg.rules))
	newAgent(cfg, fw, st).run(ctx)
	log.Print("stopped")
}

// testCmd replays a log file through the rules, so a pattern can be checked
// before it bans anyone. Line timestamps are unknown, so the window is ignored.
// With -ban it also bans what it found and reports it to the central app.
func testCmd(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	only := fs.String("rule", "", "only test this rule")
	ban := fs.Bool("ban", false, "ban the IPs over the threshold and report them to the central app (stop the agent first)")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}

	var in io.Reader = os.Stdin
	if name := fs.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}

	rules := selectRules(cfg, *only)
	tallies := map[*Rule]*tally{}
	for _, r := range rules {
		tallies[r] = newTally()
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, r := range rules {
			tallies[r].add(r, sc.Text(), *ban)
		}
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}

	var a *Agent
	isIgnored := cfg.ignored
	if *ban {
		if a, err = scanAgent(cfg); err != nil {
			log.Fatal(err)
		}
		isIgnored = a.ignored // also what the central app listed on the last pull
	}
	judge(os.Stdout, rules, tallies, isIgnored, a, time.Now())
	if a != nil {
		a.reports.Wait() // a one-shot run must not exit before the central POSTs land
	}
}

func selectRules(cfg *Config, only string) []*Rule {
	var rules []*Rule
	for _, r := range cfg.rules {
		if only == "" || r.Name == only {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		log.Fatalf("no rule named %q", only)
	}
	return rules
}

// tally counts the lines of one rule per IP, without a window: replayed lines
// carry no usable time.
type tally struct {
	counts   map[netip.Addr]int
	patterns map[netip.Addr]string   // last pattern matched, sent as matched_value
	evidence map[netip.Addr][]string // last matching lines, sent as evidence
}

func newTally() *tally {
	return &tally{counts: map[netip.Addr]int{}, patterns: map[netip.Addr]string{}, evidence: map[netip.Addr][]string{}}
}

func (t *tally) add(r *Rule, line string, keepEvidence bool) {
	ip, p, ok := r.Match(line)
	if !ok {
		return
	}
	t.counts[ip]++
	t.patterns[ip] = p
	if keepEvidence {
		ev := append(t.evidence[ip], truncate(line, maxEvidenceLine))
		t.evidence[ip] = ev[max(0, len(ev)-maxEvidence):]
	}
}

// judge prints every IP each rule matched, most lines first, and bans the ones
// over the threshold when a is set (a nil: only says who would be). It returns
// how many are (or would be) banned and how many are ignored.
func judge(w io.Writer, rules []*Rule, tallies map[*Rule]*tally, isIgnored func(netip.Prefix) bool, a *Agent, now time.Time) (bans, ignored int) {
	ctx := context.Background()
	for _, r := range rules {
		t := tallies[r]
		ips := make([]netip.Addr, 0, len(t.counts))
		total := 0
		for ip, n := range t.counts {
			ips = append(ips, ip)
			total += n
		}
		sort.Slice(ips, func(i, j int) bool {
			if a, b := t.counts[ips[i]], t.counts[ips[j]]; a != b {
				return a > b
			}
			return ips[i].Less(ips[j])
		})

		kind := ""
		if r.report {
			kind = " (report only: never bans)"
		}
		fmt.Fprintf(w, "rule %s%s: %d matching lines, %d IPs\n", r.Name, kind, total, len(ips))
		for _, ip := range ips {
			n, mark := t.counts[ip], ""
			switch {
			case r.report: // events, never bans
			case isIgnored(hostPrefix(ip)):
				mark = "  (ignored)"
				ignored++
			case n < r.limits().threshold:
			case a == nil:
				mark = "  <- would ban"
				bans++
			default:
				if b, ok := a.decide(r, ip, t.patterns[ip], n, now); ok {
					b.Evidence = t.evidence[ip]
					mark = fmt.Sprintf("  <- banned %s (offense %d)", b.Duration, b.Offense)
					bans++
					if err := a.enforce(ctx, b); err != nil {
						mark = fmt.Sprintf("  <- BAN FAILED (offense %d, still reported): %v", b.Offense, err)
					}
				} else {
					mark = "  (already banned)"
				}
			}
			fmt.Fprintf(w, "  %6d  %s%s\n", n, ip, mark)
		}
	}
	return bans, ignored
}

// scanAgent builds an agent for test -ban and replay -ban. It loads and saves
// the same state file as the daemon, so the escalation ladder carries on, but
// it does not recreate an existing nftables table (that would drop every
// running ban).
func scanAgent(cfg *Config) (*Agent, error) {
	fw, err := newFirewall(cfg.Firewall)
	if err != nil {
		return nil, err
	}
	if n, ok := fw.(nftables); ok {
		if err := n.Ensure(); err != nil {
			return nil, fmt.Errorf("firewall init: %w", err)
		}
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		return nil, fmt.Errorf("state %s: %w", cfg.StateFile, err)
	}
	return newAgent(cfg, fw, st), nil
}
