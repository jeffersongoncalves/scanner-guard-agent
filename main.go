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
	case "ip":
		ipCmd(os.Args[2:])
	case "nginx-init":
		nginxInitCmd(os.Args[2:])
	case "nginx-test":
		nginxTestCmd(os.Args[2:])
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
  scanner-guard-agent run  [-config %s]
  scanner-guard-agent test [-config %s] [-rule NAME] [-ban] LOGFILE|-
  scanner-guard-agent ip   [-config %s] IP...
  scanner-guard-agent nginx-init [-dir %s] [-proxy cloudflare,CIDR,...]
  scanner-guard-agent nginx-test [-dir %s] ACCESSLOG|-
  scanner-guard-agent version
`, version, defaultConfig, defaultConfig, defaultConfig, defaultNginxDir, defaultNginxDir)
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

	counts := map[*Rule]map[netip.Addr]int{}
	patterns := map[*Rule]map[netip.Addr]string{} // last pattern matched, sent as matched_value
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, r := range cfg.rules {
			if *only != "" && r.Name != *only {
				continue
			}
			if ip, p, ok := r.Match(sc.Text()); ok {
				if counts[r] == nil {
					counts[r] = map[netip.Addr]int{}
					patterns[r] = map[netip.Addr]string{}
				}
				counts[r][ip]++
				patterns[r][ip] = p
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}

	var a *Agent
	isIgnored := cfg.ignored
	if *ban {
		a = scanAgent(cfg)
		isIgnored = a.ignored // also what the central app listed on the last pull
	}
	ctx := context.Background()
	now := time.Now()

	for _, r := range cfg.rules {
		if *only != "" && r.Name != *only {
			continue
		}
		ips := make([]netip.Addr, 0, len(counts[r]))
		total := 0
		for ip, n := range counts[r] {
			ips = append(ips, ip)
			total += n
		}
		sort.Slice(ips, func(i, j int) bool { return counts[r][ips[i]] > counts[r][ips[j]] })

		fmt.Printf("rule %s: %d matching lines, %d IPs\n", r.Name, total, len(ips))
		for _, ip := range ips {
			n, mark := counts[r][ip], ""
			switch {
			case isIgnored(hostPrefix(ip)):
				mark = "  (ignored)"
			case n < r.threshold:
			case a == nil:
				mark = "  <- would ban"
			default:
				if b, ok := a.decide(r, ip, patterns[r][ip], n, now); ok {
					mark = fmt.Sprintf("  <- banned %s (offense %d)", b.Duration, b.Offense)
					if err := a.enforce(ctx, b); err != nil {
						mark = fmt.Sprintf("  <- BAN FAILED (offense %d, still reported): %v", b.Offense, err)
					}
				} else {
					mark = "  (already banned)"
				}
			}
			fmt.Printf("  %6d  %s%s\n", n, ip, mark)
		}
	}

	if a != nil {
		a.reports.Wait() // a one-shot run must not exit before the central POSTs land
	}
}

// scanAgent builds an agent for test -ban. It loads and saves the same state
// file as the daemon, so the escalation ladder carries on, but it does not
// recreate an existing nftables table (that would drop every running ban).
func scanAgent(cfg *Config) *Agent {
	fw, err := newFirewall(cfg.Firewall)
	if err != nil {
		log.Fatal(err)
	}
	if n, ok := fw.(nftables); ok {
		if err := n.Ensure(); err != nil {
			log.Fatalf("firewall init: %v", err)
		}
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		log.Fatalf("state %s: %v", cfg.StateFile, err)
	}
	return newAgent(cfg, fw, st)
}
