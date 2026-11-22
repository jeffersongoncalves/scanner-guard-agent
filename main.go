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
	"os"
	"os/signal"
	"sort"
	"syscall"
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
  scanner-guard-agent test [-config %s] [-rule NAME] LOGFILE|-
  scanner-guard-agent version
`, version, defaultConfig, defaultConfig)
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
func testCmd(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	only := fs.String("rule", "", "only test this rule")
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

	counts := map[*Rule]map[string]int{}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, r := range cfg.rules {
			if *only != "" && r.Name != *only {
				continue
			}
			if ip, _, ok := r.Match(sc.Text()); ok {
				if counts[r] == nil {
					counts[r] = map[string]int{}
				}
				counts[r][ip.String()]++
			}
		}
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}

	for _, r := range cfg.rules {
		if *only != "" && r.Name != *only {
			continue
		}
		ips := make([]string, 0, len(counts[r]))
		total := 0
		for ip, n := range counts[r] {
			ips = append(ips, ip)
			total += n
		}
		sort.Slice(ips, func(i, j int) bool { return counts[r][ips[i]] > counts[r][ips[j]] })

		fmt.Printf("rule %s: %d matching lines, %d IPs\n", r.Name, total, len(ips))
		for _, ip := range ips {
			mark := ""
			if counts[r][ip] >= r.threshold {
				mark = "  <- would ban"
			}
			if cfg.ignored(mustTarget(ip)) {
				mark = "  (ignored)"
			}
			fmt.Printf("  %6d  %s%s\n", counts[r][ip], ip, mark)
		}
	}
}
