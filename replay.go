package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// replayCmd runs every rule over its own past logs (journald since -since, or
// the whole file): who would be banned before going live, and with -ban the
// bans of the attackers already in the logs.
func replayCmd(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	only := fs.String("rule", "", "only replay this rule")
	sinceFlag := fs.String("since", "7d", "how far back journald rules read (file rules read the whole file)")
	ban := fs.Bool("ban", false, "ban the IPs over the threshold and report them to the central app (stops the running agent meanwhile)")
	_ = fs.Parse(args)

	since, err := parseDuration(*sinceFlag)
	if err != nil {
		log.Fatalf("-since: %v", err)
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	st, err := loadState(cfg.StateFile)
	if err != nil {
		log.Printf("state %s: %v", cfg.StateFile, err)
	}
	applyRuleSettings(cfg.rules, st.Rules, func(string, ...any) {}) // as the running agent counts
	rules := selectRules(cfg, *only)

	tallies := map[*Rule]*tally{}
	for _, r := range rules {
		t, err := replayRule(r, time.Now().Add(-since), *ban)
		if err != nil {
			log.Fatalf("rule %s: %v", r.Name, err)
		}
		tallies[r] = t
	}

	isIgnored := func(p netip.Prefix) bool { return cfg.ignored(p) || slices.ContainsFunc(st.Ignore, p.Overlaps) }
	if !*ban {
		bans, ignored := judge(os.Stdout, rules, tallies, isIgnored, nil, time.Now())
		fmt.Printf("\nwould ban: %d   ignored: %d\n", bans, ignored)
		fmt.Println("A customer, a partner or a monitor in there? Add it to ignore in agent.yaml, or to Never block in the central app.")
		return
	}

	// The running agent saves the same state file: stop it meanwhile.
	running := exec.Command("systemctl", "is-active", "--quiet", "scanner-guard-agent").Run() == nil
	if running {
		fmt.Println("stopping scanner-guard-agent meanwhile")
		if out, err := exec.Command("systemctl", "stop", "scanner-guard-agent").CombinedOutput(); err != nil {
			log.Fatalf("systemctl stop scanner-guard-agent: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	a, err := scanAgent(cfg)
	if err == nil {
		bans, ignored := judge(os.Stdout, rules, tallies, a.ignored, a, time.Now())
		a.reports.Wait() // a one-shot run must not exit before the central POSTs land
		fmt.Printf("\nbanned: %d   ignored: %d\n", bans, ignored)
	}
	if running {
		if out, serr := exec.Command("systemctl", "start", "scanner-guard-agent").CombinedOutput(); serr != nil {
			log.Printf("systemctl start scanner-guard-agent: %v: %s", serr, strings.TrimSpace(string(out)))
			err = fmt.Errorf("the agent is stopped, start it: systemctl start scanner-guard-agent")
		} else {
			fmt.Println("scanner-guard-agent started again")
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}

// replayRule counts the past lines of r from its own source.
func replayRule(r *Rule, since time.Time, keepEvidence bool) (*tally, error) {
	t := newTally()
	var in io.ReadCloser
	var cmd *exec.Cmd
	if r.file != "" {
		f, err := os.Open(r.file)
		if err != nil {
			return nil, err
		}
		in = f
	} else {
		args := []string{"--since=" + since.Format("2006-01-02 15:04:05"), "--output=cat", "--no-pager"}
		for _, u := range r.journald {
			args = append(args, "--unit="+u)
		}
		cmd = exec.Command("journalctl", args...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		in = out
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		t.add(r, sc.Text(), keepEvidence)
	}
	err := sc.Err()
	in.Close()
	if cmd != nil {
		if werr := cmd.Wait(); err == nil && werr != nil {
			err = fmt.Errorf("journalctl: %w", werr)
		}
	}
	return t, err
}
