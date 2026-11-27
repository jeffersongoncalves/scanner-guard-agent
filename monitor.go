package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// monitors are ready-made report rules, switched on and off by
// `scanner-guard-agent monitor NAME on|off` as one file in rules.d, so a server
// gets them without editing its agent.yaml.
var monitors = map[string]struct {
	about string
	rule  string // the rule's name, also the file name
	yaml  string
}{
	"ssh-logins": {
		about: "every accepted SSH login (user, method, key) as an event on the central app",
		rule:  "ssh_login",
		yaml: `# Written by scanner-guard-agent monitor ssh-logins on; "off" deletes it.
rules:
  - name: ssh_login
    journald: [ssh.service, sshd.service]
    report: true
    patterns:
      - 'Accepted (?P<method>\S+) for (?P<user>\S+) from <ip> port \d+ ssh2(?:: \S+ (?P<key>SHA256:\S+))?'
`,
	},
}

func monitorCmd(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	noRestart := fs.Bool("no-restart", false, "do not restart the agent")
	_ = fs.Parse(args)

	switch fs.NArg() {
	case 0:
		if err := monitorList(os.Stdout, *path); err != nil {
			log.Fatal(err)
		}
		return
	case 2:
	default:
		usage()
		os.Exit(2)
	}

	state := fs.Arg(1)
	if state != "on" && state != "off" {
		log.Fatalf("%q: use on or off", state)
	}
	msg, changed, err := monitorSet(*path, fs.Arg(0), state == "on")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(msg)
	if !changed || *noRestart {
		return
	}
	// try-restart: a stopped agent stays stopped and picks the change up on start.
	if out, err := exec.Command("systemctl", "try-restart", "scanner-guard-agent").CombinedOutput(); err != nil {
		log.Fatalf("systemctl try-restart scanner-guard-agent: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Println("agent restarted")
}

// monitorSet writes or deletes the monitor's file, reporting whether anything
// changed. A file the config then fails to load with is removed again.
func monitorSet(configPath, name string, on bool) (string, bool, error) {
	m, ok := monitors[name]
	if !ok {
		return "", false, fmt.Errorf("unknown monitor %q (%s)", name, strings.Join(monitorNames(), ", "))
	}
	file := filepath.Join(rulesDir(configPath), m.rule+".yaml")
	_, err := os.Stat(file)
	exists := err == nil

	if !on {
		if !exists {
			if inMainConfig(configPath, m.rule) {
				return "", false, fmt.Errorf("rule %s is in %s: remove it there", m.rule, configPath)
			}
			return name + " is already off", false, nil
		}
		if err := os.Remove(file); err != nil {
			return "", false, err
		}
		return name + " off", true, nil
	}

	if exists {
		return name + " is already on", false, nil
	}
	if inMainConfig(configPath, m.rule) {
		return name + " is already on (rule " + m.rule + " in " + configPath + ")", false, nil
	}
	if err := os.MkdirAll(rulesDir(configPath), 0o755); err != nil {
		return "", false, err
	}
	if err := os.WriteFile(file, []byte(m.yaml), 0o644); err != nil {
		return "", false, err
	}
	if _, err := loadConfig(configPath); err != nil {
		_ = os.Remove(file)
		return "", false, fmt.Errorf("left off, the config does not load with it: %w", err)
	}
	return name + " on: " + m.about, true, nil
}

func monitorList(w io.Writer, configPath string) error {
	for _, name := range monitorNames() {
		m := monitors[name]
		state := "off"
		if _, err := os.Stat(filepath.Join(rulesDir(configPath), m.rule+".yaml")); err == nil {
			state = "on"
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		} else if inMainConfig(configPath, m.rule) {
			state = "on (in " + filepath.Base(configPath) + ")"
		}
		fmt.Fprintf(w, "%-12s %-18s %s\n", name, state, m.about)
	}
	return nil
}

// inMainConfig reports whether the config itself (not rules.d) has the rule.
func inMainConfig(configPath, rule string) bool {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return false
	}
	for _, r := range cfg.Rules {
		if r.Name == rule {
			return true
		}
	}
	return false
}

func monitorNames() []string {
	names := make([]string, 0, len(monitors))
	for n := range monitors {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
