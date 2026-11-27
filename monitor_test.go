package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const monitorBase = "rules:\n  - {name: r, file: /x, patterns: ['<ip>'], threshold: 1, window: 1m, ban: [1h]}\n"

func monitorConfig(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMonitorOnOff(t *testing.T) {
	f := monitorConfig(t, monitorBase)

	if _, changed, err := monitorSet(f, "ssh-logins", true); err != nil || !changed {
		t.Fatalf("on: changed=%v err=%v", changed, err)
	}
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.rules) != 2 || cfg.rules[1].Name != "ssh_login" || !cfg.rules[1].report {
		t.Fatalf("rules.d not loaded: %+v", cfg.Rules)
	}
	if msg, changed, _ := monitorSet(f, "ssh-logins", true); changed || !strings.Contains(msg, "already on") {
		t.Fatalf("second on: %q changed=%v", msg, changed)
	}

	var out strings.Builder
	if err := monitorList(&out, f); err != nil || !strings.Contains(out.String(), "ssh-logins   on ") {
		t.Fatalf("list: %q %v", out.String(), err)
	}

	if _, changed, err := monitorSet(f, "ssh-logins", false); err != nil || !changed {
		t.Fatalf("off: changed=%v err=%v", changed, err)
	}
	if cfg, _ := loadConfig(f); len(cfg.rules) != 1 {
		t.Fatal("rule still loaded after off")
	}
	if msg, changed, _ := monitorSet(f, "ssh-logins", false); changed || !strings.Contains(msg, "already off") {
		t.Fatalf("second off: %q", msg)
	}
}

func TestMonitorRuleInMainConfig(t *testing.T) {
	f := monitorConfig(t, monitorBase+"  - {name: ssh_login, journald: [ssh.service], report: true, patterns: ['from <ip>']}\n")

	if msg, changed, err := monitorSet(f, "ssh-logins", true); err != nil || changed || !strings.Contains(msg, "already on") {
		t.Fatalf("on: %q changed=%v err=%v", msg, changed, err)
	}
	if _, _, err := monitorSet(f, "ssh-logins", false); err == nil || !strings.Contains(err.Error(), "remove it there") {
		t.Fatalf("off must point at the config: %v", err)
	}
	var out strings.Builder
	_ = monitorList(&out, f)
	if !strings.Contains(out.String(), "on (in agent.yaml)") {
		t.Fatalf("list: %q", out.String())
	}
}

func TestMonitorLeftOffWhenConfigBreaks(t *testing.T) {
	f := monitorConfig(t, monitorBase)
	bad := monitorConfig(t, monitorBase+"bogus: 1\n") // unknown key: loadConfig fails

	if _, _, err := monitorSet(bad, "ssh-logins", true); err == nil {
		t.Fatal("a config that does not load must refuse the monitor")
	}
	if _, err := os.Stat(filepath.Join(rulesDir(bad), "ssh_login.yaml")); !os.IsNotExist(err) {
		t.Fatal("file kept after a failed load")
	}
	if _, _, err := monitorSet(f, "nope", true); err == nil || !strings.Contains(err.Error(), "ssh-logins") {
		t.Fatalf("unknown monitor: %v", err)
	}
}
