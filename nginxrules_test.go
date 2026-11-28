package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// oldRules is the shipped rules file as written before 2.8.0: no includes.
func oldRules() string {
	return regexp.MustCompile(`(?m)^\n?.*nginx_rules.*\n.*include /var/lib/scanner-guard.*\n`).ReplaceAllString(string(nginxRulesConf), "")
}

func TestWithOptionalIncludes(t *testing.T) {
	old := oldRules()
	if strings.Contains(old, nginxOptionalDir) {
		t.Fatal("oldRules still has the includes")
	}
	conf, changed, err := withOptionalIncludes(old)
	if err != nil || !changed {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	// Each include lands at the end of its own map.
	for file, m := range optionalMaps {
		head := strings.Index(conf, "$"+m+" {")
		inc := strings.Index(conf, optionalInclude(file))
		end := head + strings.Index(conf[head:], "\n}")
		if head < 0 || inc < head || inc > end {
			t.Errorf("%s not inside map $%s", optionalInclude(file), m)
		}
	}
	if _, err := parseNginxMaps(conf); err != nil {
		t.Fatal(err)
	}
	if _, changed, _ := withOptionalIncludes(conf); changed {
		t.Error("added the includes twice")
	}
	if _, changed, _ := withOptionalIncludes(string(nginxRulesConf)); changed {
		t.Error("the shipped file already has them")
	}
	if _, _, err := withOptionalIncludes("mine"); err == nil {
		t.Error("accepted a file without the maps")
	}
}

func TestNginxInitAddsIncludes(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, nginxRulesFile)
	if err := os.MkdirAll(filepath.Dir(rules), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte(oldRules()), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeNginx{}
	var out strings.Builder
	if err := nginxInit(dir, nil, &out, f.ops()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(rules); !strings.Contains(string(got), optionalInclude("path")) || f.reloads != 1 {
		t.Errorf("reloads %d, output:\n%s", f.reloads, out.String())
	}

	// nginx -t fails: the old file comes back.
	if err := os.WriteFile(rules, []byte(oldRules()), 0o644); err != nil {
		t.Fatal(err)
	}
	f = &fakeNginx{testErr: errors.New("exit status 1")}
	if err := nginxInit(dir, nil, io.Discard, f.ops()); err == nil {
		t.Fatal("nginx -t failed, no error")
	}
	if got, _ := os.ReadFile(rules); string(got) != oldRules() {
		t.Error("rules file not restored")
	}
}

func TestSetNginxRules(t *testing.T) {
	dir, opt := t.TempDir(), t.TempDir()
	rules := filepath.Join(dir, nginxRulesFile)
	if err := os.MkdirAll(filepath.Dir(rules), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte(oldRules()), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeNginx{}
	a := newAgent(&Config{rules: []*Rule{{Name: "web_attack", file: defaultGuardLog}}}, fakeFirewall{}, newState())
	a.nginxDir, a.nginxOptional, a.nginx = dir, opt, f.ops()

	// Not included yet (nginx-init not run): nothing written.
	a.setNginxRules([]string{"cms"}, time.Now())
	if _, err := os.Stat(filepath.Join(opt, "path.conf")); err == nil || f.reloads != 0 {
		t.Fatal("wrote optional rules nginx doesn't include")
	}

	if err := os.WriteFile(rules, nginxRulesConf, 0o644); err != nil {
		t.Fatal(err)
	}
	a.nginxRules = nil
	a.setNginxRules([]string{"cms", "empty-agent", "bogus"}, time.Now())
	path, _ := os.ReadFile(filepath.Join(opt, "path.conf"))
	agent, _ := os.ReadFile(filepath.Join(opt, "agent.conf"))
	uri, _ := os.ReadFile(filepath.Join(opt, "uri.conf"))
	if !strings.Contains(string(path), " cms;") || !strings.Contains(string(agent), "empty-agent;") || strings.Contains(string(uri), ";") || f.reloads != 1 {
		t.Fatalf("reloads %d\npath %s\nagent %s\nuri %s", f.reloads, path, agent, uri)
	}

	a.setNginxRules([]string{"cms", "empty-agent", "bogus"}, time.Now())
	if f.reloads != 1 {
		t.Error("reloaded for the same set")
	}

	// nginx -t fails: the previous files stay, and the same set is not retried.
	f.testErr = errors.New("exit status 1")
	a.setNginxRules([]string{"rfi"}, time.Now())
	if got, _ := os.ReadFile(filepath.Join(opt, "path.conf")); !strings.Contains(string(got), " cms;") || f.reloads != 1 {
		t.Errorf("not restored after nginx -t failed: %s", got)
	}

	// The failure shows in status; the same set is tried again only after nginxRetry.
	failed := a.state.Nginx
	if failed == nil || !strings.Contains(failed.Error, "nginx -t failed") {
		t.Fatalf("failure not recorded: %+v", failed)
	}
	var out strings.Builder
	writeStatus(&out, &Config{}, a.state, "active", nil, nil, 0, time.Now())
	if !strings.Contains(out.String(), "rfi FAILED") {
		t.Errorf("status:\n%s", out.String())
	}
	f.testErr = nil
	a.setNginxRules([]string{"rfi"}, failed.At.Add(time.Minute))
	if f.reloads != 1 {
		t.Error("retried before nginxRetry")
	}
	a.setNginxRules([]string{"rfi"}, failed.At.Add(nginxRetry))
	if got, _ := os.ReadFile(filepath.Join(opt, "uri.conf")); !strings.Contains(string(got), " rfi;") || f.reloads != 2 || a.state.Nginx.Error != "" {
		t.Errorf("not retried after nginxRetry (reloads %d, state %+v): %s", f.reloads, a.state.Nginx, got)
	}
	a.setNginxRules([]string{"cms", "empty-agent"}, time.Now())

	// What nginx-test reads through the include is what nginx would.
	conf := strings.ReplaceAll(string(nginxRulesConf), nginxOptionalDir, filepath.ToSlash(opt))
	maps, err := parseNginxMaps(conf)
	if err != nil {
		t.Fatal(err)
	}
	if got := nginxRule(maps, "/wp-login.php", "x"); got != "cms" {
		t.Errorf("/wp-login.php: %q", got)
	}
	if got := nginxRule(maps, "/", "-"); got != "empty-agent" {
		t.Errorf("no User-Agent: %q", got)
	}
}

// No web_attack rule (a server without nginx, too): nobody bans on the 403s.
func TestSetNginxRulesWithoutWebAttack(t *testing.T) {
	f := &fakeNginx{}
	a := newAgent(&Config{rules: []*Rule{{Name: "ssh_bruteforce", journald: []string{"ssh.service"}}}}, fakeFirewall{}, newState())
	a.nginxDir, a.nginxOptional, a.nginx = t.TempDir(), t.TempDir(), f.ops()
	a.state.Nginx = &nginxApplied{Rules: []string{"cms"}, Error: "no conf.d/scanner-guard-rules.conf on this server"}
	a.setNginxRules([]string{"cms"}, time.Now())
	if a.state.Nginx != nil || f.reloads != 0 {
		t.Errorf("server without nginx: state %+v, reloads %d", a.state.Nginx, f.reloads)
	}
}

func TestNginxTestWith(t *testing.T) {
	maps := shippedMaps(t)
	if got := nginxRule(maps, "/x?u=https://evil.example/", "x"); got != "" {
		t.Fatalf("rfi is off by default, got %q", got)
	}
	if err := addOptional(maps, "rfi, encoded"); err != nil {
		t.Fatal(err)
	}
	if got := nginxRule(maps, "/x?u=https://evil.example/", "x"); got != "rfi" {
		t.Errorf("-with rfi: %q", got)
	}
	if err := addOptional(maps, "nope"); err == nil {
		t.Error("accepted an unknown rule")
	}
}

func TestRemoteDiagnosis(t *testing.T) {
	got := make(chan map[string]any, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path == "/bans/diagnostics" {
			got <- body
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cfg := &Config{Source: "vps-01", secret: "s3cret", Central: CentralConfig{URL: srv.URL + "/bans", Timeout: Duration(5 * time.Second)}}
	a := newAgent(cfg, fakeFirewall{}, newState())
	a.exec = fakeRun(map[string]string{"ping": "4 packets transmitted, 4 received, 0% packet loss"}, nil)

	a.startDiagnosis(context.Background(), DiagnosisRequest{ID: 7, IP: "203.0.113.9"})
	a.startDiagnosis(context.Background(), DiagnosisRequest{ID: 7, IP: "203.0.113.9"}) // listed again before it ended
	body := <-got
	if body["id"] != float64(7) || body["source"] != "vps-01" || !strings.Contains(body["report"].(string), "== verdict ==") {
		t.Fatalf("%v", body)
	}

	a.startDiagnosis(context.Background(), DiagnosisRequest{ID: 8, IP: "not-an-ip"})
	if body := <-got; !strings.Contains(body["report"].(string), "is not an IP address") {
		t.Errorf("%v", body)
	}

	off := false
	a.cfg.Central.Diagnose = &off
	a.startDiagnosis(context.Background(), DiagnosisRequest{ID: 9, IP: "203.0.113.9"})
	if body := <-got; !strings.Contains(body["report"].(string), "are off on this server") {
		t.Errorf("%v", body)
	}

	select {
	case extra := <-got:
		t.Errorf("id 7 ran twice: %v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}
