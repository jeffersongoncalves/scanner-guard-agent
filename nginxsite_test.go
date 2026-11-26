package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const siteExample = `server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    #listen 8443 ssl;
    server_name example.com www.example.com; # main
    location / {
        try_files $uri /index.php?$query_string;
    }
}
`

const siteOther = `server {
	listen 80;
#	listen 443 ssl;
	server_name other.test;
	root /var/www/other;
}
`

// fakeNginx records what would run; nginx -t fails when test is set.
type fakeNginx struct {
	testErr error
	reloads int
	probes  []string
}

func (f *fakeNginx) ops() nginxOps {
	return nginxOps{
		test: func() (string, error) {
			return "nginx: [emerg] unknown directive\nnginx: configuration file test failed", f.testErr
		},
		reload: func() error { f.reloads++; return nil },
		probe: func(site string, t probeTarget, path string) (int, error) {
			f.probes = append(f.probes, site+" "+t.String()+" "+path)
			if strings.Contains(path, "union") {
				return 403, nil
			}
			return 200, nil
		},
	}
}

func nginxDir(t *testing.T, sites map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"conf.d", "sites-available", "sites-enabled"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range sites {
		if err := os.WriteFile(filepath.Join(dir, "sites-enabled", name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestParseSiteFile(t *testing.T) {
	f := parseSiteFile("x", siteExample)
	if len(f.blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(f.blocks))
	}
	b := f.blocks[1]
	if strings.Join(b.names, ",") != "example.com,www.example.com" || b.nameLine != 9 || b.start != 6 || b.end != 13 {
		t.Errorf("block = %+v", b)
	}
	if len(b.listens) != 1 || b.listens[0] != "443 ssl http2" {
		t.Errorf("listens = %q, the commented one must not count", b.listens)
	}
}

func TestParseListen(t *testing.T) {
	for in, want := range map[string]string{
		"80":                        "http 127.0.0.1:80",
		"443 ssl http2":             "https 127.0.0.1:443",
		"[::]:443 ssl":              "https 127.0.0.1:443",
		"10.0.0.5:8080":             "http 10.0.0.5:8080",
		"*:8443 ssl":                "https 127.0.0.1:8443",
		"[2001:db8::5]:80":          "http [2001:db8::5]:80",
		"443":                       "https 127.0.0.1:443",
		"0.0.0.0:80 default_server": "http 127.0.0.1:80",
	} {
		if got := parseListen(in).String(); got != want {
			t.Errorf("parseListen(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestNginxEnableDisable(t *testing.T) {
	dir := nginxDir(t, map[string]string{"example": siteExample, "other": siteOther})
	f := &fakeNginx{}
	var out bytes.Buffer
	if err := nginxEnable(dir, []string{"example.com", "other.test"}, &out, f.ops()); err != nil {
		t.Fatal(err)
	}

	got := read(t, filepath.Join(dir, "sites-enabled", "example"))
	if strings.Count(got, "    "+nginxInclude+"\n    server_name example.com") != 2 {
		t.Errorf("include before each server_name:\n%s", got)
	}
	if !strings.Contains(read(t, filepath.Join(dir, "sites-enabled", "other")), "\t"+nginxInclude+"\n\tserver_name other.test;") {
		t.Errorf("other.test: tab indent kept")
	}
	if _, err := os.Stat(filepath.Join(dir, nginxRulesFile)); err != nil {
		t.Errorf("rules not created: %v", err)
	}
	if f.reloads != 1 {
		t.Errorf("reloads = %d, want one for every site", f.reloads)
	}
	// https for the site on 443, http for the one whose 443 is commented out.
	want := []string{
		"example.com https 127.0.0.1:443 /?id=1+union+select+1", "example.com https 127.0.0.1:443 /",
		"other.test http 127.0.0.1:80 /?id=1+union+select+1", "other.test http 127.0.0.1:80 /",
	}
	if strings.Join(f.probes, "|") != strings.Join(want, "|") {
		t.Errorf("probes = %q", f.probes)
	}
	if !strings.Contains(out.String(), "attack: 403 ok") {
		t.Errorf("output:\n%s", out.String())
	}

	out.Reset()
	if err := nginxEnable(dir, []string{"www.example.com"}, &out, f.ops()); err != nil || !strings.Contains(out.String(), "already on") {
		t.Errorf("second enable: %v\n%s", err, out.String())
	}

	var sites bytes.Buffer
	if err := nginxSites(dir, &sites); err != nil || !strings.Contains(sites.String(), "3 of 3 server blocks on") {
		t.Errorf("sites: %v\n%s", err, sites.String())
	}

	if err := nginxDisable(dir, []string{"example.com"}, &out, f.ops()); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(dir, "sites-enabled", "example")); got != siteExample {
		t.Errorf("disable must give the original file back:\n%s", got)
	}
}

func TestNginxEnableRestoresOnFailedTest(t *testing.T) {
	dir := nginxDir(t, map[string]string{"example": siteExample})
	f := &fakeNginx{testErr: errors.New("exit status 1")}
	err := nginxEnable(dir, []string{"example.com"}, &bytes.Buffer{}, f.ops())
	if err == nil || !strings.Contains(err.Error(), "configuration file test failed") {
		t.Fatalf("err = %v", err)
	}
	if got := read(t, filepath.Join(dir, "sites-enabled", "example")); got != siteExample {
		t.Errorf("not restored:\n%s", got)
	}
	if f.reloads != 0 {
		t.Error("reloaded after a failed nginx -t")
	}
}

func TestNginxEnableForge(t *testing.T) {
	site := "server {\n    listen 443 ssl;\n    server_name app.test;\n    include forge-conf/123/server/*;\n}\n"
	dir := nginxDir(t, map[string]string{"app.test": site})
	f := &fakeNginx{}
	if err := nginxEnable(dir, []string{"app.test"}, &bytes.Buffer{}, f.ops()); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(dir, "forge-conf", "123", "server", forgeIncludeFile)
	if got := read(t, inc); got != nginxInclude+"\n" {
		t.Errorf("forge include = %q", got)
	}
	if got := read(t, filepath.Join(dir, "sites-enabled", "app.test")); got != site {
		t.Errorf("a Forge site file must stay untouched:\n%s", got)
	}

	if err := nginxDisable(dir, []string{"app.test"}, &bytes.Buffer{}, f.ops()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(inc); !os.IsNotExist(err) {
		t.Errorf("forge include still there: %v", err)
	}
}

func TestFindSiteSuggests(t *testing.T) {
	files := []*siteFile{parseSiteFile("x", siteExample)}
	_, err := findSite(files, "example")
	if err == nil || !strings.Contains(err.Error(), "did you mean example.com, www.example.com?") {
		t.Errorf("err = %v", err)
	}
}
