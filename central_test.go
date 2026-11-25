package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Vector checked against PHP in laravel-scanner-guard's SignedResponseTest.
func TestVerifyMatchesPHP(t *testing.T) {
	got := signResponse("1700000000", strings.Repeat("a", 64), "vps-01", `{"bans":[]}`, "secret")
	if got != "1ad7189f847c000414df825a35600c719979793f0d3330d895e9f989d073bac6" {
		t.Errorf("response signature = %s", got)
	}
}

func TestPullVerifiesSignature(t *testing.T) {
	const body = `{"bans":[],"ip_blocklist":["192.0.2.0/24"]}`
	type reply struct {
		ts, request, source, body, secret string
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	ago := func(d time.Duration) string { return strconv.FormatInt(time.Now().Add(-d).Unix(), 10) }

	for name, tc := range map[string]struct {
		change           func(*reply)
		unsigned         bool
		optional, always bool // accepted with require_signed_response off / on
	}{
		"signed":          {change: func(*reply) {}, optional: true, always: true},
		"clock drift":     {change: func(r *reply) { r.ts = ago(4 * time.Minute) }, optional: true, always: true},
		"unsigned":        {unsigned: true, optional: true},
		"tampered body":   {change: func(r *reply) { r.body = `{"bans":[]}` }},
		"wrong secret":    {change: func(r *reply) { r.secret = "other" }},
		"another source":  {change: func(r *reply) { r.source = "vps-02" }},
		"another request": {change: func(r *reply) { r.request = strings.Repeat("0", 64) }},
		"expired":         {change: func(r *reply) { r.ts = ago(10 * time.Minute) }},
		"future":          {change: func(r *reply) { r.ts = ago(-10 * time.Minute) }},
		"not a timestamp": {change: func(r *reply) { r.ts = "now" }},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !tc.unsigned {
				r := reply{now, req.Header.Get("X-Signature"), "vps-01", body, "s3cret"}
				tc.change(&r)
				w.Header().Set("X-Timestamp", r.ts)
				w.Header().Set("X-Signature", signResponse(r.ts, r.request, r.source, r.body, r.secret))
			}
			_, _ = w.Write([]byte(body))
		}))
		for _, required := range []bool{false, true} {
			want := tc.optional
			if required {
				want = tc.always
			}
			c := &Central{url: srv.URL, source: "vps-01", secret: "s3cret", requireSigned: required, client: srv.Client()}
			dl, err := c.Pull(context.Background())
			if (err == nil) != want {
				t.Errorf("%s, required=%v: err = %v, want accepted = %v", name, required, err, want)
			}
			if err == nil && len(dl.IPBlocklist) != 1 {
				t.Errorf("%s: denylist = %+v", name, dl)
			}
		}
		srv.Close()
	}
}

// The request signature, echoed back, is no response signature.
func TestPullRefusesEchoedSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Timestamp", r.Header.Get("X-Timestamp"))
		w.Header().Set("X-Signature", r.Header.Get("X-Signature"))
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := &Central{url: srv.URL, source: "vps-01", secret: "s3cret", client: srv.Client()}
	if _, err := c.Pull(context.Background()); err == nil {
		t.Error("accepted the request's own signature")
	}
}

func TestPullRefusesOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"bans":[]}`))
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxDenylist)) // valid JSON, if read truncated
	}))
	defer srv.Close()
	c := &Central{url: srv.URL, client: srv.Client()}
	if _, err := c.Pull(context.Background()); err == nil || !strings.Contains(err.Error(), "over 32 MB") {
		t.Errorf("err = %v", err)
	}
}

// A refused pull keeps what the firewall already has.
func TestBadSignatureKeepsLastList(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pulls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if pulls == 2 {
				cancel()
			}
			return
		}
		pulls++
		body, secret := `{"ip_blocklist":["192.0.2.0/24"]}`, "s3cret"
		if pulls == 2 {
			body, secret = `{"ip_blocklist":[]}`, "forged"
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		w.Header().Set("X-Timestamp", ts)
		w.Header().Set("X-Signature", signResponse(ts, r.Header.Get("X-Signature"), "vps-01", body, secret))
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	fw := fakeFirewall{}
	a := newAgent(&Config{Central: CentralConfig{PullInterval: Duration(time.Millisecond)}}, fw, newState())
	a.central = &Central{url: srv.URL, source: "vps-01", secret: "s3cret", client: srv.Client()}
	a.run(ctx)
	if _, ok := fw[mustTarget("192.0.2.0/24")]; !ok {
		t.Error("a forged response lifted the list")
	}
}

func TestRequireSignedResponseConfig(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.ToSlash(filepath.Join(dir, "secret"))
	f := filepath.Join(dir, "agent.yaml")
	yaml := "central: {url: 'https://central.example.com/bans', secret_file: '" + secret + "', require_signed_response: true}\nrules:\n  - {name: r, file: /x, patterns: ['<ip>'], threshold: 1, window: 1m, ban: [1h]}\n"
	for p, content := range map[string]string{secret: "s3cret", f: yaml} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if !newAgent(cfg, fakeFirewall{}, newState()).central.requireSigned {
		t.Error("central.require_signed_response did not reach the client")
	}
}
