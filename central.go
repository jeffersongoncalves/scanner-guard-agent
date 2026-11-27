package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Central speaks laravel-scanner-guard's http-driver protocol: signed ban
// POSTs and signed denylist GETs on the same URL.
type Central struct {
	url, source, secret string
	requireSigned       bool // refuse an unsigned denylist
	client              *http.Client
}

const (
	maxDenylist       = 32 << 20
	responseTolerance = 5 * time.Minute // same as the central app's for requests
)

// newCentralClient never leaves https, not even through a redirect (the
// default client follows https -> http).
func newCentralClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects") // the default limit, replaced by this func
			}
			return requireSecure(req.URL)
		},
	}
}

// requireSecure refuses plain http: the pulled denylist holds raw IPs, and only
// TLS keeps others on the path from reading it (or changing it, while unsigned
// ones are accepted). Loopback never leaves the host.
func requireSecure(u *url.URL) error {
	host := u.Hostname()
	ip, err := netip.ParseAddr(host)
	loopback := strings.EqualFold(host, "localhost") || err == nil && ip.Unmap().IsLoopback()
	if host != "" && (u.Scheme == "https" || u.Scheme == "http" && loopback) {
		return nil
	}
	return fmt.Errorf("%s must be https (http only for localhost)", u.Redacted())
}

type Denylist struct {
	Bans []struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"bans"`
	IPBlocklist []string `json:"ip_blocklist"`
	// nil: a central app without the feature, or an error body. An empty list
	// is a list.
	Ignore *[]string `json:"ignore"`
	// Threshold, window and ban steps per rule name. nil: a central app without
	// the feature (keep the last ones); empty: agent.yaml's for every rule.
	AgentRules *map[string]RuleSettings `json:"agent_rules"`
}

// sign matches ScannerGuard::sign(): hash_hmac('sha256', timestamp.body, secret).
func sign(timestamp, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + body))
	return hex.EncodeToString(mac.Sum(nil))
}

// signResponse matches ScannerGuard::signResponse(): bound to the request it
// answers, so an older list can't be replayed.
func signResponse(timestamp, requestSignature, source, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join([]string{"response", timestamp, requestSignature, source, body}, "\n")))
	return hex.EncodeToString(mac.Sum(nil))
}

// verify checks the signature of a denylist response. A missing one passes
// unless requireSigned (central apps older than signed responses), a wrong one
// never does.
func (c *Central) verify(h http.Header, requestSignature string, body []byte, now time.Time) error {
	ts, sig := h.Get("X-Timestamp"), h.Get("X-Signature")
	if sig == "" {
		if c.requireSigned {
			return errors.New("the response is not signed (central.require_signed_response)")
		}
		return nil
	}
	if !hmac.Equal([]byte(signResponse(ts, requestSignature, c.source, string(body), c.secret)), []byte(sig)) {
		return errors.New("the response has an invalid signature")
	}
	if sec, err := strconv.ParseInt(ts, 10, 64); err != nil || now.Sub(time.Unix(sec, 0)).Abs() > responseTolerance {
		return fmt.Errorf("the response timestamp %q is too far from this server's clock", ts)
	}
	return nil
}

func (c *Central) Report(ctx context.Context, b Ban) error {
	body, err := json.Marshal(map[string]any{
		"ip":     b.IP.String(),
		"reason": b.Reason,
		// The pattern, never the log line: the line holds the raw IP and the
		// central table must only ever store its hash.
		"matched_value": truncate(b.Pattern, 255),
		"hit_count":     b.Hits,
		"banned_at":     b.At.Format(time.RFC3339),
		"expires_at":    b.At.Add(b.Duration).Format(time.RFC3339),
		"offense":       b.Offense,
		"source":        c.source,
		// The lines that tripped the rule, with the IP taken out for the same
		// reason. A central app that doesn't know the field ignores it.
		"evidence": redact(b.Evidence, b.IP),
	})
	if err != nil {
		return err
	}

	for attempt := 1; ; attempt++ {
		retry, err := c.post(ctx, c.url, body)
		if err == nil || !retry || attempt == 3 {
			return err
		}
		if !sleep(ctx, time.Duration(attempt)*5*time.Second) {
			return ctx.Err()
		}
	}
}

type Heartbeat struct {
	Version    string    `json:"version"`
	Rules      []string  `json:"rules"`
	ActiveBans int       `json:"active_bans"`
	StartedAt  time.Time `json:"started_at"`
	// Matching lines per rule since the last heartbeat that got through
	// (ignored IPs left out, except on report rules).
	Matches map[string]int64 `json:"matches"`
}

// Event is one match of a report rule: something worth knowing, not a ban.
type Event struct {
	Rule    string
	Pattern string
	IP      netip.Addr
	Fields  map[string]string // the pattern's other named groups
	Line    string
	Ignored bool // the IP is on an ignore list
	At      time.Time
}

// errNotFound: a central app without the endpoint (older laravel-scanner-guard).
var errNotFound = errors.New("central answered 404 Not Found")

// Event sends e to <url>/events. One attempt: the same event is sent again
// once eventEvery has passed.
func (c *Central) Event(ctx context.Context, e Event) error {
	fields := e.Fields
	if fields == nil {
		fields = map[string]string{} // always a JSON object
	}
	body, err := json.Marshal(map[string]any{
		"source":  c.source,
		"rule":    e.Rule,
		"ip":      e.IP.String(),
		"pattern": truncate(e.Pattern, 255),
		"fields":  fields,
		// The line with the IP taken out, as the ban evidence: the IP has its own field.
		"line":    redact([]string{truncate(e.Line, maxEvidenceLine)}, e.IP)[0],
		"ignored": e.Ignored,
		"at":      e.At.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	_, err = c.post(ctx, strings.TrimRight(c.url, "/")+"/events", body)
	return err
}

// Heartbeat tells the central app this agent is alive, at <url>/heartbeat.
// One attempt: the next one is a pull_interval away anyway.
func (c *Central) Heartbeat(ctx context.Context, h Heartbeat) error {
	body, err := json.Marshal(map[string]any{
		"source":      c.source,
		"version":     h.Version,
		"rules":       h.Rules,
		"active_bans": h.ActiveBans,
		"started_at":  h.StartedAt.Format(time.RFC3339),
		"matches":     h.Matches,
	})
	if err != nil {
		return err
	}
	_, err = c.post(ctx, strings.TrimRight(c.url, "/")+"/heartbeat", body)
	return err
}

// post sends one signed attempt (fresh timestamp, so a retry is not a replay).
func (c *Central) post(ctx context.Context, url string, body []byte) (retry bool, err error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sign(ts, string(body), c.secret))

	resp, err := c.client.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode/100 == 2 {
		return false, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, errNotFound
	}
	// 403 bad secret/clock, 422 invalid payload: resending won't help.
	return resp.StatusCode >= 500, fmt.Errorf("central answered %s", resp.Status)
}

func (c *Central) Pull(ctx context.Context) (*Denylist, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Source", c.source)
	req.Header.Set("X-Timestamp", ts)
	sig := sign(ts, c.source, c.secret)
	req.Header.Set("X-Signature", sig)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("central answered %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDenylist+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDenylist {
		return nil, fmt.Errorf("denylist is over %d MB", maxDenylist>>20)
	}
	if err := c.verify(resp.Header, sig, body, time.Now()); err != nil {
		return nil, err
	}

	var dl Denylist
	if err := json.Unmarshal(body, &dl); err != nil {
		return nil, fmt.Errorf("decode denylist: %w", err)
	}
	return &dl, nil
}

// redact replaces ip in each line with <ip>, in the spellings a log writes it:
// as is, upper-case (IPv6) and fully expanded (IPv6). Never nil, so the field
// is always a JSON list.
// ponytail: only the banned IP is taken out; a rule whose lines hold other IPs would send them.
func redact(lines []string, ip netip.Addr) []string {
	forms := []string{ip.String(), strings.ToUpper(ip.String())}
	if ip.Is6() {
		forms = append(forms, ip.StringExpanded(), strings.ToUpper(ip.StringExpanded()))
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		for _, f := range forms {
			l = strings.ReplaceAll(l, f, "<ip>")
		}
		out = append(out, l)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
