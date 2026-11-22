package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Central speaks laravel-scanner-guard's http-driver protocol: signed ban
// POSTs and signed denylist GETs on the same URL.
type Central struct {
	url, source, secret string
	client              *http.Client
}

type Denylist struct {
	Bans []struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		ExpiresAt time.Time `json:"expires_at"`
	} `json:"bans"`
	IPBlocklist []string `json:"ip_blocklist"`
}

// sign matches ScannerGuard::sign(): hash_hmac('sha256', timestamp.body, secret).
func sign(timestamp, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + body))
	return hex.EncodeToString(mac.Sum(nil))
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
	})
	if err != nil {
		return err
	}

	for attempt := 1; ; attempt++ {
		retry, err := c.post(ctx, body)
		if err == nil || !retry || attempt == 3 {
			return err
		}
		if !sleep(ctx, time.Duration(attempt)*5*time.Second) {
			return ctx.Err()
		}
	}
}

// post sends one signed attempt (fresh timestamp, so a retry is not a replay).
func (c *Central) post(ctx context.Context, body []byte) (retry bool, err error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(string(body)))
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
	req.Header.Set("X-Signature", sign(ts, c.source, c.secret))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("central answered %s", resp.Status)
	}

	var dl Denylist
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&dl); err != nil {
		return nil, fmt.Errorf("decode denylist: %w", err)
	}
	return &dl, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
