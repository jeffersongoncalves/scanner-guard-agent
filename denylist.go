package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"log"
	"maps"
	"net/netip"
	"os"
	"path"
	"slices"
	"strings"
	"time"
)

// DenylistConfig is a web server config file kept in line with the active
// bans, for servers behind a proxy or CDN: nftables only sees the proxy there,
// nginx and Apache can see the restored client IP.
type DenylistConfig struct {
	Format string `yaml:"format"`
	Path   string `yaml:"path"`
}

const (
	// Every write makes the web server reload, so an attack must not cause one per ban.
	denylistInterval = 10 * time.Second
	// How long a restart keeps the previous list while the first pull has not
	// succeeded: writing earlier would briefly lift every central ban.
	denylistGrace = 5 * time.Minute
)

type denied struct {
	prefix  netip.Prefix
	expires time.Time // zero = static
}

var denylistFormats = map[string]func([]denied) string{
	"nginx":  renderNginx,
	"apache": renderApache,
}

func validateDenylists(cfg *Config) error {
	// Every file is staged at path+".tmp" (writeAtomic), so that is taken too.
	state := path.Clean(cfg.StateFile)
	seen := map[string]bool{state: true, state + ".tmp": true}
	for _, d := range cfg.Denylists {
		if denylistFormats[d.Format] == nil {
			return fmt.Errorf("denylists: unknown format %q (nginx | apache)", d.Format)
		}
		if !path.IsAbs(d.Path) {
			return fmt.Errorf("denylists: path %q must be absolute", d.Path)
		}
		p := path.Clean(d.Path)
		if seen[p] || seen[p+".tmp"] {
			return fmt.Errorf("denylists: path %q is already in use", d.Path)
		}
		seen[p], seen[p+".tmp"] = true, true
	}
	return nil
}

func (a *Agent) denylistLoop(ctx context.Context) {
	failed := map[string]string{} // path -> last error, logged once
	for {
		for _, d := range a.cfg.Denylists {
			n, err := a.writeDenylist(d, time.Now())
			switch {
			case err == nil:
				delete(failed, d.Path)
				if n >= 0 {
					log.Printf("denylist %s: wrote %d entries", d.Path, n)
				}
			case failed[d.Path] != err.Error():
				failed[d.Path] = err.Error()
				log.Printf("denylist %s: %v (retrying)", d.Path, err)
			}
		}
		if !sleep(ctx, denylistInterval) {
			return
		}
	}
}

// writeDenylist rewrites d when its content changed and returns the number of
// entries written, -1 when there was nothing to do.
func (a *Agent) writeDenylist(d DenylistConfig, now time.Time) (int, error) {
	entries, ready := a.denied(now)
	if !ready {
		return -1, nil
	}
	content := []byte(denylistFormats[d.Format](entries))
	if old, err := os.ReadFile(d.Path); err == nil && bytes.Equal(old, content) {
		return -1, nil
	}
	if err := writeAtomic(d.Path, content, 0o644); err != nil {
		return -1, err
	}
	return len(entries), nil
}

// denied lists every active ban, local and pulled, static entries first. The
// longest ban of an IP wins. false: still waiting for the first pull.
func (a *Agent) denied(now time.Time) ([]denied, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.central != nil && a.pulled == nil && now.Sub(a.started) < denylistGrace {
		return nil, false
	}

	active := a.blockedLocked(now)
	out := make([]denied, 0, len(active))
	for p, exp := range active {
		out = append(out, denied{p, exp})
	}
	slices.SortFunc(out, func(x, y denied) int {
		if x.expires.IsZero() != y.expires.IsZero() {
			if x.expires.IsZero() {
				return -1
			}
			return 1
		}
		return cmp.Or(x.prefix.Addr().Compare(y.prefix.Addr()), cmp.Compare(x.prefix.Bits(), y.prefix.Bits()))
	})
	return out, true
}

// blockedLocked maps everything this server blocks now, local and pulled
// bans, to its expiry (zero = static). The longest ban of an IP wins.
func (a *Agent) blockedLocked(now time.Time) map[netip.Prefix]time.Time {
	active := map[netip.Prefix]time.Time{}
	for p, exp := range a.pulled {
		if exp.IsZero() || exp.After(now) {
			active[p] = exp
		}
	}
	for ip, until := range a.state.Banned {
		if !until.After(now) {
			continue
		}
		p := hostPrefix(ip)
		if exp, ok := active[p]; ok && (exp.IsZero() || exp.After(until)) {
			continue
		}
		active[p] = until
	}
	return active
}

// setPulled publishes the valid entries of the central denylist.
func (a *Agent) setPulled(applied map[netip.Prefix]time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pulled = maps.Clone(applied)
}

const denylistHeader = "# Managed by scanner-guard-agent, do not edit.\n"

// Prefixes come from parseTarget, so they are safe to splice into a config.
func renderNginx(entries []denied) string {
	var b strings.Builder
	b.WriteString(denylistHeader)
	for _, e := range entries {
		fmt.Fprintf(&b, "deny %s; # %s\n", nftElem(e.prefix), e.note())
	}
	return b.String()
}

// Apache has no trailing comments: the note goes on its own line.
func renderApache(entries []denied) string {
	var b strings.Builder
	b.WriteString(denylistHeader)
	b.WriteString("<RequireAll>\n\tRequire all granted\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "\t# %s\n\tRequire not ip %s\n", e.note(), nftElem(e.prefix))
	}
	b.WriteString("</RequireAll>\n")
	return b.String()
}

func (e denied) note() string {
	if e.expires.IsZero() {
		return "static"
	}
	return "expires " + e.expires.UTC().Format(time.RFC3339)
}
