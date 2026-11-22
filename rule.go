package main

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Replaces <ip> in a pattern; the match is then validated with netip.
const ipGroup = `(?P<ip>[0-9A-Fa-f:.]{3,45})`

// Rule counts pattern matches per IP and trips once threshold matches land
// inside window. Owned by a single goroutine: no locking. Escalation (which
// step of ban applies) lives in the agent's persisted state.
type Rule struct {
	Name      string
	file      string
	journald  []string
	patterns  []*regexp.Regexp
	raw       []string
	threshold int
	window    time.Duration
	ban       []time.Duration

	hits map[netip.Addr][]time.Time
}

type Ban struct {
	IP       netip.Addr
	Reason   string
	Pattern  string
	Hits     int
	Offense  int
	Duration time.Duration
	At       time.Time
}

func newRule(rc RuleConfig) (*Rule, error) {
	switch {
	case rc.Name == "" || len(rc.Name) > 30:
		return nil, errors.New("name is required, at most 30 characters (the central app's limit)")
	case (rc.File == "") == (len(rc.Journald) == 0):
		return nil, errors.New("set exactly one of file or journald")
	case len(rc.Patterns) == 0:
		return nil, errors.New("no patterns")
	case rc.Threshold < 1:
		return nil, errors.New("threshold must be at least 1")
	case rc.Window <= 0:
		return nil, errors.New("window must be positive")
	case len(rc.Ban) == 0:
		return nil, errors.New("ban needs at least one duration")
	}

	r := &Rule{
		Name:      rc.Name,
		file:      rc.File,
		journald:  rc.Journald,
		raw:       rc.Patterns,
		threshold: rc.Threshold,
		window:    time.Duration(rc.Window),
		hits:      map[netip.Addr][]time.Time{},
	}
	for _, d := range rc.Ban {
		if d <= 0 {
			return nil, errors.New("ban durations must be positive")
		}
		r.ban = append(r.ban, time.Duration(d))
	}
	for _, p := range rc.Patterns {
		if strings.Count(p, "<ip>") != 1 {
			return nil, errors.New("pattern must contain <ip> exactly once: " + p)
		}
		re, err := regexp.Compile(strings.Replace(p, "<ip>", ipGroup, 1))
		if err != nil {
			return nil, err
		}
		r.patterns = append(r.patterns, re)
	}
	return r, nil
}

// Match returns the IP and the pattern (as configured) a line matched.
func (r *Rule) Match(line string) (netip.Addr, string, bool) {
	for i, re := range r.patterns {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip, err := netip.ParseAddr(m[re.SubexpIndex("ip")])
		if err != nil {
			continue
		}
		return ip.Unmap().WithZone(""), r.raw[i], true
	}
	return netip.Addr{}, "", false
}

// Hit records one match; once the threshold is reached it returns the number
// of hits inside the window and true, and starts counting from zero again.
func (r *Rule) Hit(ip netip.Addr, now time.Time) (int, bool) {
	cutoff := now.Add(-r.window)
	hits := r.hits[ip][:0]
	for _, t := range r.hits[ip] {
		if t.After(cutoff) {
			hits = append(hits, t)
		}
	}
	hits = append(hits, now)

	if len(hits) < r.threshold {
		r.hits[ip] = hits
		return 0, false
	}

	delete(r.hits, ip)
	return len(hits), true
}

// Prune drops counters with no hit inside the window, so IPs that never
// reach the threshold don't pile up.
func (r *Rule) Prune(now time.Time) {
	cutoff := now.Add(-r.window)
	for ip, hits := range r.hits {
		if !hits[len(hits)-1].After(cutoff) {
			delete(r.hits, ip)
		}
	}
}
