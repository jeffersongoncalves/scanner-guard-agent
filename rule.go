package main

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Replaces <ip> in a pattern; the match is then validated with netip.
const ipGroup = `(?P<ip>[0-9A-Fa-f:.]{3,45})`

// Rule counts pattern matches per IP and trips once threshold matches land
// inside window. Owned by a single goroutine: no locking. Escalation (which
// step of ban applies) lives in the agent's persisted state.
type Rule struct {
	Name     string
	file     string
	journald []string
	patterns []*regexp.Regexp
	raw      []string
	local    limits                 // agent.yaml's
	cur      atomic.Pointer[limits] // in force: local, or the central app's (swapped by a pull)
	report   bool                   // never bans: each match is an event for the central app

	hits    map[netip.Addr][]hit
	matched atomic.Int64 // matches since the last heartbeat that got through
}

// limits are the knobs of a rule the central app may set (agent_rules).
type limits struct {
	threshold int
	window    time.Duration
	ban       []time.Duration
	central   bool // set by the central app, not agent.yaml
}

func (r *Rule) limits() *limits { return r.cur.Load() }

// RuleSettings is one entry of the central app's agent_rules, in seconds.
type RuleSettings struct {
	Threshold int     `json:"threshold"`
	Window    int64   `json:"window"`
	Ban       []int64 `json:"ban"`
}

// setCentral puts s in force, or agent.yaml's limits back when s is nil.
// false: s is invalid, agent.yaml's apply.
func (r *Rule) setCentral(s *RuleSettings) bool {
	if s == nil {
		r.cur.Store(&r.local)
		return true
	}
	l := &limits{threshold: s.Threshold, window: time.Duration(s.Window) * time.Second, central: true}
	for _, d := range s.Ban {
		l.ban = append(l.ban, time.Duration(d)*time.Second)
	}
	if l.threshold < 1 || l.window <= 0 || len(l.ban) == 0 || slices.ContainsFunc(l.ban, func(d time.Duration) bool { return d <= 0 }) {
		r.cur.Store(&r.local)
		return false
	}
	r.cur.Store(l)
	return true
}

func (l *limits) String() string {
	steps := make([]string, len(l.ban))
	for i, d := range l.ban {
		steps[i] = shortDur(d)
	}
	return fmt.Sprintf("%d in %s, ban %s", l.threshold, shortDur(l.window), strings.Join(steps, "/"))
}

// hit is one matching line, kept until the threshold trips so the ban can show
// what led to it.
type hit struct {
	at   time.Time
	line string
}

// Evidence limits: at most threshold-1 lines wait per IP, and a ban sends the
// last maxEvidence of them, each cut to maxEvidenceLine bytes.
const (
	maxEvidence     = 20
	maxEvidenceLine = 512
)

type Ban struct {
	IP       netip.Addr
	Reason   string
	Pattern  string
	Hits     int
	Offense  int
	Duration time.Duration
	At       time.Time
	Evidence []string // the lines that tripped the rule, oldest first
}

func newRule(rc RuleConfig) (*Rule, error) {
	switch {
	case rc.Name == "" || len(rc.Name) > 30:
		return nil, errors.New("name is required, at most 30 characters (the central app's limit)")
	case (rc.File == "") == (len(rc.Journald) == 0):
		return nil, errors.New("set exactly one of file or journald")
	case len(rc.Patterns) == 0:
		return nil, errors.New("no patterns")
	case rc.Report && (rc.Threshold != 0 || rc.Window != 0 || len(rc.Ban) != 0):
		return nil, errors.New("a report rule never bans: drop threshold, window and ban")
	case rc.Report:
	case rc.Threshold < 1:
		return nil, errors.New("threshold must be at least 1")
	case rc.Window <= 0:
		return nil, errors.New("window must be positive")
	case len(rc.Ban) == 0:
		return nil, errors.New("ban needs at least one duration")
	}

	r := &Rule{
		Name:     rc.Name,
		file:     rc.File,
		journald: rc.Journald,
		raw:      rc.Patterns,
		local:    limits{threshold: rc.Threshold, window: time.Duration(rc.Window)},
		report:   rc.Report,
		hits:     map[netip.Addr][]hit{},
	}
	for _, d := range rc.Ban {
		if d <= 0 {
			return nil, errors.New("ban durations must be positive")
		}
		r.local.ban = append(r.local.ban, time.Duration(d))
	}
	r.cur.Store(&r.local)
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
	ip, pattern, _, ok := r.matchFields(line)
	return ip, pattern, ok
}

// Most a field of an event carries.
const maxFieldLen = 255

// matchFields is Match plus the other named groups of the pattern, (?P<user>\S+)
// say, as the fields of an event. Empty groups are left out.
func (r *Rule) matchFields(line string) (netip.Addr, string, map[string]string, bool) {
	for i, re := range r.patterns {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ip, err := netip.ParseAddr(m[re.SubexpIndex("ip")])
		if err != nil {
			continue
		}
		fields := map[string]string{}
		for j, name := range re.SubexpNames() {
			if name != "" && name != "ip" && m[j] != "" {
				fields[name] = truncate(m[j], maxFieldLen)
			}
		}
		return ip.Unmap().WithZone(""), r.raw[i], fields, true
	}
	return netip.Addr{}, "", nil, false
}

// Hit records one matching line; once the threshold is reached it returns the
// number of hits inside the window, the last lines (evidence) and true, and
// starts counting from zero again.
func (r *Rule) Hit(ip netip.Addr, now time.Time, line string) (int, []string, bool) {
	l := r.limits()
	cutoff := now.Add(-l.window)
	hits := r.hits[ip][:0]
	for _, h := range r.hits[ip] {
		if h.at.After(cutoff) {
			hits = append(hits, h)
		}
	}
	hits = append(hits, hit{now, truncate(line, maxEvidenceLine)})

	if len(hits) < l.threshold {
		r.hits[ip] = hits
		return 0, nil, false
	}

	delete(r.hits, ip)
	lines := make([]string, 0, min(len(hits), maxEvidence))
	for _, h := range hits[max(0, len(hits)-maxEvidence):] {
		lines = append(lines, h.line)
	}
	return len(hits), lines, true
}

// Prune drops counters with no hit inside the window, so IPs that never
// reach the threshold don't pile up.
func (r *Rule) Prune(now time.Time) {
	cutoff := now.Add(-r.limits().window)
	for ip, hits := range r.hits {
		if !hits[len(hits)-1].at.After(cutoff) {
			delete(r.hits, ip)
		}
	}
}
