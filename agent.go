package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Agent struct {
	cfg     *Config
	fw      Firewall
	central *Central // nil: standalone, no reporting or pulling
	started time.Time

	mu        sync.Mutex
	state     *state
	statePath string                     // "" = don't persist (tests)
	pulled    map[netip.Prefix]time.Time // valid entries of the last pull (zero = static), nil before the first pull
	events    map[string]time.Time       // event key -> when it was last sent (see eventEvery)

	eventsOff atomic.Bool    // the central app has no /events: stop sending
	reports   sync.WaitGroup // in-flight central reports; one-shot commands wait on it

	// Optional nginx rules from the central app (nginxrules.go).
	nginxRules    *string   // the last set handled, nil before the first
	nginxFailed   time.Time // when that set last failed, zero if it worked
	nginxDir      string
	nginxOptional string
	nginx         nginxOps

	// Diagnoses the central app asked for (remote.go).
	diagnoses map[int64]bool                                         // running or done, by id
	diagnose  sync.Mutex                                             // one at a time
	exec      func(time.Duration, string, ...string) (string, error) // runs the diagnosis commands
}

// An event (same rule, IP and fields) is sent at most once per eventEvery: a
// login repeated every minute is one event a day, not 1440.
const (
	eventEvery = 24 * time.Hour
	maxEvents  = 10000 // remembered event keys
)

func newAgent(cfg *Config, fw Firewall, st *state) *Agent {
	a := &Agent{
		cfg: cfg, fw: fw, state: st, statePath: cfg.StateFile, started: time.Now(), events: map[string]time.Time{},
		nginxDir: defaultNginxDir, nginxOptional: nginxOptionalDir, nginx: systemNginx, diagnoses: map[int64]bool{}, exec: execOut,
	}
	if cfg.Central.URL != "" {
		a.central = &Central{
			url:    cfg.Central.URL,
			source: cfg.Source,
			secret: cfg.secret,

			requireSigned: cfg.Central.RequireSigned,
			client:        newCentralClient(time.Duration(cfg.Central.Timeout)),
		}
	}
	return a
}

func (a *Agent) run(ctx context.Context) {
	a.restore(time.Now())

	// Before watching anything: on the first start the central ignore list must
	// be in place before the first ban.
	var first *Denylist
	if a.central != nil {
		first = a.pull(ctx)
	}

	var wg sync.WaitGroup
	for _, r := range a.cfg.rules {
		wg.Go(func() { a.watch(ctx, r) })
	}
	if a.central != nil {
		wg.Go(func() { a.centralLoop(ctx, first) })
	}
	if len(a.cfg.Denylists) > 0 {
		if a.cfg.Firewall == "none" {
			log.Print("dry-run: denylists are not written (an existing file keeps blocking)")
		} else {
			wg.Go(func() { a.denylistLoop(ctx) })
		}
	}
	wg.Wait()
}

// restore re-applies the local bans still running before the restart. A ban
// that is now ignored, or that the firewall rejects, leaves the state: kept,
// it would make decide() skip that IP as "already banned" while nothing
// blocks it. Its escalation step stays, so the next ban picks up from there.
func (a *Agent) restore(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.prune(now, time.Duration(a.cfg.EscalationLookback))
	applyRuleSettings(a.cfg.rules, a.state.Rules, log.Printf) // the last ones the central app sent
	for ip, until := range a.state.Banned {
		if a.ignoredLocked(hostPrefix(ip)) {
			delete(a.state.Banned, ip)
			continue
		}
		if err := a.fw.Ban(hostPrefix(ip), until.Sub(now)); err != nil {
			log.Printf("restore ban %s: %v", ip, err)
			delete(a.state.Banned, ip)
		}
	}
	if n := len(a.state.Banned); n > 0 {
		log.Printf("restored %d local bans", n)
	}
}

func (a *Agent) watch(ctx context.Context, r *Rule) {
	lines := make(chan string, 256)
	if r.file != "" {
		go tailFile(ctx, r.file, lines)
	} else {
		go tailJournal(ctx, r.journald, lines)
	}

	prune := time.NewTicker(time.Minute)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-prune.C:
			r.Prune(now)
		case line := <-lines:
			ip, pattern, fields, ok := r.matchFields(line)
			if !ok {
				continue
			}
			now := time.Now()
			if r.report {
				a.event(ctx, Event{Rule: r.Name, Pattern: pattern, IP: ip, Fields: fields, Line: line, At: now})
				continue
			}
			if a.ignored(hostPrefix(ip)) {
				continue
			}
			r.matched.Add(1)
			if hits, evidence, trip := r.Hit(ip, now, line); trip {
				if b, ok := a.decide(r, ip, pattern, hits, now); ok {
					b.Evidence = evidence
					_ = a.enforce(ctx, b) // logged; the state already lets it retry
				}
			}
		}
	}
}

// decide picks the escalation step and records the ban in the persisted
// state. false: the IP is already banned (e.g. two rules tripping on it), or a
// pull has just put it on the ignore list.
func (a *Agent) decide(r *Rule, ip netip.Addr, pattern string, hits int, now time.Time) (Ban, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	lookback := time.Duration(a.cfg.EscalationLookback)
	a.state.prune(now, lookback)
	if _, already := a.state.Banned[ip]; already || a.ignoredLocked(hostPrefix(ip)) {
		return Ban{}, false
	}

	offs := a.state.Offenses[r.Name]
	if offs == nil {
		offs = map[netip.Addr]offense{}
		a.state.Offenses[r.Name] = offs
	}
	o := offs[ip] // pruned above if older than lookback, so this restarts at step one
	o.N++
	o.Last = now
	offs[ip] = o

	steps := r.limits().ban
	b := Ban{
		IP:       ip,
		Reason:   r.Name,
		Pattern:  pattern,
		Hits:     hits,
		Offense:  o.N,
		Duration: steps[min(o.N, len(steps))-1], // the last step repeats
		At:       now,
	}
	a.state.Banned[ip] = now.Add(b.Duration)

	if a.statePath != "" {
		if err := a.state.save(a.statePath); err != nil {
			log.Printf("save state: %v", err) // the ban still applies, only persistence is lost
		}
	}
	return b, true
}

// enforce blocks b and reports it. A failed block leaves state.Banned (the
// escalation step stays), so the IP can be banned again instead of being
// skipped as "already banned" while nothing blocks it.
func (a *Agent) enforce(ctx context.Context, b Ban) error {
	err := a.fw.Ban(hostPrefix(b.IP), b.Duration)
	if err != nil {
		log.Printf("ban %s: %v", b.IP, err) // still reported: the other servers can block it
		a.mu.Lock()
		delete(a.state.Banned, b.IP)
		if a.statePath != "" {
			if serr := a.state.save(a.statePath); serr != nil {
				log.Printf("save state: %v", serr)
			}
		}
		a.mu.Unlock()
	} else {
		log.Printf("banned %s rule=%s hits=%d offense=%d for %s", b.IP, b.Reason, b.Hits, b.Offense, b.Duration)
	}

	if a.central != nil {
		a.reports.Go(func() {
			if err := a.central.Report(ctx, b); err != nil {
				log.Printf("report %s to central: %v", b.IP, err)
			}
		})
	}
	return err
}

// event logs and sends a report rule's match, unless the same one (rule, IP,
// fields) went out less than eventEvery ago. Ignored IPs are sent too, marked:
// a new key logging in from the office is still news.
func (a *Agent) event(ctx context.Context, e Event) {
	a.mu.Lock()
	for _, r := range a.cfg.rules {
		if r.Name == e.Rule {
			r.matched.Add(1)
		}
	}
	key := eventKey(e)
	if last, ok := a.events[key]; ok && e.At.Sub(last) < eventEvery {
		a.mu.Unlock()
		return
	}
	if len(a.events) >= maxEvents {
		for k, at := range a.events {
			if e.At.Sub(at) >= eventEvery {
				delete(a.events, k)
			}
		}
		if len(a.events) >= maxEvents {
			// ponytail: a flood of distinct events forgets them all; an LRU if that ever matters.
			clear(a.events)
		}
	}
	a.events[key] = e.At
	e.Ignored = a.ignoredLocked(hostPrefix(e.IP))
	a.mu.Unlock()

	log.Printf("event rule=%s ip=%s%s", e.Rule, e.IP, fieldsText(e.Fields))
	if a.central == nil || a.eventsOff.Load() {
		return
	}
	a.reports.Go(func() {
		err := a.central.Event(ctx, e)
		switch {
		case errors.Is(err, errNotFound):
			if a.eventsOff.CompareAndSwap(false, true) {
				log.Print("the central app has no /events (update laravel-scanner-guard): events stay in this log only")
			}
		case err != nil:
			log.Printf("event %s to central: %v", e.Rule, err)
		}
	})
}

// eventKey identifies an event for deduplication: rule, IP and fields.
func eventKey(e Event) string {
	return e.Rule + "\x00" + e.IP.String() + fieldsText(e.Fields)
}

// fieldsText prints fields sorted by name: " key=SHA256:abc user=deploy".
func fieldsText(f map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(f)) {
		fmt.Fprintf(&b, " %s=%s", k, f[k])
	}
	return b.String()
}

// pull fetches the denylist and puts its ignore list in place. nil: it failed.
func (a *Agent) pull(ctx context.Context) *Denylist {
	dl, err := a.central.Pull(ctx)
	if err != nil {
		log.Printf("pull denylist: %v (keeping the last one)", err)
		return nil
	}
	if dl.Ignore != nil {
		a.setIgnore(*dl.Ignore)
	}
	if dl.AgentRules != nil {
		a.setRuleSettings(*dl.AgentRules)
	}
	if dl.NginxRules != nil {
		a.setNginxRules(*dl.NginxRules, time.Now())
	}
	for _, r := range dl.Diagnostics {
		a.startDiagnosis(ctx, r)
	}
	return dl
}

// setRuleSettings puts the central app's rule settings in force, kept in the
// state so a restart with the central app down still honors them.
func (a *Agent) setRuleSettings(m map[string]RuleSettings) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maps.EqualFunc(m, a.state.Rules, func(x, y RuleSettings) bool {
		return x.Threshold == y.Threshold && x.Window == y.Window && slices.Equal(x.Ban, y.Ban)
	}) {
		return
	}
	a.state.Rules = m
	applyRuleSettings(a.cfg.rules, m, log.Printf)
	if a.statePath != "" {
		if err := a.state.save(a.statePath); err != nil {
			log.Printf("save state: %v", err)
		}
	}
}

// applyRuleSettings puts m in force on the rules of the same name, and
// agent.yaml's limits back on the others, logging every change. Names this
// agent has no rule for are skipped.
func applyRuleSettings(rules []*Rule, m map[string]RuleSettings, logf func(string, ...any)) {
	for _, r := range rules {
		if r.report {
			continue // nothing to set: it never bans
		}
		before := r.limits()
		s, ok := m[r.Name]
		switch {
		case !ok:
			r.setCentral(nil)
		case !r.setCentral(&s):
			logf("rule %s: invalid settings from the central app %+v, using agent.yaml's", r.Name, s)
			continue
		}
		if after := r.limits(); after.String() != before.String() || after.central != before.central {
			from := "agent.yaml"
			if after.central {
				from = "the central app"
			}
			logf("rule %s: %s (from %s)", r.Name, after, from)
		}
	}
}

// centralLoop applies the denylist and sends a heartbeat every pull_interval,
// starting with the one already pulled.
func (a *Agent) centralLoop(ctx context.Context, dl *Denylist) {
	applied := map[netip.Prefix]time.Time{} // pulled entries -> expiry (zero = static)
	for {
		if dl != nil {
			a.setPulled(a.apply(dl, applied, time.Now()))
		}
		hb := a.heartbeat()
		if err := a.central.Heartbeat(ctx, hb); err != nil {
			a.unsend(hb) // its matches go in the next one
			log.Printf("heartbeat: %v", err)
		}
		if !sleep(ctx, time.Duration(a.cfg.Central.PullInterval)) {
			return
		}
		dl = a.pull(ctx)
	}
}

// setIgnore replaces the central ignore list, kept in the state so a restart
// with the central app down still honors it, and lifts the local bans it
// covers. The config's ignore always applies on top.
func (a *Agent) setIgnore(list []string) {
	var ignore []netip.Prefix
	var skipped []string
	for _, s := range list {
		p, err := parseTarget(s)
		if err != nil || tooBroad(p) {
			skipped = append(skipped, s)
			continue
		}
		ignore = append(ignore, p)
	}
	slices.SortFunc(ignore, func(x, y netip.Prefix) int {
		return cmp.Or(x.Addr().Compare(y.Addr()), cmp.Compare(x.Bits(), y.Bits()))
	})
	ignore = slices.Compact(ignore)

	a.mu.Lock()
	if slices.Equal(ignore, a.state.Ignore) {
		a.mu.Unlock()
		return
	}
	a.state.Ignore = ignore
	var lifted []netip.Addr
	for ip := range a.state.Banned {
		if a.ignoredLocked(hostPrefix(ip)) {
			delete(a.state.Banned, ip)
			lifted = append(lifted, ip)
		}
	}
	if a.statePath != "" {
		if err := a.state.save(a.statePath); err != nil {
			log.Printf("save state: %v", err)
		}
	}
	a.mu.Unlock()

	log.Printf("ignore list from central: %d entries", len(ignore))
	for _, s := range skipped {
		log.Printf("ignore list from central: skipping %q (invalid or too broad)", s)
	}
	for _, ip := range lifted {
		if err := a.fw.Unban(hostPrefix(ip)); err != nil {
			log.Printf("unban %s: %v", ip, err)
			continue
		}
		log.Printf("unbanned %s: now on the central ignore list", ip)
	}
}

// ignored reports whether p is never to be banned: the config's list plus the
// central app's.
func (a *Agent) ignored(p netip.Prefix) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ignoredLocked(p)
}

func (a *Agent) ignoredLocked(p netip.Prefix) bool {
	return a.cfg.ignored(p) || slices.ContainsFunc(a.state.Ignore, p.Overlaps)
}

// heartbeat takes the match counters (zeroed: unsend puts them back if the
// heartbeat doesn't get through).
func (a *Agent) heartbeat() Heartbeat {
	rules := make([]string, 0, len(a.cfg.rules))
	matches := make(map[string]int64, len(a.cfg.rules))
	for _, r := range a.cfg.rules {
		rules = append(rules, r.Name)
		matches[r.Name] = r.matched.Swap(0)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Everything the firewall blocks: this server's bans plus the pulled ones.
	return Heartbeat{Version: version, Rules: rules, ActiveBans: len(a.blockedLocked(time.Now())), StartedAt: a.started, Matches: matches}
}

func (a *Agent) unsend(h Heartbeat) {
	for _, r := range a.cfg.rules {
		r.matched.Add(h.Matches[r.Name])
	}
}

// apply brings the firewall in line with the pulled denylist: adds new or
// extended entries, lifts the ones the central app no longer lists (unless
// this agent banned them itself). It returns every valid, non-ignored entry,
// the ones the firewall rejected included; applied only tracks its successes.
func (a *Agent) apply(dl *Denylist, applied map[netip.Prefix]time.Time, now time.Time) map[netip.Prefix]time.Time {
	want := map[netip.Prefix]time.Time{}
	for _, b := range dl.Bans {
		if p, err := parseTarget(b.IP); err == nil && b.ExpiresAt.After(now) {
			if b.ExpiresAt.After(want[p]) { // two spellings of one target: the longest ban wins
				want[p] = b.ExpiresAt
			}
		} else if err != nil {
			log.Printf("pull: skipping invalid ip %q", b.IP)
		}
	}
	for _, s := range dl.IPBlocklist {
		if p, err := parseTarget(s); err == nil {
			want[p] = time.Time{}
		} else {
			log.Printf("pull: skipping invalid ip_blocklist entry %q", s)
		}
	}

	for p, exp := range want {
		if a.ignored(p) {
			delete(want, p)
			continue
		}
		if old, ok := applied[p]; ok && old.Equal(exp) {
			continue
		}
		var d time.Duration
		if !exp.IsZero() {
			d = exp.Sub(now)
		}
		if err := a.fw.Ban(p, d); err != nil {
			log.Printf("pull: block %s: %v", p, err)
			continue
		}
		applied[p] = exp
	}

	for p := range applied {
		if _, ok := want[p]; ok {
			continue
		}
		delete(applied, p)
		if p.IsSingleIP() && a.bannedLocally(p.Addr(), now) {
			continue
		}
		if err := a.fw.Unban(p); err != nil {
			log.Printf("pull: unblock %s: %v", p, err)
		}
	}
	return want
}

func (a *Agent) bannedLocally(ip netip.Addr, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.state.Banned[ip]
	return ok && until.After(now)
}

func hostPrefix(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, ip.BitLen())
}
