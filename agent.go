package main

import (
	"context"
	"log"
	"net/netip"
	"sync"
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

	reports sync.WaitGroup // in-flight central reports; one-shot commands wait on it
}

func newAgent(cfg *Config, fw Firewall, st *state) *Agent {
	a := &Agent{cfg: cfg, fw: fw, state: st, statePath: cfg.StateFile, started: time.Now()}
	if cfg.Central.URL != "" {
		a.central = &Central{
			url:    cfg.Central.URL,
			source: cfg.Source,
			secret: cfg.secret,
			client: newCentralClient(time.Duration(cfg.Central.Timeout)),
		}
	}
	return a
}

func (a *Agent) run(ctx context.Context) {
	a.restore(time.Now())

	var wg sync.WaitGroup
	for _, r := range a.cfg.rules {
		wg.Go(func() { a.watch(ctx, r) })
	}
	if a.central != nil {
		wg.Go(func() { a.centralLoop(ctx) })
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
	for ip, until := range a.state.Banned {
		if a.cfg.ignored(hostPrefix(ip)) {
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
			ip, pattern, ok := r.Match(line)
			if !ok || a.cfg.ignored(hostPrefix(ip)) {
				continue
			}
			now := time.Now()
			if hits, trip := r.Hit(ip, now); trip {
				if b, ok := a.decide(r, ip, pattern, hits, now); ok {
					_ = a.enforce(ctx, b) // logged; the state already lets it retry
				}
			}
		}
	}
}

// decide picks the escalation step and records the ban in the persisted
// state. false: the IP is already banned (e.g. two rules tripping on it).
func (a *Agent) decide(r *Rule, ip netip.Addr, pattern string, hits int, now time.Time) (Ban, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	lookback := time.Duration(a.cfg.EscalationLookback)
	a.state.prune(now, lookback)
	if _, already := a.state.Banned[ip]; already {
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

	b := Ban{
		IP:       ip,
		Reason:   r.Name,
		Pattern:  pattern,
		Hits:     hits,
		Offense:  o.N,
		Duration: r.ban[min(o.N, len(r.ban))-1], // the last step repeats
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

// centralLoop pulls the denylist and sends a heartbeat every pull_interval.
func (a *Agent) centralLoop(ctx context.Context) {
	applied := map[netip.Prefix]time.Time{} // pulled entries -> expiry (zero = static)
	for {
		if dl, err := a.central.Pull(ctx); err != nil {
			log.Printf("pull denylist: %v (keeping the last one)", err)
		} else {
			a.setPulled(a.apply(dl, applied, time.Now()))
		}
		if err := a.central.Heartbeat(ctx, a.heartbeat()); err != nil {
			log.Printf("heartbeat: %v", err)
		}
		if !sleep(ctx, time.Duration(a.cfg.Central.PullInterval)) {
			return
		}
	}
}

func (a *Agent) heartbeat() Heartbeat {
	rules := make([]string, 0, len(a.cfg.rules))
	for _, r := range a.cfg.rules {
		rules = append(rules, r.Name)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	active := 0
	for _, until := range a.state.Banned {
		if until.After(now) {
			active++
		}
	}
	return Heartbeat{Version: version, Rules: rules, ActiveBans: active, StartedAt: a.started}
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
		if a.cfg.ignored(p) {
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
