package main

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type Agent struct {
	cfg     *Config
	fw      Firewall
	central *Central // nil: standalone, no reporting or pulling

	mu     sync.Mutex
	banned map[netip.Addr]time.Time // local bans -> expiry
}

func newAgent(cfg *Config, fw Firewall) *Agent {
	a := &Agent{cfg: cfg, fw: fw, banned: map[netip.Addr]time.Time{}}
	if cfg.Central.URL != "" {
		a.central = &Central{
			url:    cfg.Central.URL,
			source: cfg.Source,
			secret: cfg.secret,
			client: &http.Client{Timeout: time.Duration(cfg.Central.Timeout)},
		}
	}
	return a
}

func (a *Agent) run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, r := range a.cfg.rules {
		wg.Go(func() { a.watch(ctx, r) })
	}
	if a.central != nil {
		wg.Go(func() { a.pullLoop(ctx) })
	}
	wg.Wait()
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
			if b := r.Hit(ip, pattern, time.Now()); b != nil {
				a.handle(ctx, *b)
			}
		}
	}
}

func (a *Agent) handle(ctx context.Context, b Ban) {
	a.mu.Lock()
	for ip, until := range a.banned {
		if !until.After(b.At) {
			delete(a.banned, ip)
		}
	}
	if _, already := a.banned[b.IP]; already { // e.g. two rules tripping on the same IP
		a.mu.Unlock()
		return
	}
	a.banned[b.IP] = b.At.Add(b.Duration)
	a.mu.Unlock()

	if err := a.fw.Ban(hostPrefix(b.IP), b.Duration); err != nil {
		log.Printf("ban %s: %v", b.IP, err) // still reported: the other servers can block it
	}
	log.Printf("banned %s rule=%s hits=%d offense=%d for %s", b.IP, b.Reason, b.Hits, b.Offense, b.Duration)

	if a.central != nil {
		go func() {
			if err := a.central.Report(ctx, b); err != nil {
				log.Printf("report %s to central: %v", b.IP, err)
			}
		}()
	}
}

func (a *Agent) pullLoop(ctx context.Context) {
	applied := map[netip.Prefix]time.Time{} // pulled entries -> expiry (zero = static)
	for {
		if dl, err := a.central.Pull(ctx); err != nil {
			log.Printf("pull denylist: %v (keeping the last one)", err)
		} else {
			a.apply(dl, applied, time.Now())
		}
		if !sleep(ctx, time.Duration(a.cfg.Central.PullInterval)) {
			return
		}
	}
}

// apply brings the firewall in line with the pulled denylist: adds new or
// extended entries, lifts the ones the central app no longer lists (unless
// this agent banned them itself).
func (a *Agent) apply(dl *Denylist, applied map[netip.Prefix]time.Time, now time.Time) {
	want := map[netip.Prefix]time.Time{}
	for _, b := range dl.Bans {
		if p, err := parseTarget(b.IP); err == nil && b.ExpiresAt.After(now) {
			want[p] = b.ExpiresAt
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
}

func (a *Agent) bannedLocally(ip netip.Addr, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.banned[ip]
	return ok && until.After(now)
}

func hostPrefix(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, ip.BitLen())
}
