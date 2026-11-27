package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// state survives restarts: escalation steps per rule/IP, and the local bans
// still running (the nftables table is recreated empty on every start).
type state struct {
	Offenses map[string]map[netip.Addr]offense `json:"offenses"`         // rule -> IP
	Banned   map[netip.Addr]time.Time          `json:"banned"`           // IP -> expiry
	Ignore   []netip.Prefix                    `json:"ignore,omitempty"` // the central app's, on top of the config's
	Rules    map[string]RuleSettings           `json:"rules,omitempty"`  // the central app's agent_rules
	Nginx    *nginxApplied                     `json:"nginx,omitempty"`  // the last optional nginx rules handled, for status
}

type nginxApplied struct {
	Rules []string  `json:"rules"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

type offense struct {
	N    int       `json:"n"`
	Last time.Time `json:"last"`
}

func newState() *state {
	return &state{Offenses: map[string]map[netip.Addr]offense{}, Banned: map[netip.Addr]time.Time{}}
}

// loadState reads path; a missing file is an empty state.
func loadState(path string) (*state, error) {
	s := newState()
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return newState(), err
	}
	if s.Offenses == nil {
		s.Offenses = map[string]map[netip.Addr]offense{}
	}
	if s.Banned == nil {
		s.Banned = map[netip.Addr]time.Time{}
	}
	return s, nil
}

// save writes atomically (temp file + rename), so a crash mid-write never
// leaves a truncated file behind.
func (s *state) save(path string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(path, raw, 0o600)
}

func writeAtomic(path string, raw []byte, perm fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// prune drops expired bans and offenses older than lookback, so the file
// stays bounded.
func (s *state) prune(now time.Time, lookback time.Duration) {
	for ip, until := range s.Banned {
		if !until.After(now) {
			delete(s.Banned, ip)
		}
	}
	for rule, ips := range s.Offenses {
		for ip, o := range ips {
			if now.Sub(o.Last) > lookback {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(s.Offenses, rule)
		}
	}
}
