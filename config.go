package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Source   string        `yaml:"source"`
	Central  CentralConfig `yaml:"central"`
	Firewall string        `yaml:"firewall"`
	Ignore   []string      `yaml:"ignore"`
	Rules    []RuleConfig  `yaml:"rules"`

	Denylists []DenylistConfig `yaml:"denylists"`

	StateFile          string   `yaml:"state_file"`
	EscalationLookback Duration `yaml:"escalation_lookback"`

	rules  []*Rule
	ignore []netip.Prefix
	secret string
}

type CentralConfig struct {
	URL          string   `yaml:"url"`
	SecretFile   string   `yaml:"secret_file"`
	PullInterval Duration `yaml:"pull_interval"`
	Timeout      Duration `yaml:"timeout"`
}

type RuleConfig struct {
	Name      string     `yaml:"name"`
	File      string     `yaml:"file"`
	Journald  []string   `yaml:"journald"`
	Patterns  []string   `yaml:"patterns"`
	Threshold int        `yaml:"threshold"`
	Window    Duration   `yaml:"window"`
	Ban       []Duration `yaml:"ban"`
}

// Duration accepts Go durations plus a "d" (days) suffix: 90s, 10m, 1d.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := parseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Never banned, whatever the config says.
var alwaysIgnore = []string{"127.0.0.0/8", "::1/128"}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a typo'd key is an error, not a silently ignored rule
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if cfg.Source == "" {
		cfg.Source, _ = os.Hostname()
	}
	if cfg.Firewall == "" {
		cfg.Firewall = "nftables"
	}
	if cfg.Central.PullInterval == 0 {
		cfg.Central.PullInterval = Duration(time.Minute)
	}
	if cfg.Central.Timeout == 0 {
		cfg.Central.Timeout = Duration(5 * time.Second)
	}
	if cfg.StateFile == "" {
		cfg.StateFile = "/var/lib/scanner-guard/state.json"
	}
	if cfg.EscalationLookback == 0 {
		cfg.EscalationLookback = Duration(365 * 24 * time.Hour)
	}

	for _, s := range append(alwaysIgnore, cfg.Ignore...) {
		p, err := parseTarget(s)
		if err != nil {
			return nil, fmt.Errorf("ignore %q: %w", s, err)
		}
		cfg.ignore = append(cfg.ignore, p)
	}

	if cfg.Central.URL != "" {
		u, err := url.Parse(cfg.Central.URL)
		if err == nil {
			err = requireSecure(u)
		}
		if err != nil {
			return nil, fmt.Errorf("central.url: %w", err)
		}
		secret, err := os.ReadFile(cfg.Central.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("central.secret_file: %w", err)
		}
		if fi, err := os.Stat(cfg.Central.SecretFile); err == nil && fi.Mode().Perm()&0o077 != 0 {
			log.Printf("warning: %s is readable by group/others, chmod 600 it", cfg.Central.SecretFile)
		}
		cfg.secret = strings.TrimSpace(string(secret))
		if cfg.secret == "" {
			return nil, errors.New("central.secret_file is empty")
		}
	}

	if err := validateDenylists(cfg); err != nil {
		return nil, err
	}

	if len(cfg.Rules) == 0 {
		return nil, errors.New("no rules configured")
	}
	seen := map[string]bool{}
	for _, rc := range cfg.Rules {
		if seen[rc.Name] {
			return nil, fmt.Errorf("duplicate rule name %q", rc.Name)
		}
		seen[rc.Name] = true

		r, err := newRule(rc)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rc.Name, err)
		}
		cfg.rules = append(cfg.rules, r)
	}

	return cfg, nil
}

// ignored reports whether p overlaps any ignored address or range.
func (c *Config) ignored(p netip.Prefix) bool {
	for _, ig := range c.ignore {
		if ig.Overlaps(p) {
			return true
		}
	}
	return false
}

// parseTarget parses an IP or CIDR into a prefix (a single IP is a /32 or /128).
// Everything handed to the firewall goes through here, pulled entries included.
func parseTarget(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func mustTarget(s string) netip.Prefix {
	p, err := parseTarget(s)
	if err != nil {
		panic(err)
	}
	return p
}
