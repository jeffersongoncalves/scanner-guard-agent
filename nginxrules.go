package main

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Optional nginx rules: off by default, turned on by name from the central app
// (nginx_rules in the pull). The agent writes the ones turned on into files the
// maps of scanner-guard-rules.conf include. The central app only ever sends
// names: the rules themselves ship with the agent, so it can't write nginx
// config on a server.

const nginxOptionalDir = "/var/lib/scanner-guard/nginx"

type optionalRule struct {
	file string // uri, path or agent: the map that includes it
	line string
}

var optionalRules = map[string]optionalRule{
	// Only for servers without WordPress, Joomla or phpMyAdmin.
	"cms": {"path", `"~*/(?:wp-(?:login|admin|content|includes|json)|xmlrpc\.php|administrator/|phpmyadmin|pma/)" cms;`},
	// A full URL in a parameter (remote file inclusion). Also matches redirect/callback URLs.
	"rfi": {"uri", `"~*=(?:https?|ftp)(?::|%3a)(?:/|%2f){2}" rfi;`},
	// A percent-encoded letter (%55NION). Browsers don't send these, some API clients do.
	"encoded": {"uri", `"~*%(?:4[1-9a-f]|5[0-9a]|6[1-9a-f]|7[0-9a])" encoded;`},
	// No User-Agent at all. Also blocks some monitors and webhooks.
	"empty-agent": {"agent", `"" empty-agent;`},
}

// The map each optional file goes in, by its variable.
var optionalMaps = map[string]string{"uri": "sg_uri", "path": "sg_path", "agent": "sg_agent"}

func optionalInclude(file string) string {
	return "include " + nginxOptionalDir + "/" + file + "*.conf;"
}

// renderOptional is the content of each optional file (uri, path, agent) with
// the given rules on. Unknown names are returned apart.
func renderOptional(names []string) (map[string][]byte, []string) {
	out := map[string][]byte{}
	for f := range optionalMaps {
		out[f] = []byte("# Managed by scanner-guard-agent from the central app's nginx_rules, do not edit.\n")
	}
	var unknown []string
	names = slices.Clone(names)
	slices.Sort(names)
	for _, n := range slices.Compact(names) {
		r, ok := optionalRules[n]
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		out[r.file] = append(out[r.file], r.line+"\n"...)
	}
	return out, unknown
}

// optionalChanges lists the optional files under dir to rewrite for names.
func optionalChanges(dir string, names []string) ([]fileChange, []string, error) {
	files, unknown := renderOptional(names)
	var changes []fileChange
	for _, f := range slices.Sorted(maps.Keys(files)) {
		p := filepath.Join(dir, f+".conf")
		old, err := os.ReadFile(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			old = nil
		case err != nil:
			return nil, unknown, err
		case bytes.Equal(old, files[f]):
			continue
		}
		changes = append(changes, fileChange{path: p, old: old, new: files[f], perm: 0o644})
	}
	return changes, unknown, nil
}

// A set of optional rules that failed is tried again after this long (nginx
// may have been broken by something else meanwhile), or as soon as the
// central app sends another set.
const nginxRetry = 10 * time.Minute

// setNginxRules writes the optional rules the central app turned on and
// reloads nginx, unless nothing changed. The outcome goes in the state, for
// status.
func (a *Agent) setNginxRules(names []string, now time.Time) {
	key := strings.Join(names, ",")
	a.mu.Lock()
	if a.nginxRules != nil && *a.nginxRules == key && (a.nginxFailed.IsZero() || now.Sub(a.nginxFailed) < nginxRetry) {
		a.mu.Unlock()
		return
	}
	a.nginxRules = &key
	a.mu.Unlock()

	if a.cfg.Firewall == "none" {
		log.Printf("dry-run: nginx rules from central (%s) are not written", key)
		return
	}
	if !slices.ContainsFunc(a.cfg.rules, func(r *Rule) bool { return r.file == defaultGuardLog }) {
		// No web_attack rule (or no nginx at all): nobody would ban on the 403s,
		// nothing to apply, nothing to report.
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.Nginx != nil { // a failure recorded by 2.8.1
			a.state.Nginx = nil
			if a.statePath != "" {
				if err := a.state.save(a.statePath); err != nil {
					log.Printf("save state: %v", err)
				}
			}
		}
		return
	}
	changed, err := a.writeNginxRules(names)
	switch {
	case err != nil:
		log.Printf("nginx rules from central (%s): %v", key, err)
	case changed:
		log.Printf("nginx rules from central: %s on, nginx reloaded", cmp.Or(key, "none"))
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.nginxFailed = time.Time{}
	applied := &nginxApplied{Rules: names, At: now}
	if err != nil {
		a.nginxFailed, applied.Error = now, err.Error()
	}
	if !changed && err == nil && a.state.Nginx != nil && a.state.Nginx.Error == "" && strings.Join(a.state.Nginx.Rules, ",") == key {
		return // nothing new to record
	}
	a.state.Nginx = applied
	if a.statePath != "" {
		if serr := a.state.save(a.statePath); serr != nil {
			log.Printf("save state: %v", serr)
		}
	}
}

// writeNginxRules writes the optional files and reloads nginx when they
// changed. A server without the rules file only matters when names is not
// empty.
func (a *Agent) writeNginxRules(names []string) (bool, error) {
	rules, err := os.ReadFile(filepath.Join(a.nginxDir, nginxRulesFile))
	switch {
	case err != nil && len(names) == 0:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("no %s on this server", nginxRulesFile)
	case !bytes.Contains(rules, []byte(nginxOptionalDir)) && len(names) == 0:
		return false, nil
	case !bytes.Contains(rules, []byte(nginxOptionalDir)):
		return false, fmt.Errorf("%s doesn't include them yet, run `scanner-guard-agent nginx-init` once", nginxRulesFile)
	}

	changes, unknown, err := optionalChanges(a.nginxOptional, names)
	for _, n := range unknown {
		log.Printf("nginx rules from central: no optional rule %q in this agent version, skipped", n)
	}
	if err == nil {
		err = applyAndReload(changes, a.nginx)
	}
	return err == nil && len(changes) > 0, err
}

var nginxMapHeader = regexp.MustCompile(`^\s*map\s+\S+\s+\$(sg_uri|sg_path|sg_agent)\s*\{`)

// withOptionalIncludes adds the include of each optional file at the end of
// its map, for a scanner-guard-rules.conf written before they existed. ok is
// false when it already has them.
func withOptionalIncludes(conf string) (string, bool, error) {
	if strings.Contains(conf, nginxOptionalDir) {
		return conf, false, nil
	}
	lines := strings.Split(conf, "\n")
	var out []string
	found := map[string]bool{}
	open := ""
	for _, line := range lines {
		if m := nginxMapHeader.FindStringSubmatch(line); m != nil && open == "" {
			open = m[1]
		} else if open != "" && strings.TrimSpace(stripComment(line)) == "}" {
			for f, v := range optionalMaps {
				if v == open {
					out = append(out, "", "    # The optional rules turned on from the central app (nginx_rules), written by the agent.", "    "+optionalInclude(f))
				}
			}
			found[open], open = true, ""
		}
		out = append(out, line)
	}
	if len(found) != len(optionalMaps) {
		return conf, false, fmt.Errorf("%s: can't find the maps $sg_uri, $sg_path and $sg_agent, add by hand at the end of each: %s, %s, %s",
			nginxRulesFile, optionalInclude("uri"), optionalInclude("path"), optionalInclude("agent"))
	}
	return strings.Join(out, "\n"), true, nil
}
