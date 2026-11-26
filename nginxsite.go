package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// nginx-enable / nginx-disable / nginx-sites: turn the 403 rules on or off per
// site (server_name), without editing site files by hand.

const nginxInclude = "include " + nginxServerFile + ";"

// serverBlock is one server { } of a site file, as far as these commands need it.
type serverBlock struct {
	start, end int // line indexes of "server {" and of its closing "}"
	names      []string
	nameLine   int      // first server_name line, -1 if none
	listens    []string // arguments of each listen
	include    bool     // already includes scanner-guard/server.conf
	forge      string   // X of an include forge-conf/X/server/* or forge-conf/X/site.conf
}

type siteFile struct {
	path   string // symlinks resolved
	lines  []string
	blocks []*serverBlock
}

var forgeInclude = regexp.MustCompile(`forge-conf/([^/\s;]+)/(server/\*|site\.conf)`)

// stripComment drops a trailing # comment (nginx has no # inside the values
// these commands read).
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func parseSiteFile(path, raw string) *siteFile {
	f := &siteFile{path: path, lines: strings.Split(raw, "\n")}
	depth, serverDepth := 0, -1
	var cur *serverBlock
	for i, line := range f.lines {
		code := stripComment(line)
		fields := strings.Fields(strings.NewReplacer(";", " ", "{", " { ").Replace(code))
		switch {
		case cur == nil && len(fields) >= 2 && fields[0] == "server" && fields[1] == "{":
			cur = &serverBlock{start: i, nameLine: -1}
			serverDepth = depth
			f.blocks = append(f.blocks, cur)
		case cur != nil && len(fields) > 0:
			args := fields[1:]
			switch fields[0] {
			case "server_name":
				if depth == serverDepth+1 {
					cur.names = append(cur.names, args...)
					if cur.nameLine < 0 {
						cur.nameLine = i
					}
				}
			case "listen":
				if depth == serverDepth+1 {
					cur.listens = append(cur.listens, strings.Join(args, " "))
				}
			case "include":
				if len(args) == 0 {
					break
				}
				if args[0] == nginxServerFile || strings.HasSuffix(args[0], "/"+nginxServerFile) {
					cur.include = true
				}
				if m := forgeInclude.FindStringSubmatch(args[0]); m != nil && cur.forge == "" {
					cur.forge = m[1]
				}
			}
		}
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		if cur != nil && depth <= serverDepth {
			cur.end = i
			cur = nil
		}
	}
	return f
}

// loadSiteFiles reads every file nginx loads sites from: sites-enabled/* and
// conf.d/*.conf, symlinks resolved, the agent's own files skipped.
func loadSiteFiles(dir string) ([]*siteFile, error) {
	var out []*siteFile
	seen := map[string]bool{}
	for _, pattern := range []string{"sites-enabled/*", "conf.d/*.conf"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil || seen[real] || strings.HasPrefix(filepath.Base(real), "scanner-guard") {
				continue
			}
			if fi, err := os.Stat(real); err != nil || fi.IsDir() {
				continue
			}
			raw, err := os.ReadFile(real)
			if err != nil {
				return nil, err
			}
			seen[real] = true
			out = append(out, parseSiteFile(real, string(raw)))
		}
	}
	return out, nil
}

// forgeDir is where the include goes on a Forge site: Forge rewrites the site
// file when the site changes in its panel, but includes forge-conf/X/server/*
// (directly, or through forge-conf/X/site.conf) and leaves that folder alone.
// "" when b is not a Forge block.
func forgeDir(dir string, f *siteFile, b *serverBlock) string {
	if b.forge == "" {
		return ""
	}
	want := "forge-conf/" + b.forge + "/server/*"
	block := strings.Join(f.lines[b.start:b.end+1], "\n")
	siteConf, _ := os.ReadFile(filepath.Join(dir, "forge-conf", b.forge, "site.conf"))
	if !strings.Contains(block, want) && !strings.Contains(string(siteConf), want) {
		return ""
	}
	return filepath.Join(dir, "forge-conf", b.forge, "server")
}

const forgeIncludeFile = "scanner-guard.conf"

func blockOn(dir string, f *siteFile, b *serverBlock) bool {
	if b.include {
		return true
	}
	if d := forgeDir(dir, f, b); d != "" {
		_, err := os.Stat(filepath.Join(d, forgeIncludeFile))
		return err == nil
	}
	return false
}

// siteMatch is every server block of one file naming the site.
type siteMatch struct {
	file   *siteFile
	blocks []*serverBlock
}

func findSite(files []*siteFile, site string) ([]siteMatch, error) {
	var out []siteMatch
	for _, f := range files {
		var blocks []*serverBlock
		for _, b := range f.blocks {
			if slices.ContainsFunc(b.names, func(n string) bool { return strings.EqualFold(n, site) }) {
				blocks = append(blocks, b)
			}
		}
		if len(blocks) > 0 {
			out = append(out, siteMatch{f, blocks})
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	var close []string
	for _, f := range files {
		for _, b := range f.blocks {
			for _, n := range b.names {
				if strings.Contains(strings.ToLower(n), strings.ToLower(site)) && !slices.Contains(close, n) {
					close = append(close, n)
				}
			}
		}
	}
	msg := fmt.Sprintf("no server block with server_name %s", site)
	if len(close) > 0 {
		msg += " (did you mean " + strings.Join(close[:min(len(close), 5)], ", ") + "?)"
	}
	return nil, errors.New(msg)
}

// nginxOps runs nginx; replaced in tests.
type nginxOps struct {
	test   func() (string, error)
	reload func() error
	probe  func(site string, t probeTarget, path string) (int, error)
	settle time.Duration // reload returns before the new workers take over
}

var systemNginx = nginxOps{
	test: func() (string, error) {
		out, err := exec.Command("nginx", "-t").CombinedOutput()
		return string(out), err
	},
	reload: func() error {
		if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl reload nginx: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	},
	probe:  httpProbe,
	settle: 3 * time.Second,
}

// fileChange is one file to write: old == nil creates it, new == nil removes it.
type fileChange struct {
	path     string
	old, new []byte
	perm     fs.FileMode
}

func (c fileChange) apply() error {
	if c.new == nil {
		return os.Remove(c.path)
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	return writeAtomic(c.path, c.new, c.perm)
}

func (c fileChange) undo() {
	if c.old == nil {
		_ = os.Remove(c.path)
		return
	}
	_ = writeAtomic(c.path, c.old, c.perm)
}

// applyAndReload writes every change, keeps them only if nginx -t passes, then
// reloads nginx.
func applyAndReload(changes []fileChange, ops nginxOps) error {
	if len(changes) == 0 {
		return nil
	}
	var done []fileChange
	undo := func() {
		for _, c := range slices.Backward(done) {
			c.undo()
		}
	}
	for _, c := range changes {
		if err := c.apply(); err != nil {
			undo()
			return err
		}
		done = append(done, c)
	}
	if out, err := ops.test(); err != nil {
		undo()
		return fmt.Errorf("nginx -t failed, every file restored, nothing reloaded:\n%s", lastLines(out, 3))
	}
	if err := ops.reload(); err != nil {
		return err
	}
	time.Sleep(ops.settle)
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

func readChange(path string, content []byte) (fileChange, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileChange{}, err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return fileChange{}, err
	}
	return fileChange{path: path, old: old, new: content, perm: fi.Mode().Perm()}, nil
}

func nginxEnableCmd(args []string) {
	flags := flag.NewFlagSet("nginx-enable", flag.ExitOnError)
	dir := flags.String("dir", defaultNginxDir, "nginx config directory")
	_ = flags.Parse(args)
	if flags.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	if err := nginxEnable(*dir, flags.Args(), os.Stdout, systemNginx); err != nil {
		log.Fatal(err)
	}
}

func nginxDisableCmd(args []string) {
	flags := flag.NewFlagSet("nginx-disable", flag.ExitOnError)
	dir := flags.String("dir", defaultNginxDir, "nginx config directory")
	_ = flags.Parse(args)
	if flags.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	if err := nginxDisable(*dir, flags.Args(), os.Stdout, systemNginx); err != nil {
		log.Fatal(err)
	}
}

func nginxSitesCmd(args []string) {
	flags := flag.NewFlagSet("nginx-sites", flag.ExitOnError)
	dir := flags.String("dir", defaultNginxDir, "nginx config directory")
	_ = flags.Parse(args)
	if err := nginxSites(*dir, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// nginxEnable adds the 403 rules to every server block of the given sites, in
// one nginx -t and one reload, then checks each site answers an attack with 403.
func nginxEnable(dir string, sites []string, out io.Writer, ops nginxOps) error {
	files, err := loadSiteFiles(dir)
	if err != nil {
		return err
	}
	matches := map[string][]siteMatch{}
	for _, s := range sites {
		m, err := findSite(files, s)
		if err != nil {
			return err
		}
		matches[s] = m
	}

	if err := nginxWriteRules(dir, nil, out); err != nil {
		return err
	}

	inserts := map[*siteFile][]int{} // server_name lines to put the include before
	forge := map[string]bool{}       // forge-conf/X/server dirs
	var changes []fileChange
	for _, s := range sites {
		for _, m := range matches[s] {
			for _, b := range m.blocks {
				switch d := forgeDir(dir, m.file, b); {
				case blockOn(dir, m.file, b):
				case d != "":
					if !forge[d] {
						forge[d] = true
						changes = append(changes, fileChange{path: filepath.Join(d, forgeIncludeFile), new: []byte(nginxInclude + "\n"), perm: 0o644})
						fmt.Fprintf(out, "%s: %s (Forge: every domain of this Forge site gets it)\n", s, filepath.Join(d, forgeIncludeFile))
					}
				case b.nameLine >= 0 && !slices.Contains(inserts[m.file], b.nameLine):
					inserts[m.file] = append(inserts[m.file], b.nameLine)
					fmt.Fprintf(out, "%s: %s, line %d\n", s, m.file.path, b.nameLine+1)
				}
			}
		}
	}
	for f, lines := range inserts {
		var b strings.Builder
		for i, line := range f.lines {
			if slices.Contains(lines, i) {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				b.WriteString(indent + nginxInclude + "\n")
			}
			b.WriteString(line)
			if i < len(f.lines)-1 {
				b.WriteString("\n")
			}
		}
		c, err := readChange(f.path, []byte(b.String()))
		if err != nil {
			return err
		}
		changes = append(changes, c)
	}
	if len(changes) == 0 {
		fmt.Fprintln(out, "already on for every site given")
	}
	if err := applyAndReload(changes, ops); err != nil {
		return err
	}

	fmt.Fprintln(out)
	for _, s := range sites {
		t := pickTarget(matches[s])
		attack, aerr := ops.probe(s, t, "/?id=1+union+select+1")
		normal, nerr := ops.probe(s, t, "/")
		fmt.Fprintf(out, "%s (%s)\n", s, t)
		fmt.Fprintf(out, "  attack: %s\n", verdict(attack, aerr, attack == 403, "want 403"))
		fmt.Fprintf(out, "  normal: %s\n", verdict(normal, nerr, normal != 403 && normal < 500, "was it like this before? undo: scanner-guard-agent nginx-disable "+s))
	}
	return nil
}

func verdict(code int, err error, ok bool, hint string) string {
	switch {
	case err != nil:
		return "error: " + err.Error()
	case ok:
		return fmt.Sprintf("%d ok", code)
	default:
		return fmt.Sprintf("%d  <- %s", code, hint)
	}
}

// nginxDisable removes the include from every server block of the given sites.
func nginxDisable(dir string, sites []string, out io.Writer, ops nginxOps) error {
	files, err := loadSiteFiles(dir)
	if err != nil {
		return err
	}
	drop := map[*siteFile]map[int]bool{}
	var changes []fileChange
	for _, s := range sites {
		matches, err := findSite(files, s)
		if err != nil {
			return err
		}
		for _, m := range matches {
			for _, b := range m.blocks {
				if d := forgeDir(dir, m.file, b); d != "" {
					p := filepath.Join(d, forgeIncludeFile)
					if c, err := readChange(p, nil); err == nil && !slices.ContainsFunc(changes, func(x fileChange) bool { return x.path == p }) {
						changes = append(changes, c)
						fmt.Fprintf(out, "%s: removing %s\n", s, p)
					}
				}
				for i := b.start; i <= b.end; i++ {
					if strings.TrimSpace(stripComment(m.file.lines[i])) == nginxInclude {
						if drop[m.file] == nil {
							drop[m.file] = map[int]bool{}
						}
						drop[m.file][i] = true
						fmt.Fprintf(out, "%s: %s, line %d\n", s, m.file.path, i+1)
					}
				}
			}
		}
	}
	for f, lines := range drop {
		kept := make([]string, 0, len(f.lines))
		for i, line := range f.lines {
			if !lines[i] {
				kept = append(kept, line)
			}
		}
		c, err := readChange(f.path, []byte(strings.Join(kept, "\n")))
		if err != nil {
			return err
		}
		changes = append(changes, c)
	}
	if len(changes) == 0 {
		fmt.Fprintln(out, "already off for every site given")
		return nil
	}
	if err := applyAndReload(changes, ops); err != nil {
		return err
	}
	fmt.Fprintln(out, "off, nginx reloaded")
	return nil
}

// nginxSites lists every server block with whether the 403 rules are on.
func nginxSites(dir string, out io.Writer) error {
	files, err := loadSiteFiles(dir)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "403\tSERVER_NAME\tLISTEN\tFILE")
	on, total := 0, 0
	for _, f := range files {
		for _, b := range f.blocks {
			if len(b.names) == 0 {
				continue
			}
			total++
			state := "off"
			if blockOn(dir, f, b) {
				state = "on"
				on++
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s:%d\n", state, strings.Join(b.names, " "), strings.Join(listenPorts(b.listens), ","), f.path, b.start+1)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d of %d server blocks on. Turn one on: scanner-guard-agent nginx-enable SERVER_NAME\n", on, total)
	return nil
}

func listenPorts(listens []string) []string {
	out := make([]string, 0, len(listens))
	for _, l := range listens {
		t := parseListen(l)
		p := t.port
		if t.tls {
			p += "s"
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// probeTarget is where a site answers on this server.
type probeTarget struct {
	host, port string
	tls        bool
}

func (t probeTarget) String() string {
	scheme := "http"
	if t.tls {
		scheme = "https"
	}
	return scheme + " " + net.JoinHostPort(t.host, t.port)
}

// parseListen reads the arguments of a listen directive: "80", "443 ssl http2",
// "[::]:443 ssl", "10.0.0.5:8080". Wildcards become the loopback.
func parseListen(arg string) probeTarget {
	fields := strings.Fields(arg)
	t := probeTarget{host: "127.0.0.1", port: "80"}
	if len(fields) == 0 {
		return t
	}
	addr := fields[0]
	switch {
	case isPort(addr):
		t.port = addr
	case strings.HasPrefix(addr, "["):
		host, port, ok := strings.Cut(strings.TrimPrefix(addr, "["), "]")
		if p := strings.TrimPrefix(port, ":"); ok && isPort(p) {
			t.port = p
		}
		if host != "::" {
			t.host = host
		}
	default:
		host, port, ok := strings.Cut(addr, ":")
		if ok && isPort(port) {
			t.port = port
		}
		if host != "*" && host != "0.0.0.0" && host != "" {
			t.host = host
		}
	}
	t.tls = t.port == "443" || slices.Contains(fields[1:], "ssl")
	return t
}

func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536
}

// pickTarget prefers https: a site listening on both usually redirects http.
// A listen 443 that is commented out doesn't count (nginx -T showed such sites
// answering https through another server block).
func pickTarget(matches []siteMatch) probeTarget {
	var first *probeTarget
	for _, m := range matches {
		for _, b := range m.blocks {
			for _, l := range b.listens {
				t := parseListen(l)
				if t.tls {
					return t
				}
				if first == nil {
					first = &t
				}
			}
		}
	}
	if first == nil {
		return probeTarget{host: "127.0.0.1", port: "80"}
	}
	return *first
}

// httpProbe asks this server's nginx for path on site, by name (Host and SNI),
// without following redirects.
func httpProbe(site string, t probeTarget, path string) (int, error) {
	addr := net.JoinHostPort(t.host, t.port)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			// Our own nginx, asked by name: its certificate may be for another name or expired.
			TLSClientConfig: &tls.Config{ServerName: site, InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	scheme := "http"
	if t.tls {
		scheme = "https"
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(site, t.port) + path)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp.StatusCode, nil
}
