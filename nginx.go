package main

import (
	"bufio"
	"cmp"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Starting point for an nginx that blocks common attacks itself. The files
// belong to the admin once written: nginx-init never overwrites them.

//go:embed packaging/nginx/scanner-guard-rules.conf
var nginxRulesConf []byte

//go:embed packaging/nginx/server.conf
var nginxServerConf []byte

//go:embed packaging/nginx/login.conf
var nginxLoginConf []byte

// https://www.cloudflare.com/ips/ (2026-11-25)
var cloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

const (
	defaultNginxDir = "/etc/nginx"
	nginxRulesFile  = "conf.d/scanner-guard-rules.conf"
	nginxServerFile = "scanner-guard/server.conf"
	nginxLoginFile  = "scanner-guard/login.conf"
	nginxRealIPFile = "conf.d/scanner-guard-realip.conf"
	nginxSamples    = 10 // URIs printed per rule
)

func nginxInitCmd(args []string) {
	flags := flag.NewFlagSet("nginx-init", flag.ExitOnError)
	dir := flags.String("dir", defaultNginxDir, "nginx config directory")
	proxy := flags.String("proxy", "", "proxies in front of this server, comma-separated: cloudflare, an IP or a CIDR")
	_ = flags.Parse(args)

	proxies, err := parseProxies(*proxy)
	if err != nil {
		log.Fatal(err)
	}
	if err := nginxInit(*dir, proxies, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func parseProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for s := range strings.SplitSeq(list, ",") {
		s = strings.TrimSpace(s)
		names := []string{s}
		switch {
		case s == "":
			continue
		case strings.EqualFold(s, "cloudflare"):
			names = cloudflareRanges
		}
		for _, n := range names {
			p, err := parseTarget(n)
			if err != nil {
				return nil, fmt.Errorf("-proxy %q: %w", n, err)
			}
			if tooBroad(p) {
				return nil, fmt.Errorf("-proxy %q: too broad, any client could forge its IP", n)
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// X-Forwarded-For read from the right, skipping trusted proxies, works for one
// proxy or a chain (Cloudflare -> Traefik) and can't be forged by the client.
func renderRealIP(proxies []netip.Prefix) []byte {
	var b strings.Builder
	b.WriteString("# Scanner Guard: client IP behind a proxy or CDN. Created by `scanner-guard-agent\n" +
		"# nginx-init -proxy`, yours to edit. Trust only your own proxies.\n")
	for _, p := range proxies {
		fmt.Fprintf(&b, "set_real_ip_from %s;\n", nftElem(p))
	}
	b.WriteString("real_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n")
	return []byte(b.String())
}

func nginxInit(dir string, proxies []netip.Prefix, out io.Writer) error {
	// Not created here: without it nginx.conf most likely doesn't load conf.d.
	if fi, err := os.Stat(filepath.Join(dir, "conf.d")); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s has no conf.d directory, is it the nginx config directory? (-dir)", dir)
	}

	// The inactive ones first: a half-done run leaves nothing nginx loads.
	type file struct {
		name    string
		content []byte
	}
	files := []file{{nginxServerFile, nginxServerConf}, {nginxLoginFile, nginxLoginConf}, {nginxRulesFile, nginxRulesConf}}
	if len(proxies) > 0 {
		files = append(files, file{nginxRealIPFile, renderRealIP(proxies)})
	}
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		switch err := writeNew(p, f.content); {
		case errors.Is(err, fs.ErrExist):
			fmt.Fprintf(out, "kept    %s (already there, delete it to start over)\n", p)
		case err != nil:
			return err
		default:
			fmt.Fprintf(out, "created %s\n", p)
		}
	}

	fmt.Fprintf(out, `
Nothing is blocked yet. Next:
  1. see what the rules would block in the log you already have:
       scanner-guard-agent nginx-test -dir %[1]s /var/log/nginx/access.log
     false positive? add an exception or disable the rule in %[2]s
  2. add to each server block to protect, before its own if/rewrite/return:
       include %[3]s;
       include %[4]s;   # optional, limits login attempts
  3. nginx -t && systemctl reload nginx
  4. optional, ban who insists: enable the web_attack and web_login rules in agent.yaml.
`, dir, filepath.Join(dir, nginxRulesFile), nginxServerFile, nginxLoginFile)

	if len(proxies) == 0 {
		fmt.Fprintln(out, "     Behind a proxy or CDN? Run again with -proxy first, or you would ban the proxy.")
		return nil
	}
	names := make([]string, len(proxies))
	for i, p := range proxies {
		names[i] = nftElem(p)
	}
	fmt.Fprintf(out, "     Add the proxies to ignore in agent.yaml, next to your own IPs:\n       ignore: [%s]\n", strings.Join(names, ", "))
	return nil
}

// writeNew creates p, failing with fs.ErrExist rather than overwriting.
func writeNew(p string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(p) // a truncated file would be kept by the next run
	}
	return err
}

func nginxTestCmd(args []string) {
	flags := flag.NewFlagSet("nginx-test", flag.ExitOnError)
	dir := flags.String("dir", defaultNginxDir, "nginx config directory")
	_ = flags.Parse(args)

	if flags.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	conf := filepath.Join(*dir, nginxRulesFile)
	raw, err := os.ReadFile(conf)
	if err != nil {
		log.Fatalf("%v (run nginx-init first)", err)
	}
	maps, err := parseNginxMaps(string(raw))
	if err != nil {
		log.Fatalf("%s:%v", conf, err)
	}

	var in io.Reader = os.Stdin
	if name := flags.Arg(0); name != "-" {
		f, err := os.Open(name)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}
	if err := nginxTest(maps, in, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// nginxMap is the subset of an nginx map block the shipped config uses.
type nginxMap struct {
	def     string
	entries []nginxMapEntry
}

type nginxMapEntry struct {
	literal string         // used when re is nil
	re      *regexp.Regexp // "~" or "~*" key
	value   string
}

// value follows nginx: literal keys first (case-insensitive), then the regexes
// in order.
func (m nginxMap) value(s string) string {
	for _, e := range m.entries {
		if e.re == nil && strings.EqualFold(e.literal, s) {
			return e.value
		}
	}
	for _, e := range m.entries {
		if e.re != nil && e.re.MatchString(s) {
			return e.value
		}
	}
	return m.def
}

var (
	nginxMapOpen  = regexp.MustCompile(`^map\s+\S+\s+\$(\w+)\s*\{(?:\s*#.*)?$`)
	nginxMapEntRe = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|[^\s"]+)\s+("[^"\\]*"|[^\s"]+)\s*;(?:\s*#.*)?$`)
	nginxUnescape = strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\\`, `\`, `\t`, "\t", `\r`, "\r", `\n`, "\n")
)

// parseNginxMaps reads the map blocks of scanner-guard-rules.conf, one entry per line
// as shipped. A line inside a map it can't evaluate is an error: skipping it
// would make nginx-test disagree with nginx.
func parseNginxMaps(conf string) (map[string]nginxMap, error) {
	maps := map[string]nginxMap{}
	var name string
	var cur nginxMap
	for i, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if name == "" {
			if m := nginxMapOpen.FindStringSubmatch(line); m != nil {
				name, cur = m[1], nginxMap{}
			} else if strings.HasPrefix(line, "map ") {
				return nil, fmt.Errorf("%d: not supported by nginx-test: %s", i+1, line)
			}
			continue
		}
		if line == "}" {
			maps[name], name = cur, ""
			continue
		}
		m := nginxMapEntRe.FindStringSubmatch(line)
		if m == nil || m[1] == "include" {
			return nil, fmt.Errorf("%d: not supported by nginx-test: %s", i+1, line)
		}
		key, value := nginxToken(m[1]), nginxToken(m[2])
		expr, isRegex := strings.CutPrefix(key, "~")
		switch {
		case key == "default":
			cur.def = value
		case isRegex:
			if e, ok := strings.CutPrefix(expr, "*"); ok {
				expr = "(?i)" + e
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("%d: nginx-test can't run this rule: %w", i+1, err)
			}
			cur.entries = append(cur.entries, nginxMapEntry{re: re, value: value})
		default:
			cur.entries = append(cur.entries, nginxMapEntry{literal: key, value: value})
		}
	}
	if name != "" {
		return nil, fmt.Errorf("map $%s is never closed", name)
	}
	if len(maps["sg_uri"].entries)+len(maps["sg_path"].entries)+len(maps["sg_agent"].entries) == 0 {
		return nil, errors.New("no rules in the maps $sg_uri, $sg_path and $sg_agent")
	}
	return maps, nil
}

func nginxToken(s string) string {
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	return nginxUnescape.Replace(s)
}

var (
	// Request line and, when there, User-Agent of the combined format (nginx and Apache).
	logRequest = regexp.MustCompile(`"[A-Z]+ ((?:[^"\\]|\\.)+?) HTTP/[0-9.]+"(?: \S+ \S+ "(?:[^"\\]|\\.)*" "((?:[^"\\]|\\.)*)")?`)
	logEscape  = regexp.MustCompile(`\\(?:x[0-9A-Fa-f]{2}|["\\])`)
)

// logUnescape undoes the escaping of a logged value: \x22 is a quote.
func logUnescape(s string) string {
	return logEscape.ReplaceAllStringFunc(s, func(s string) string {
		if s[1] != 'x' {
			return s[1:]
		}
		n, _ := strconv.ParseUint(s[2:], 16, 8)
		return string([]byte{byte(n)})
	})
}

// nginxRule returns the rule that blocks a logged request, "" for none.
func nginxRule(maps map[string]nginxMap, uri, agent string) string {
	uri, agent = logUnescape(uri), logUnescape(agent)
	if agent == "-" {
		agent = ""
	}
	// $uri: decoded and normalized, so /admin/../x.php is not an exception.
	p, _, _ := strings.Cut(uri, "?")
	if d, err := url.PathUnescape(p); err == nil {
		p = d
	}
	clean := path.Clean("/" + p)
	if last := p[strings.LastIndex(p, "/")+1:]; (last == "" || last == "." || last == "..") && clean != "/" {
		clean += "/" // path.Clean drops it, nginx doesn't
	}

	rule := cmp.Or(maps["sg_uri"].value(uri), maps["sg_path"].value(clean), maps["sg_agent"].value(agent))
	if rule == "" {
		return ""
	}
	if skip := maps["sg_skip"].value(clean); skip != "0" && skip != "" {
		return ""
	}
	return rule
}

// nginxTest prints what the rules would have blocked in an access log.
func nginxTest(maps map[string]nginxMap, in io.Reader, out io.Writer) error {
	type stat struct {
		total int
		ips   map[string]bool
		uris  map[string]int
	}
	stats := map[string]*stat{}
	lines, requests := 0, 0

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines++
		m := logRequest.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		requests++
		rule := nginxRule(maps, m[1], m[2])
		if rule == "" {
			continue
		}
		st := stats[rule]
		if st == nil {
			st = &stat{ips: map[string]bool{}, uris: map[string]int{}}
			stats[rule] = st
		}
		st.total++
		st.ips[logClient(sc.Text())] = true
		st.uris[m[1]]++
	}
	if err := sc.Err(); err != nil {
		return err
	}

	names := make([]string, 0, len(stats))
	blocked := 0
	for n, st := range stats {
		names = append(names, n)
		blocked += st.total
	}
	sort.Strings(names)

	fmt.Fprintf(out, "%d lines, %d requests, %d would be blocked\n", lines, requests, blocked)
	for _, n := range names {
		st := stats[n]
		fmt.Fprintf(out, "rule %s: %d requests, %d clients\n", n, st.total, len(st.ips))
		uris := make([]string, 0, len(st.uris))
		for u := range st.uris {
			uris = append(uris, u)
		}
		sort.Slice(uris, func(i, j int) bool {
			if a, b := st.uris[uris[i]], st.uris[uris[j]]; a != b {
				return a > b
			}
			return uris[i] < uris[j]
		})
		for _, u := range uris[:min(len(uris), nginxSamples)] {
			fmt.Fprintf(out, "  %6d  %s\n", st.uris[u], printable(truncate(u, 160)))
		}
		if more := len(uris) - nginxSamples; more > 0 {
			fmt.Fprintf(out, "          ... and %d more\n", more)
		}
	}
	return nil
}

// logClient returns the client of a log line: the first IP before the date, so
// a format that starts with the site ("$server_name $remote_addr - ...") counts
// clients, not sites. Without an IP there, the first field.
func logClient(line string) string {
	head, _, _ := strings.Cut(line, " [")
	fields := strings.Fields(head)
	for _, f := range fields {
		if _, err := netip.ParseAddr(f); err == nil {
			return f
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// printable keeps control characters from a log off the terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}
