package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// diagnoseCmd answers, for a client that cannot reach a server: does anything
// on this server block the IP (the agent, another firewall, fail2ban, nginx),
// do its requests reach the server at all, and can the server reach it back.
// Read-only.
func diagnoseCmd(args []string) {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "config file")
	since := fs.String("since", "24h", "how far back journald is searched")
	capture := fs.Duration("capture", 0, "also capture the IP's packets for this long with tcpdump (ask the client to try meanwhile), e.g. 60s")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	a, err := netip.ParseAddr(fs.Arg(0))
	if err != nil {
		log.Fatalf("%q is not an IP address", fs.Arg(0))
	}
	diagnose(os.Stdout, a, *path, *since, *capture, execOut)
}

// diagnose writes the whole report on ip, from the command or for the central app.
func diagnose(w io.Writer, ip netip.Addr, configPath, since string, capture time.Duration, run func(time.Duration, string, ...string) (string, error)) {
	d := &diagnosis{w: w, ip: ip.Unmap().WithZone(""), run: run, packets: -1}
	d.agent(configPath)
	d.firewalls()
	d.web(configPath)
	d.logs(since)
	d.network()
	if capture > 0 {
		d.capture(capture)
	}
	d.verdict()
}

type diagnosis struct {
	w   io.Writer
	ip  netip.Addr
	run func(timeout time.Duration, name string, args ...string) (string, error)

	blockedBy []string // what blocks the IP on this server
	seen      []string // where the IP's traffic shows up
	pingOK    *bool
	packets   int // captured; -1 = no capture
}

var errNotInstalled = errors.New("not installed")

func execOut(timeout time.Duration, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", errNotInstalled
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func (d *diagnosis) section(title string) { fmt.Fprintf(d.w, "\n== %s ==\n", title) }

func (d *diagnosis) agent(configPath string) {
	d.section("scanner-guard-agent")
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(d.w, "  config: %v\n", err)
		return
	}
	st, _ := loadState(cfg.StateFile)
	lookup := func(p netip.Prefix) (string, string) {
		set, elem := nftLookup(p)
		if set != "" {
			d.blockedBy = append(d.blockedBy, "scanner-guard-agent (nftables set "+set+")")
		}
		return set, elem
	}
	if cfg.Firewall != "nftables" {
		lookup = nil
	}
	var b strings.Builder
	describeIP(&b, cfg, st, d.ip, lookup, time.Now())
	_, rest, _ := strings.Cut(b.String(), "\n") // drop the IP line
	fmt.Fprint(d.w, rest)
	if out, _ := d.run(5*time.Second, "systemctl", "is-active", "scanner-guard-agent"); out != "" {
		fmt.Fprintf(d.w, "  service:   %s\n", strings.TrimSpace(out))
	}
}

// firewalls looks for the IP everywhere else a server can drop it.
func (d *diagnosis) firewalls() {
	d.section("other firewalls on this server")

	if out, err := d.run(10*time.Second, "nft", "list", "ruleset"); err == nil {
		hits := nftMentions(out, d.ip)
		d.report("nftables", hits, "(scanner_guard table above)")
	} else {
		fmt.Fprintf(d.w, "  nftables:  %v\n", short(err))
	}

	for _, ipt := range []string{"iptables-save", "ip6tables-save", "iptables-legacy-save"} {
		if ipt == "iptables-save" && !d.ip.Is4() || ipt == "ip6tables-save" && d.ip.Is4() {
			continue
		}
		out, err := d.run(10*time.Second, ipt)
		if errors.Is(err, errNotInstalled) {
			continue
		}
		d.report(ipt, mentions(out, d.ip, ""), "")
	}

	if out, err := d.run(10*time.Second, "ipset", "list"); err == nil {
		d.report("ipset", ipsetMentions(out, d.ip), "")
	}

	d.fail2ban()

	for _, f := range []string{"/etc/hosts.deny", "/etc/csf/csf.deny", "/etc/apf/deny_hosts.rules"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		d.report(f, mentions(stripComments(string(raw)), d.ip, ""), "")
	}
}

func (d *diagnosis) fail2ban() {
	out, err := d.run(10*time.Second, "fail2ban-client", "status")
	switch {
	case errors.Is(err, errNotInstalled):
		return
	case err != nil:
		fmt.Fprintf(d.w, "  fail2ban:  not running (%s)\n", strings.TrimSpace(firstLine(out)))
		return
	}
	_, list, _ := strings.Cut(out, "Jail list:")
	var hits []string
	for j := range strings.SplitSeq(list, ",") {
		if j = strings.TrimSpace(j); j == "" {
			continue
		}
		st, _ := d.run(10*time.Second, "fail2ban-client", "status", j)
		for line := range strings.SplitSeq(st, "\n") {
			if _, ips, ok := strings.Cut(line, "Banned IP list:"); ok && len(mentions(ips, d.ip, "")) > 0 {
				hits = append(hits, "jail "+j)
			}
		}
	}
	d.report("fail2ban", hits, "")
}

// report prints one firewall's result; any hit blocks (or may block) the IP.
func (d *diagnosis) report(name string, hits []string, none string) {
	if len(hits) == 0 {
		fmt.Fprintf(d.w, "  %-9s  nothing about %s %s\n", name+":", d.ip, none)
		return
	}
	verb := "allow" // only ACCEPT rules: they let the IP in
	for _, h := range hits {
		if !strings.Contains(strings.ToLower(h), "accept") {
			verb = "cover"
			d.blockedBy = append(d.blockedBy, name)
			break
		}
	}
	fmt.Fprintf(d.w, "  %-9s  %d rule(s) or entries %s %s:\n", name+":", len(hits), verb, d.ip)
	for _, h := range hits[:min(len(hits), 10)] {
		fmt.Fprintf(d.w, "               %s\n", h)
	}
}

func (d *diagnosis) web(configPath string) {
	d.section("nginx / apache")
	if cfg, err := loadConfig(configPath); err == nil {
		for _, dl := range cfg.Denylists {
			raw, err := os.ReadFile(dl.Path)
			if err != nil {
				continue
			}
			if hits := mentions(stripComments(string(raw)), d.ip, ""); len(hits) > 0 {
				d.blockedBy = append(d.blockedBy, "denylist "+dl.Path)
				fmt.Fprintf(d.w, "  denylist:  listed in %s: %s\n", dl.Path, hits[0])
			} else {
				fmt.Fprintf(d.w, "  denylist:  not in %s\n", dl.Path)
			}
		}
	}

	n, last := grepFile(defaultGuardLog, d.ip.String())
	if n > 0 {
		d.blockedBy = append(d.blockedBy, "nginx 403 rules (scanner-guard.log)")
		fmt.Fprintf(d.w, "  403 rules: %d request(s) answered 403, last: %s\n", n, last)
	} else {
		fmt.Fprintf(d.w, "  403 rules: no request of %s answered 403 (%s)\n", d.ip, defaultGuardLog)
	}

	// ponytail: current log files only, not the rotated .1/.gz ones.
	logs, _ := filepath.Glob("/var/log/nginx/*access*.log")
	apache, _ := filepath.Glob("/var/log/apache2/*access*.log")
	total := 0
	for _, f := range append(logs, apache...) {
		if n, last := grepFile(f, d.ip.String()); n > 0 {
			total += n
			fmt.Fprintf(d.w, "  access:    %d request(s) in %s, last: %s\n", n, f, truncate(last, 200))
		}
	}
	if total > 0 {
		d.seen = append(d.seen, fmt.Sprintf("%d web request(s)", total))
	} else if len(logs)+len(apache) > 0 {
		fmt.Fprintf(d.w, "  access:    no request of %s in the current access logs\n", d.ip)
	}
}

func (d *diagnosis) logs(since string) {
	d.section("ssh and system logs (journald, " + since + ")")
	out, err := d.run(60*time.Second, "journalctl", "--since", "-"+since, "--no-pager", "-q", "-o", "short-iso")
	if err != nil && out == "" {
		fmt.Fprintf(d.w, "  journald:  %v\n", short(err))
		return
	}
	n, last := 0, ""
	for line := range strings.SplitSeq(out, "\n") {
		if containsIP(line, d.ip.String()) {
			n, last = n+1, line
		}
	}
	if n == 0 {
		fmt.Fprintf(d.w, "  no line mentions %s\n", d.ip)
		return
	}
	d.seen = append(d.seen, fmt.Sprintf("%d journald line(s)", n))
	fmt.Fprintf(d.w, "  %d line(s) mention %s, last: %s\n", n, d.ip, truncate(last, 200))
}

func (d *diagnosis) network() {
	d.section("network (from this server to " + d.ip.String() + ")")
	if out, err := d.run(5*time.Second, "ip", "route", "get", d.ip.String()); err == nil {
		fmt.Fprintf(d.w, "  route:     %s\n", strings.Join(strings.Fields(firstLine(out)), " "))
	}

	out, err := d.run(15*time.Second, "ping", "-c", "4", "-W", "2", d.ip.String())
	if errors.Is(err, errNotInstalled) {
		fmt.Fprintln(d.w, "  ping:      not installed")
	} else {
		ok := err == nil
		d.pingOK = &ok
		fmt.Fprintf(d.w, "  ping:      %s\n", pingSummary(out))
	}

	for _, tool := range [][]string{{"mtr", "-n", "-r", "-c", "5", d.ip.String()}, {"tracepath", "-n", "-m", "20", d.ip.String()}} {
		out, err := d.run(90*time.Second, tool[0], tool[1:]...)
		if errors.Is(err, errNotInstalled) {
			continue
		}
		fmt.Fprintf(d.w, "  %s:\n", tool[0])
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		for _, l := range lines[max(0, len(lines)-12):] {
			fmt.Fprintf(d.w, "    %s\n", l)
		}
		return
	}
	fmt.Fprintln(d.w, "  route trace: install mtr-tiny or iputils-tracepath to see where the path stops")
}

func (d *diagnosis) capture(dur time.Duration) {
	d.section(fmt.Sprintf("capture (%s): ask the client to try now", dur))
	out, err := d.run(dur+5*time.Second, "timeout", fmt.Sprintf("%ds", int(dur.Seconds())), "tcpdump", "-n", "-l", "-i", "any", "-c", "200", "host", d.ip.String())
	if errors.Is(err, errNotInstalled) {
		fmt.Fprintln(d.w, "  timeout or tcpdump not installed")
		d.packets = -1
		return
	}
	var pkts []string
	for line := range strings.SplitSeq(out, "\n") {
		if containsIP(line, d.ip.String()) {
			pkts = append(pkts, line)
		}
	}
	d.packets = len(pkts)
	fmt.Fprintf(d.w, "  %d packet(s) to or from %s\n", len(pkts), d.ip)
	for _, p := range pkts[:min(len(pkts), 15)] {
		fmt.Fprintf(d.w, "    %s\n", truncate(p, 160))
	}
}

func (d *diagnosis) verdict() {
	d.section("verdict")
	if len(d.blockedBy) > 0 {
		fmt.Fprintf(d.w, "  BLOCKED on this server by: %s\n", strings.Join(d.blockedBy, "; "))
		fmt.Fprintln(d.w, "  Unblock it there (scanner-guard: unban on the central app or `ip` above; add it to Never block if it is a client).")
		return
	}
	fmt.Fprintf(d.w, "  Nothing on this server blocks %s.\n", d.ip)
	switch {
	case d.packets > 0:
		fmt.Fprintln(d.w, "  Its packets reach this server: look at the application (TLS, the site, its own access rules).")
	case d.packets == 0:
		fmt.Fprintln(d.w, "  No packet arrived while capturing: the traffic stops before this server (client network, ISP, datacenter firewall or DDoS protection).")
	case len(d.seen) > 0:
		fmt.Fprintf(d.w, "  Its traffic shows up here (%s): it does reach this server.\n", strings.Join(d.seen, ", "))
	default:
		fmt.Fprintln(d.w, "  No trace of it in the logs: it may never reach this server. Run again with -capture 60s while the client tries.")
	}
	if d.pingOK != nil && !*d.pingOK {
		fmt.Fprintln(d.w, "  The server gets no ping reply: many clients filter ICMP, so this alone proves nothing; the trace shows where the path stops.")
	}
}

// mentions returns the lines of s holding an address, CIDR or range that
// covers a. A /0 is skipped: "any address" is not about this IP.
func mentions(s string, a netip.Addr, prefix string) []string {
	var hits []string
	for line := range strings.SplitSeq(s, "\n") {
		if lineCovers(line, a) {
			hits = append(hits, prefix+strings.TrimSpace(line))
		}
	}
	return hits
}

func lineCovers(line string, a netip.Addr) bool {
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" \t,{}()[];\"'=", r) }) {
		if strings.HasSuffix(tok, "/0") {
			continue
		}
		if elemCovers(tok, a) {
			return true
		}
	}
	return false
}

// nftMentions finds the IP in the ruleset outside the agent's own table,
// naming the table and the chain or set of each hit.
func nftMentions(ruleset string, a netip.Addr) []string {
	var hits []string
	table, block := "", ""
	for line := range strings.SplitSeq(ruleset, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "table "):
			table, block = strings.TrimSuffix(strings.TrimPrefix(t, "table "), " {"), ""
			continue
		case strings.HasPrefix(t, "chain "), strings.HasPrefix(t, "set "):
			block = strings.TrimSuffix(t, " {")
			continue
		}
		if table == "inet scanner_guard" || !lineCovers(t, a) {
			continue
		}
		hits = append(hits, fmt.Sprintf("table %s, %s: %s", table, block, truncate(t, 160)))
	}
	return hits
}

func ipsetMentions(out string, a netip.Addr) []string {
	var hits []string
	set := ""
	for line := range strings.SplitSeq(out, "\n") {
		if name, ok := strings.CutPrefix(line, "Name: "); ok {
			set = strings.TrimSpace(name)
			continue
		}
		if lineCovers(line, a) {
			hits = append(hits, "set "+set+": "+strings.TrimSpace(line))
		}
	}
	return hits
}

// grepFile counts the lines of f holding ip and returns the last one.
func grepFile(f, ip string) (int, string) {
	file, err := os.Open(f)
	if err != nil {
		return 0, ""
	}
	defer file.Close()
	n, last := 0, ""
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if containsIP(sc.Text(), ip) {
			n, last = n+1, sc.Text()
		}
	}
	return n, last
}

// containsIP finds ip not glued to another digit or dot: 1.2.3.4 is not in 11.2.3.45.
func containsIP(line, ip string) bool {
	for i := 0; ; {
		j := strings.Index(line[i:], ip)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(ip)
		if (start == 0 || !isIPChar(line[start-1])) && (end == len(line) || !isIPChar(line[end])) {
			return true
		}
		i = start + 1
	}
}

func isIPChar(c byte) bool {
	return c == '.' || c == ':' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func pingSummary(out string) string {
	var stats, rtt string
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "packet loss") {
			stats = strings.TrimSpace(line)
		}
		if strings.HasPrefix(line, "rtt") || strings.HasPrefix(line, "round-trip") {
			rtt = strings.TrimSpace(line)
		}
	}
	if stats == "" {
		return strings.TrimSpace(firstLine(out))
	}
	if rtt != "" {
		return stats + "; " + rtt
	}
	return stats
}

func stripComments(s string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		line, _, _ = strings.Cut(line, "#")
		b.WriteString(line + "\n")
	}
	return b.String()
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

func short(err error) string {
	return firstLine(err.Error())
}
