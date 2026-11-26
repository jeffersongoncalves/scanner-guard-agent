package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const defaultGuardLog = "/var/log/nginx/scanner-guard.log"

// The scanner_guard log_format of scanner-guard-rules.conf:
// $remote_addr - [$time_local] "$request" $status rule=$sg_rule host=$host "$http_user_agent"
var guardLogLine = regexp.MustCompile(`^(\S+) - \[([^\]]+)\] "((?:[^"\\]|\\.)*)" \d{3} rule=(\S*) host=(\S*) "`)

// nginxReportCmd sums up what the 403 rules blocked: per rule, client and site,
// plus the last requests. Read-only.
func nginxReportCmd(args []string) {
	flags := flag.NewFlagSet("nginx-report", flag.ExitOnError)
	sinceFlag := flags.String("since", "24h", `only requests this recent ("" = the whole log)`)
	host := flags.String("host", "", "only this site (server name)")
	n := flags.Int("n", 10, "rows per list")
	_ = flags.Parse(args)

	var since time.Time
	if *sinceFlag != "" {
		d, err := parseDuration(*sinceFlag)
		if err != nil {
			log.Fatalf("-since: %v", err)
		}
		since = time.Now().Add(-d)
	}

	name := defaultGuardLog
	if flags.NArg() > 0 {
		name = flags.Arg(0)
	}
	var in io.Reader = os.Stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}
	if err := nginxReport(in, os.Stdout, since, *host, *n); err != nil {
		log.Fatal(err)
	}
}

func nginxReport(in io.Reader, out io.Writer, since time.Time, host string, n int) error {
	rules, clients, sites := map[string]int{}, map[string]int{}, map[string]int{}
	clientRules := map[string][]string{}
	var last []string
	total := 0

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := guardLogLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		ip, at, rule, site := m[1], m[2], m[4], m[5]
		if host != "" && !strings.EqualFold(site, host) {
			continue
		}
		if !since.IsZero() {
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", at)
			if err != nil || t.Before(since) {
				continue
			}
		}
		total++
		rules[rule]++
		clients[ip]++
		sites[site]++
		if !slices.Contains(clientRules[ip], rule) {
			clientRules[ip] = append(clientRules[ip], rule)
		}
		last = append(last, sc.Text())
		if len(last) > n {
			last = last[1:]
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}

	scope := "in the whole log"
	if !since.IsZero() {
		scope = "since " + since.Local().Format("2006-01-02 15:04")
	}
	fmt.Fprintf(out, "%d blocked requests %s, from %d clients, on %d sites\n", total, scope, len(clients), len(sites))
	if total == 0 {
		return nil
	}
	top := func(title string, counts map[string]int, extra func(string) string) {
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if a, b := counts[keys[i]], counts[keys[j]]; a != b {
				return a > b
			}
			return keys[i] < keys[j]
		})
		fmt.Fprintf(out, "\n%s:\n", title)
		for _, k := range keys[:min(len(keys), n)] {
			fmt.Fprintf(out, "  %7d  %s%s\n", counts[k], printable(k), extra(k))
		}
		if more := len(keys) - n; more > 0 {
			fmt.Fprintf(out, "           ... and %d more\n", more)
		}
	}
	none := func(string) string { return "" }
	top("by rule", rules, none)
	top("by client", clients, func(ip string) string { return "  (" + strings.Join(clientRules[ip], ", ") + ")" })
	if host == "" {
		top("by site", sites, none)
	}
	fmt.Fprintln(out, "\nlast requests:")
	for _, l := range last {
		fmt.Fprintf(out, "  %s\n", printable(truncate(l, 300)))
	}
	fmt.Fprintln(out, "\nWhy is a client blocked, or not? scanner-guard-agent ip IP")
	return nil
}
