![Scanner Guard Agent](https://raw.githubusercontent.com/jeffersongoncalves/scanner-guard-agent/main/art/jeffersongoncalves-scanner-guard-agent.png)

# Scanner Guard Agent

[![Tests](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/scanner-guard-agent/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/scanner-guard-agent/actions/workflows/tests.yml)
[![Release](https://img.shields.io/github/v/release/jeffersongoncalves/scanner-guard-agent?style=flat-square)](https://github.com/jeffersongoncalves/scanner-guard-agent/releases)
[![License](https://img.shields.io/github/license/jeffersongoncalves/scanner-guard-agent?style=flat-square)](LICENSE.md)

A small static Go binary for Linux servers. It watches logs (sshd, nginx, postfix, anything that
logs an IP), bans abusive IPs in nftables and reports every ban to a central
[`laravel-scanner-guard`](https://github.com/jeffersongoncalves/laravel-scanner-guard) app. It also
pulls the central denylist back, so an IP banned by any app or server is dropped on every server.

```
sshd / nginx / postfix logs ──► agent ──► nftables (local drop)
                                  │
                                  ├─ POST ban (HMAC) ──► central laravel-scanner-guard app
                                  └─ GET denylist (HMAC) ◄─┘   (bans from every app and server)
```

- No runtime dependencies: one binary (`CGO_ENABLED=0`), linux amd64 and arm64.
- Reads journald (through `journalctl`) or plain files, and follows logrotate and copytruncate.
- Generic rules: regex patterns with an `<ip>` placeholder, threshold, window and an escalation ladder.
- Uses its own nftables table (`inet scanner_guard`) and never touches your other rules. It coexists with fail2ban.
- Drops in `prerouting`, before Docker's DNAT, so a ban also covers published container ports.
- Optional nginx and Apache denylist files, for servers behind a proxy or CDN.
- `nginx-init` command sets up nginx to block common attacks itself: SQL injection, file inclusion, XSS, exposed files, login brute force. `nginx-enable` turns it on per site, tested and reverted if `nginx -t` fails; `nginx-report` sums up what it blocked.
- `replay` command runs the rules over the logs you already have, before anything gets banned (or bans the attackers in them).
- `status` and `ip` commands tell what is blocked on the server and why.

## Install

Script (checks the release checksum):

```bash
curl -fsSL https://raw.githubusercontent.com/jeffersongoncalves/scanner-guard-agent/main/install.sh | sudo sh
# pin a version: curl ... | sudo VERSION=1.0.0 sh
```

Or a package from the [releases](https://github.com/jeffersongoncalves/scanner-guard-agent/releases):

```bash
sudo dpkg -i scanner-guard-agent_1.0.0_linux_amd64.deb   # Debian / Ubuntu
sudo rpm -i  scanner-guard-agent_1.0.0_linux_amd64.rpm   # RHEL / Alma / Rocky
```

Requires `nftables` (`apt install nftables` / `dnf install nftables`) and systemd.

## Configure

Edit `/etc/scanner-guard/agent.yaml`, the [example config](packaging/agent.yaml) ships with an sshd rule:

```yaml
source: vps-01                 # name in the central ban table (default: hostname)
central:
  url: https://central.example.com/scanner-guard/bans
  secret_file: /etc/scanner-guard/secret
  pull_interval: 60s
firewall: nftables             # or "none" for a dry run
ignore: [203.0.113.10, 10.0.0.0/8]   # YOUR OWN IPs. 127.0.0.0/8 and ::1 are always ignored
rules:
  - name: ssh_bruteforce       # becomes the ban "reason" on the central app (max 30 chars)
    journald: [ssh.service, sshd.service]   # or: file: /var/log/auth.log
    patterns:
      - 'Failed (password|publickey) for (invalid user )?\S+ from <ip> port'
      - 'Invalid user \S* from <ip> port'
    threshold: 5
    window: 10m
    ban: [1d, 7d, 30d]         # 1st, 2nd, 3rd+ offense
```

> **Warning:** put the IPs you administer the server from in `ignore` before you start the agent.
> Otherwise a few mistyped passwords lock you out. Start with `firewall: none` to watch what it
> would ban.

Run the rules over the logs you already have first. Each rule reads its own source: journald since
`-since` (7 days by default), a `file` rule the whole file. Nothing is banned:

```bash
sudo scanner-guard-agent replay                       # who would be banned, per rule
sudo scanner-guard-agent replay -rule ssh_bruteforce -since 1d
```

Add `-ban` to also ban what the replay found: each IP over the threshold gets the next escalation
step, is blocked in nftables and reported to the central app. Use it once on install to catch the
attacks already in the logs. A running agent is stopped meanwhile and started again (both write the
same state file):

```bash
sudo scanner-guard-agent replay -ban
```

The window is ignored here, so hits spread over the whole period count together. Narrow
`-since` if that bans too much. `test` does the same with a log you pass yourself
(`journalctl ... | scanner-guard-agent test [-ban] -`).

Then start it:

```bash
sudo systemctl enable --now scanner-guard-agent
journalctl -u scanner-guard-agent -f
```

## Central app

The agent speaks the `http` driver protocol of `laravel-scanner-guard`. On the central app
(`database` driver):

```dotenv
SCANNER_GUARD_HTTP_SERVER_ENABLED=true
SCANNER_GUARD_HTTP_SECRET=a-long-random-shared-secret
```

On the server, store the same secret (or a per-source one from `http.secrets`):

```bash
echo 'a-long-random-shared-secret' | sudo tee /etc/scanner-guard/secret >/dev/null
sudo chmod 600 /etc/scanner-guard/secret
```

Each ban is POSTed with `reason` = rule name, `source` = `source`, `matched_value` = the pattern
that matched, `hit_count`, `offense`, `banned_at`, `expires_at` and `evidence` = the last log lines
that tripped the rule (up to 20, 512 bytes each, the banned IP replaced by `<ip>`; a central app that
doesn't know the field ignores it), signed as `X-Signature: hmac_sha256(X-Timestamp . body, secret)`. It then shows up in
the central ban table, the daily stats and the central denylist sinks (Cloudflare, nginx, ...):

```php
ScannerGuardBan::query()->where('source', 'vps-01')->where('reason', 'ssh_bruteforce')->get();
```

Every `pull_interval` the agent GETs the central denylist (active bans plus `ip_blocklist`) and
syncs it into nftables. It adds new entries and lifts the ones the central app no longer lists,
except bans this agent made itself. `central.url` must be `https` (plain `http` only for localhost):
the pulled list holds raw IPs. The agent refuses to start otherwise, and never follows a redirect to
`http`.

The central app signs the response with the source's secret, bound to the request it answers. A wrong
signature, or a timestamp more than 5 minutes from this server's clock, fails the pull and keeps the
last list. An unsigned response (older `laravel-scanner-guard`) is accepted by default. Once the central
app signs, refuse it, or whoever terminates TLS could strip the signature:

```yaml
central:
  require_signed_response: true
```

The response may also carry `ignore`, a list of IPs and CIDRs no server should ban, added to the
`ignore` of `agent.yaml` (which always applies). The agent pulls it before it starts watching the logs,
so a new server has it before its first ban. It lifts local bans the list covers, and keeps the list in
the state file for when the central app is down. An empty list clears it, a response without the key
leaves it as is. Ranges wider than /8 (IPv4) or /16 (IPv6) are refused. It needs a central app that
sends it (`ip_ignore` in `laravel-scanner-guard`).

> **Warning:** whoever can change the response can add entries to `ignore`. See
> [#8](https://github.com/jeffersongoncalves/scanner-guard-agent/issues/8), signing the response.

It may also carry `agent_rules`: a `threshold`, `window` and `ban` steps (in seconds) per rule
name, set once on the central app for every server (`ScannerGuardAgentRule` in
`laravel-scanner-guard`, a page in `filament-scanner-guard`):

```json
"agent_rules": {"web_attack": {"threshold": 5, "window": 600, "ban": [86400, 604800, 2592000]}}
```

They replace those three values of the rule with that name, within a pull interval, and the agent
logs each change (`rule web_attack: 5 in 10m, ban 1d/7d/30d (from the central app)`). The patterns
and the log a rule reads always come from `agent.yaml`. A rule the central app leaves out, or sends
invalid, uses `agent.yaml`'s values, so an empty object puts every rule back. A response without the
key keeps the last settings, which the state file holds across restarts. An IP keeps its offense
count when the steps change: its next ban takes the new step for that count. `status` marks the
rules set by the central app, and `replay` counts with the same values as the running agent.

Two more keys, from `laravel-scanner-guard` 2.8.0: `nginx_rules`, the [optional nginx
rules](#optional-rules) to turn on (`["cms"]`; absent: keep the last ones), and `diagnostics`, the
[diagnoses](#a-client-cannot-connect) to run (`[{"id": 7, "ip": "203.0.113.7", "capture": 60}]`).

After each pull the agent also POSTs a signed heartbeat to `<central.url>/heartbeat` (`source`,
`version`, `rules`, `active_bans`, `started_at`, `matches`). `active_bans` counts everything the firewall
blocks: this server's bans plus the pulled ones (before 2.3.0: only its own). `matches` counts the
matching lines per rule since the last heartbeat that got through (ignored IPs left out, except on
report rules), so the central app can chart the attacks per server. On the central app, run the
`create_scanner_guard_agents_table` migration, then spot dead servers with
`ScannerGuardAgent::query()->offline()->get()`. Central versions without the endpoint answer
`404`. The agent logs that and keeps working.

### Report rules (events, no bans)

A rule with `report: true` never bans: each match is logged and sent to `<central.url>/events`, so
the central app can tell when something worth knowing happens, an SSH login from a new IP or with a
new key, say. Named groups in the patterns, other than `<ip>`, become the event's fields:

```yaml
  - name: ssh_login
    journald: [ssh.service, sshd.service]
    report: true # no threshold, window or ban
    patterns:
      - 'Accepted (?P<method>\S+) for (?P<user>\S+) from <ip> port \d+ ssh2(?:: \S+ (?P<key>SHA256:\S+))?'
```

The event carries `source`, `rule`, `ip`, `pattern`, `fields` (`{"method": "publickey", "user":
"deploy", "key": "SHA256:..."}`), `line` (the log line, the IP replaced by `<ip>`), `ignored` (the IP
is on an ignore list: sent anyway, a new key logging in from the office is still news) and `at`. The
same event (rule, IP and fields) goes out at most once a day, so a login every minute is one event,
not 1440. A central app without the endpoint answers `404`: the agent logs that once and keeps the
events in its own log only. `replay` and `test` list what a report rule matches, never as bans.

Ready-made monitors switch on and off without editing `agent.yaml`:

```bash
sudo scanner-guard-agent monitor                 # the monitors, on or off
sudo scanner-guard-agent monitor ssh-logins on   # the ssh_login rule above
sudo scanner-guard-agent monitor ssh-logins off
```

`on` writes the rule to `rules.d/ssh_login.yaml` next to the config (left out again if the config no
longer loads with it), `off` deletes it, and both restart a running agent (`-no-restart` to skip).
Every `rules.d/*.yaml` file adds its `rules:` to the config's, so hand-written rules can live there
too. A monitor whose rule is already in `agent.yaml` is reported as on; turn that one off there.

Without `central.url` the agent runs standalone and only bans locally.

## Behind a proxy or CDN: nginx and Apache denylists

Behind Cloudflare or a load balancer, nftables only sees the proxy's IP, so it can't block the
visitor. The agent can also write this server's active bans (its own plus the pulled ones) to a web
server config file:

```yaml
ignore: [203.0.113.10, 173.245.48.0/20]   # your own IPs AND every proxy/CDN range
denylists:
  - format: nginx                         # nginx | apache
    path: /var/lib/scanner-guard/nginx-deny.conf
```

> **Warning:** restore the client IP first (below) and put the proxy ranges in `ignore`. Otherwise the
> access log holds the proxy's IP, and a rule on it bans the proxy itself. Trust only the proxy's
> ranges, or anyone can forge the header.

nginx, e.g. `/etc/nginx/conf.d/scanner-guard.conf` (covers every site):

```nginx
set_real_ip_from 173.245.48.0/20;   # repeat for every proxy range
real_ip_header CF-Connecting-IP;
include /var/lib/scanner-guard/nginx-deny*.conf;
```

A `server` or `location` with its own `allow`/`deny` doesn't inherit the list, repeat the `include`
there.

Apache 2.4 (`mod_remoteip`), at the end of each virtual host, with `format: apache` and the path
`/var/lib/scanner-guard/apache2-deny.conf` (`httpd-deny.conf` on RHEL / Alma / Rocky):

```apache
RemoteIPHeader CF-Connecting-IP
RemoteIPTrustedProxy 173.245.48.0/20

<Location "/">
    AuthMerging And
    # Debian / Ubuntu
    IncludeOptional /var/lib/scanner-guard/apache2-deny*.conf
    # RHEL / Alma / Rocky: use this line instead
    # IncludeOptional /var/lib/scanner-guard/httpd-deny*.conf
</Location>
```

Keep `AuthMerging And`: without it, the list's `Require all granted` replaces your own rules. Also log
the restored IP: `%a` instead of `%h` in `LogFormat`.

Then reload the web server whenever the list changes. The unit's instance is the service name, and it
watches `/var/lib/scanner-guard/<service>-deny.conf`:

```bash
sudo systemctl restart scanner-guard-agent
sudo systemctl enable --now scanner-guard-reload@nginx.path     # or @apache2.path, @httpd.path
sudo systemctl reload nginx
```

- The file is checked every 10s and only rewritten when its content changes. Expired bans are removed.
- After a restart the previous list stays until the first pull succeeds (5 minutes at most).
- While the agent is stopped the list is frozen, expired bans included.
- A failed reload is retried every 30s until it works.
- `firewall: none` is a dry run and doesn't write the files. An existing one keeps blocking.
- To stop using a denylist, in this order: remove its `denylists` entry, restart the agent (it would
  recreate the file otherwise), delete the file, reload the web server.
- The systemd sandbox only allows `/var/lib/scanner-guard`. Any other path needs a `ReadWritePaths=`
  drop-in, and your own reload unit.

## Block attacks in nginx

The agent reads logs, so it only acts after a request was served. nginx can refuse the request itself:

```bash
sudo scanner-guard-agent nginx-init                                # -dir for another /etc/nginx
sudo scanner-guard-agent nginx-test /var/log/nginx/access.log      # what the rules would have blocked
```

Behind a proxy or CDN, also pass `-proxy`, with `cloudflare`, IPs or CIDRs (the whole chain, e.g.
`-proxy cloudflare,172.18.0.0/16`). It restores the client IP in nginx and prints the `ignore` line for
`agent.yaml`. Skip it if your config already has a `real_ip_header`: nginx accepts only one.

`nginx-init` never overwrites a file, so they are yours to adjust:

| File in `/etc/nginx` | What it holds |
|------|---------------|
| `conf.d/scanner-guard-rules.conf` | exceptions (paths) and rules, one per line |
| `conf.d/scanner-guard-realip.conf` | client IP behind a proxy (only with `-proxy`) |
| `scanner-guard/server.conf` | the 403 and its log |
| `scanner-guard/login.conf` | login rate limit (optional) |

| Rules | Catch |
|-------|-------|
| `sqli-*` | SQL injection: `UNION SELECT`, `' or 1=1`, `sleep(5)`, `information_schema` |
| `traversal`, `lfi`, `nullbyte`, `wrapper` | `../../`, `/etc/passwd`, `%00`, `php://filter` |
| `command`, `code`, `phpini`, `object`, `globals`, `jndi` | `;wget http`, `system(`, `-d allow_url_include`, serialized objects |
| `xss` | `<script>`, `onerror=`, `javascript:` |
| `dotfile`, `backup`, `config`, `probe` | `.env`, `.git`, `dump.sql`, `config.php.bak`, `composer.lock`, web shells |
| `upload-php` | PHP inside `uploads`, `tmp`, `temp` or `cache` |
| `scanner`, `shellshock` | User-Agents: sqlmap, nikto, nuclei, ... |
| `encoded`, `rfi`, `cms`, `empty-agent` | stricter, off: see [Optional rules](#optional-rules) |

Run `nginx-test` on a few days of logs. On a false positive, add the path to the exceptions or comment
the rule out, and test again. Then turn the rules on per site, by `server_name`:

```bash
sudo scanner-guard-agent nginx-sites                          # every site, 403 on or off
sudo scanner-guard-agent nginx-enable example.com shop.test   # on
sudo scanner-guard-agent nginx-disable example.com            # off again
```

`nginx-enable` adds `include scanner-guard/server.conf;` before the `server_name` of every server block
of those sites (in `sites-enabled/*` and `conf.d/*.conf`, symlinks followed), runs `nginx -t` and puts
every file back if it fails, reloads nginx once, then asks each site for an attack and for `/` on the
port it listens on (https when it has `listen 443`/`ssl`). The attack must get `403`; the page should
answer as before. On a [Laravel Forge](https://forge.laravel.com) site the include goes to
`forge-conf/<id>/server/scanner-guard.conf` instead, which Forge leaves alone when it rewrites the
site file. Sites with a regex `server_name`, or an include the commands don't see, take it by hand,
before the block's own `if`/`rewrite`/`return`:

```nginx
include scanner-guard/server.conf;
include scanner-guard/login.conf;   # optional
```

The catch-all (the `default_server` answering an unknown host or the bare IP, usually with `return
444`) is a site like the others: `nginx-enable _`. Scanners probing the IP then get the `403` and go to
the log when a rule matches; every other request keeps its `444` and stays out of it. Don't point an
`access_log` of the catch-all at `scanner-guard.log` by hand: every request would count as an attack.

### Optional rules

`cms`, `rfi`, `encoded` and `empty-agent` block more, with more false positives, so they ship off.
Check one against your logs first:

```bash
sudo scanner-guard-agent nginx-test -with cms /var/log/nginx/access.log
```

Then turn it on for every server from the central app (`nginx_rules` in the pull, a page in
`filament-scanner-guard`, with exceptions per server). The central app only sends names: the rules
ship with the agent, which writes the ones turned on to `/var/lib/scanner-guard/nginx/{uri,path,agent}.conf`,
runs `nginx -t` and reloads, or puts the previous files back. The maps of `scanner-guard-rules.conf`
include those files; on a rules file written before 2.8.0, run `nginx-init` once to add the includes
(tested, reverted if `nginx -t` fails). Don't also uncomment the rule in `scanner-guard-rules.conf`: it
would be listed twice. Without a central app, uncomment it there instead.

What the rules blocked, per rule, client and site (the last 24 hours by default):

```bash
sudo scanner-guard-agent nginx-report
sudo scanner-guard-agent nginx-report -since 7d -host example.com
```

Blocked requests get a `403` and go to `/var/log/nginx/scanner-guard.log` with the name of the rule,
instead of the site's access log. Login POSTs above the rate get a `429`, on the paths listed in
`scanner-guard-rules.conf` (a route in the query string, as in `index.php?r=login`, isn't seen). A
`location` with its own `limit_req` doesn't inherit the login limit, repeat the `include`'s `limit_req`
line there.

To also ban who insists, add to `agent.yaml` and restart the agent
(`sudo systemctl restart scanner-guard-agent`):

```yaml
  - name: web_attack
    file: /var/log/nginx/scanner-guard.log
    patterns: ['^<ip> - \[']
    threshold: 3
    window: 10m
    ban: [1d, 7d, 30d]
  - name: web_login
    file: /var/log/nginx/access.log          # the site's own log
    patterns: ['^<ip> - \S+ \[[^\]]+\] "POST [^"]*" 429 ']
    threshold: 20
    window: 10m
    ban: [1h, 1d, 7d]
```

> **Warning:** behind a proxy or CDN, run `nginx-init -proxy` and put the proxies in `ignore` before
> enabling these rules or `login.conf`. Otherwise the log holds the proxy's IP, the agent bans the
> proxy, and every visitor shares one login limit.

This is a filter for common probes, not a WAF, and it doesn't fix a vulnerable application:

- Only the path, query string and User-Agent are checked: not the POST body, cookies or other headers.
- Percent-encoded letters (`%55NION`), comments with text (`union/*x*/select`) and more than 40
  separators in a row get through. The `encoded` rule covers the first.
- Use bound parameters in the application. For the rest, ModSecurity or Coraza with the OWASP CRS.
- The logrotate rule of the nginx package covers the log, as long as it rotates `/var/log/nginx/*.log`.
- To get the rules of a newer version, move `conf.d/scanner-guard-rules.conf` away, run `nginx-init` and bring
  your changes over.
- To undo: `nginx-disable` every site (or remove the `include` lines), delete the files, reload nginx.
  Remove the agent rules and restart the agent.
- `nginx-test` reads the request line and User-Agent of the combined format, also with the site in front
  (`$server_name $remote_addr - ...`), told apart by where the `-` falls. It reads the optional rules
  through their absolute `include`, fails on rules it can't run (another `include`, lookaheads) instead
  of skipping them, and doesn't cover the login limit.

## Manage bans

```bash
scanner-guard-agent status                                          # service, central, blocked count, rules, last bans
scanner-guard-agent ip 203.0.113.7                                  # blocked? local ban, offenses, ignored?
nft list table inet scanner_guard                                   # everything blocked
nft delete element inet scanner_guard ban4 '{ 203.0.113.7 }'        # unban now (ban6 for IPv6)
```

A ban that also came from the central app is re-added on the next pull. Unban it there instead
(`ScannerGuard::unban()`).

`nft delete` doesn't touch the nginx/Apache denylists. To lift a local ban from those too, add the IP
to `ignore` and restart the agent.

### A client cannot connect

```bash
sudo scanner-guard-agent diagnose 203.0.113.7               # read-only
sudo scanner-guard-agent diagnose -capture 60s 203.0.113.7  # also watch its packets while the client tries
```

`diagnose` looks for the IP everywhere a server can drop it, not only in the agent: the agent's own
table, the rest of the nftables ruleset, iptables (`-save`, legacy too), ipset, fail2ban jails,
`hosts.deny`/csf/apf, the agent's nginx/Apache denylists and the nginx 403 rules' log. Then it
checks whether the IP's traffic shows up at all (current nginx/Apache access logs, journald for
`-since`, default `24h`), the route, `ping` and `mtr`/`tracepath` from the server to the IP, and,
with `-capture`, `tcpdump` on every interface. It ends with a verdict:

- **blocked on this server by ...**: unblock it there;
- **nothing blocks it, its packets arrive**: look at the application (TLS, the site's own rules);
- **nothing blocks it, no packet arrived while capturing**: the traffic stops before the server
  (client network, ISP, the datacenter's firewall or DDoS protection).

An ACCEPT rule mentioning the IP is listed but not counted as a block. Missing tools are skipped.

The central app can ask for the same report on one server or all of them (`diagnostics` in the pull,
a panel action in `filament-scanner-guard`): within a pull interval each agent runs `diagnose` on the
IP, with a `tcpdump` capture of up to 120s if asked, and POSTs the report, signed, to
`<central.url>/diagnostics`. One diagnosis runs at a time. The central app only sends an IP and a
capture length, never a command. To refuse them on a server, set `central.diagnose: false`: the agent
then answers each request with that.

## State and restarts

The agent keeps its escalation steps and the local bans still running in `state_file` (default
`/var/lib/scanner-guard/state.json`, created by the systemd unit's `StateDirectory`). On start it
recreates its nftables table, re-applies those bans for their remaining time, and the first pull
brings back the central ones. An escalation step is forgotten once the IP has had no ban for
`escalation_lookback` (default `365d`), and the ladder starts over:

```yaml
state_file: /var/lib/scanner-guard/state.json
escalation_lookback: 365d
```

A corrupt state file is logged and replaced by an empty one, so it never keeps the agent down.

## Notes and limits

- Line timestamps are not parsed: the window is measured on arrival time.
- Hit counters (below the threshold) live in memory and start from zero after a restart.

## Build

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/scanner-guard-agent .
go test ./...
```

Releases are built by GoReleaser on a tag push (`.goreleaser.yaml`): tar.gz, `.deb`, `.rpm` and
`checksums.txt` for linux amd64/arm64.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
