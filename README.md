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
- `test` command replays a log through the rules before anything gets banned.

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

Test a rule against real logs first:

```bash
journalctl -u ssh -u sshd --since -1d -o cat | scanner-guard-agent test -
scanner-guard-agent test -rule nginx_scanner /var/log/nginx/access.log
```

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
that matched (never the log line, which holds the raw IP), `hit_count`, `offense`, `banned_at` and
`expires_at`, signed as `X-Signature: hmac_sha256(X-Timestamp . body, secret)`. It then shows up in
the central ban table, the daily stats and the central denylist sinks (Cloudflare, nginx, ...):

```php
ScannerGuardBan::query()->where('source', 'vps-01')->where('reason', 'ssh_bruteforce')->get();
```

Every `pull_interval` the agent GETs the central denylist (active bans plus `ip_blocklist`) and
syncs it into nftables. It adds new entries and lifts the ones the central app no longer lists,
except bans this agent made itself. Use an `https` URL: the pulled list holds raw IPs and isn't
signed.

Without `central.url` the agent runs standalone and only bans locally.

## Manage bans

```bash
nft list table inet scanner_guard                                   # everything blocked
nft delete element inet scanner_guard ban4 '{ 203.0.113.7 }'        # unban now (ban6 for IPv6)
```

A ban that also came from the central app is re-added on the next pull. Unban it there instead
(`ScannerGuard::unban()`).

## Notes and limits

- Restarting the agent recreates its nftables table. The first pull restores the central bans, but
  local-only bans (standalone mode) are lost.
- Escalation counters live in memory, so they restart at the first step after an agent restart.
- Line timestamps are not parsed: the window is measured on arrival time.

## Build

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/scanner-guard-agent .
go test ./...
```

Releases are built by GoReleaser on a tag push (`.goreleaser.yaml`): tar.gz, `.deb`, `.rpm` and
`checksums.txt` for linux amd64/arm64.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
