# Changelog

All notable changes to `scanner-guard-agent` will be documented in this file.

## 2.2.0 - 2026-11-25

### New

- `scanner-guard-agent ip IP...` tells what the agent does with an address: the nftables element that blocks it, the local ban and its expiry (or that the block comes from the central app), the offenses per rule, and the `ignore` entry that covers it. Read-only, works with the agent stopped (#15).
  
  ```
  203.0.113.7
    blocked:   yes, ban4 { 203.0.113.7 timeout 1d expires 23h12m }
    local ban: until 2026-11-26 20:14 -0300 (23h12m0s left)
    offense:   web_attack #1, last 2026-11-25 20:14 -0300
    ignored:   no
  
  ```

### Fixed

- `nginx-test` counted sites as clients in logs that start with the site (`$server_name $remote_addr - ...`) (#14).

### Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/jeffersongoncalves/scanner-guard-agent/main/install.sh | sudo VERSION=2.2.0 sh
sudo systemctl restart scanner-guard-agent

```
No config change.

**Full Changelog**: https://github.com/jeffersongoncalves/scanner-guard-agent/compare/2.1.0...2.2.0

## 2.1.0 - 2026-11-25

### Changelog

* 2bf29bfd331f00b8cffc75f25644f690e6f16085: Update CHANGELOG (@jeffersongoncalves)
* 0d34ec285dc111e20471423dde9042552dc75024: Update CHANGELOG (@jeffersongoncalves)
* c7e50d620adf12b9da8e26f2344189c659df87df: Update CHANGELOG (@jeffersongoncalves)
* 54560525547eaf275539b9681fd8f7754bcf0094: Update CHANGELOG (@jeffersongoncalves)
* a15d2ad2f1cc8eb9da39a4dd1a3c64f1b8f89cc4: feat: honor an ignore list pulled from the central app (#12) (@jeffersongoncalves)
* 5f6dcd134f2ef2ffe14877698b4bbe6011442d51: feat: set up nginx to block common attacks (#11) (@jeffersongoncalves)
* 25804a9b114f68e251b49048f7adb64d2d874049: feat: verify the signature of the denylist response (#13) (@jeffersongoncalves)

## 2.0.0 - 2026-11-24

### Breaking change

- `central.url` must be `https` (plain `http` only for `localhost`, `127.0.0.0/8` and `::1`), redirects included. With a remote `http` URL the agent refuses to start, so switch it to `https` **before** updating (#9).

### New

- nginx and Apache denylists, for servers behind a proxy or CDN, where nftables only sees the proxy. Optional, nothing changes without `denylists` in the config (#7).
  - The new `scanner-guard-reload@<service>.path` unit reloads the web server when the list changes and retries a failed reload.
  - Restore the client IP and put the proxy ranges in `ignore` first, see the [README](https://github.com/jeffersongoncalves/scanner-guard-agent/blob/2.0.0/README.md#behind-a-proxy-or-cdn-nginx-and-apache-denylists).
  

### Fixed

- Two central bans for the same IP in different spellings: the latest expiry now wins (#7).

### Upgrade

```bash
sudo grep url /etc/scanner-guard/agent.yaml   # must be https or empty
curl -fsSL https://raw.githubusercontent.com/jeffersongoncalves/scanner-guard-agent/main/install.sh | sudo VERSION=2.0.0 sh
sudo systemctl restart scanner-guard-agent



```
**Full Changelog**: https://github.com/jeffersongoncalves/scanner-guard-agent/compare/1.1.0...2.0.0

## 1.1.0 - 2026-11-22

### Changelog

* 15027a43a02e1d0461b394a7942e4dcd2971f401: Create auto-assign.yml (@jeffersongoncalves)
* 3aadcceebfbc995f66d6dd246cdb139a58dbf045: Merge pull request #4 from jeffersongoncalves/feat/test-ban (@jeffersongoncalves)
* 9f07b0234224698b66b5d8cf9af1b19356284a67: feat: add test -ban to ban and report IPs from past logs (@jeffersongoncalves)
* 126a15e564b29e003c7526e3c64258995e78dd51: fix: create missing nftables table and retry failed bans on replay (@jeffersongoncalves)

## 1.0.1 - 2026-11-22

### Changelog

* 2e3166aee6a36d6f87173e721a9321b266627275: Merge pull request #3 from jeffersongoncalves/fix/docker-prerouting (@jeffersongoncalves)
* 2a66d7e8a37028c3dad03a7748c782cd40dc2102: fix: drop banned IPs in prerouting to cover Docker ports (@jeffersongoncalves)

## 1.0.0 - 2026-11-22

### Changelog

* 9be360b86faf42cf65dc499a50a25e7c92ab2af0: Merge pull request #1 from jeffersongoncalves/dependabot/github_actions/all-actions-a66a4e5de6 (@jeffersongoncalves)
* c39099d0a2e9b916f12d5c5fb3d1552d3e491c79: Merge pull request #2 from jeffersongoncalves/feat/persistent-state-and-heartbeat (@jeffersongoncalves)
* 4b3d8c49f58d949cf47a8c4eb3665dacc54956af: build(deps): Bump the all-actions group with 3 updates (@dependabot)
* 21ebe85a1b5480ef5a4543f1b11541b212f02139: feat: initial scanner-guard-agent (@jeffersongoncalves)
* 70a1a79b5def3ac392100faba17725d5b4f3668f: feat: persist escalation and local bans, send heartbeat (@jeffersongoncalves)
* de8f291890d846bf3a0848e6cf6df2ef30bb144f: fix: skip ignored and unrestorable bans on start (@jeffersongoncalves)
