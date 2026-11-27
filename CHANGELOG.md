# Changelog

All notable changes to `scanner-guard-agent` will be documented in this file.

## 2.8.1 - 2026-11-27

### Changelog

* d30c909441d0ac0655f21fe251a7111f4575e219: Update CHANGELOG (@github-actions[bot])
* 5fb754f2640bcc75634cb2eb6ff65ad98bdd29d6: fix: run nginx -t outside the service sandbox (#26) (@jeffersongoncalves)

## 2.8.0 - 2026-11-27

### Changelog

* 33b15f368c1f8c5230592a5979d3149e95ef57dc: Update CHANGELOG (@github-actions[bot])
* cb00b8e3c0c000ad07cba35ac8e36acf292c7f81: feat: optional nginx rules and diagnoses from the central app (#25) (@jeffersongoncalves)

## 2.7.0 - 2026-11-27

### Changelog

* 8b9438fef13618d90215939f0fdc8c56fbf081e2: Update CHANGELOG (@github-actions[bot])
* 01c94dba3850d7d486c842afe14ce3d0b57660ec: feat: add the diagnose command for clients that cannot connect (#24) (@jeffersongoncalves)
* 08e1b83f0cae1e18e7a2ef8ca6c5614b176cdff1: feat: add the monitor command and rules.d drop-in rules (#23) (@jeffersongoncalves)

## 2.6.0 - 2026-11-26

### Changelog

* d6643a6fc59aa9db7de65752f1256322de1e43c5: Update CHANGELOG (@github-actions[bot])
* 54c395785fe7a8485ea2b97ba1740a893a9b0364: feat: add report rules (events to the central app) and per-rule match counts in the heartbeat (#22) (@jeffersongoncalves)

## 2.5.0 - 2026-11-26

### Changelog

* 686c76f69c5c3af8999ed272a945fa9f0a377548: Update CHANGELOG (@github-actions[bot])
* 64968266f0ff56d8fdeca6efe54ba961e9277f3f: feat: take rule thresholds, windows and ban steps from the central app (#21) (@jeffersongoncalves)

## 2.4.0 - 2026-11-26

### Changelog

* 4d077c728fcea9f09452284bcb6e833ffb0f2278: Update CHANGELOG (@github-actions[bot])
* 41fe35daf0c70f2c77b18b377a395af1952d2b6a: feat: add nginx-enable/disable/sites/report, replay and status commands (#20) (@jeffersongoncalves)

## 2.3.0 - 2026-11-26

### Changelog

* a6ef79873859408eaeca982cd092008e7d8707f7: Update CHANGELOG (@github-actions[bot])
* 5c19777dcf99e2dadd49db644379d9d7ad97a3fe: feat: count pulled bans in the heartbeat's active_bans (#19) (@jeffersongoncalves)
* a9ef5841ec260afe04f092fba695bf4566cf40d9: feat: send the log lines that tripped a ban to the central app (#16) (@jeffersongoncalves)

## 2.2.2 - 2026-11-25

### Changelog

* 10758c290b0154f30a1b4b5f8c318dfcd6eb271e: Update CHANGELOG (@github-actions[bot])
* 4d91e1e85fdab0ceb6fb207e9764e13f8e3cc2ef: fix: end every nft script with a newline for nftables 0.8 (#18) (@jeffersongoncalves)

## 2.2.1 - 2026-11-25

### Changelog

* 6ed1526cc73f9827a2fe8ca09680573a05897577: Update CHANGELOG (@github-actions[bot])
* 3e776f38ab6f58d3457e40dde9ca844ebacd156f: fix: pass nft scripts through /dev/stdin for nftables before 0.9 (#17) (@jeffersongoncalves)

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
