# Changelog

All notable changes to `scanner-guard-agent` will be documented in this file.

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
