#!/bin/sh
# Installs scanner-guard-agent from a GitHub release.
#   curl -fsSL https://raw.githubusercontent.com/jeffersongoncalves/scanner-guard-agent/main/install.sh | sudo sh
#   VERSION=1.0.0 sh install.sh   # pin a version
set -eu

REPO=jeffersongoncalves/scanner-guard-agent
VERSION=${VERSION:-latest}
BIN=/usr/local/bin/scanner-guard-agent

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
  [ -n "$VERSION" ] || { echo "could not find the latest release" >&2; exit 1; }
fi

NAME="scanner-guard-agent_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "downloading $NAME"
curl -fsSL -o "$TMP/$NAME" "$BASE/$NAME"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt"
(cd "$TMP" && grep "  $NAME\$" checksums.txt | sha256sum -c -)

tar -xzf "$TMP/$NAME" -C "$TMP"
install -m 0755 "$TMP/scanner-guard-agent" "$BIN"

install -d -m 0700 /etc/scanner-guard
[ -f /etc/scanner-guard/agent.yaml ] || install -m 0600 "$TMP/packaging/agent.yaml" /etc/scanner-guard/agent.yaml

sed "s#/usr/bin/scanner-guard-agent#$BIN#" "$TMP/packaging/scanner-guard-agent.service" \
  > /etc/systemd/system/scanner-guard-agent.service
install -m 0644 "$TMP"/packaging/scanner-guard-reload@.path "$TMP"/packaging/scanner-guard-reload@.service /etc/systemd/system/
systemctl daemon-reload

command -v nft >/dev/null 2>&1 || echo "warning: nft not found, install the nftables package" >&2

cat <<EOF
installed $("$BIN" version) to $BIN

next:
  1. edit /etc/scanner-guard/agent.yaml (put your own IP in ignore)
  2. optional central app: echo 'shared-secret' > /etc/scanner-guard/secret && chmod 600 /etc/scanner-guard/secret
  3. systemctl enable --now scanner-guard-agent
  4. journalctl -u scanner-guard-agent -f
EOF
