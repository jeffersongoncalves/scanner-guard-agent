#!/bin/sh
systemctl daemon-reload >/dev/null 2>&1 || true
echo "scanner-guard-agent installed. Edit /etc/scanner-guard/agent.yaml (set ignore!), then:"
echo "  systemctl enable --now scanner-guard-agent"
