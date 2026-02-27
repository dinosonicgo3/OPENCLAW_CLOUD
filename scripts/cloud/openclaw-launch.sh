#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
mkdir -p "$HOME/openclaw-logs" "$HOME/.openclaw-watchdog"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$HOME/cloud/openclaw-coreguard.sh}"
if [ -f "$CORE_GUARD_SCRIPT" ]; then
  HOME="$HOME" OPENCLAW_CONFIG_PATH="$HOME/.openclaw/openclaw.json" \
    bash "$CORE_GUARD_SCRIPT" --fix >>"$HOME/openclaw-logs/core-guard.log" 2>&1 || true
fi
heartbeat_file="$HOME/.openclaw-watchdog/openclaw-heartbeat.json"
OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [ -z "$OPENCLAW_BIN" ] && [ -x "$HOME/.npm-global/bin/openclaw" ]; then
  OPENCLAW_BIN="$HOME/.npm-global/bin/openclaw"
fi
"$OPENCLAW_BIN" gateway --allow-unconfigured >>"$HOME/openclaw-logs/gateway.log" 2>&1 &
gateway_pid="$!"
while kill -0 "$gateway_pid" >/dev/null 2>&1; do
  ts="$(date +%s)"
  printf '{"ts":%s,"pid":%s,"source":"cloud-openclaw-launch"}\n' "$ts" "$gateway_pid" > "${heartbeat_file}.tmp" || true
  mv -f "${heartbeat_file}.tmp" "$heartbeat_file" || true
  sleep 30
done
wait "$gateway_pid"
