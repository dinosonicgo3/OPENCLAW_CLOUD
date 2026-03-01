#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

RUNTIME_DIR="${OPENCLAW_RUNTIME_DIR:-$HOME/.openclaw-runtime}"
LAUNCH_LOCK_DIR="$RUNTIME_DIR/openclaw-launch.lock"
LAUNCH_PID_FILE="$RUNTIME_DIR/openclaw-launch.pid"
GATEWAY_MATCH_REGEX='openclaw-gateway|openclaw gateway'

cleanup_singleton() {
  rm -f "$LAUNCH_PID_FILE" >/dev/null 2>&1 || true
  rm -rf "$LAUNCH_LOCK_DIR" >/dev/null 2>&1 || true
}

acquire_singleton() {
  local existing
  mkdir -p "$RUNTIME_DIR"
  if ! mkdir "$LAUNCH_LOCK_DIR" >/dev/null 2>&1; then
    existing="$(cat "$LAUNCH_PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing" ] && kill -0 "$existing" >/dev/null 2>&1; then
      exit 0
    fi
    rm -rf "$LAUNCH_LOCK_DIR" >/dev/null 2>&1 || true
    mkdir "$LAUNCH_LOCK_DIR" >/dev/null 2>&1 || exit 1
  fi
  echo "$$" >"$LAUNCH_PID_FILE"
  trap 'cleanup_singleton' EXIT INT TERM HUP
}

terminate_other_gateways() {
  local pid
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    kill -TERM "$pid" >/dev/null 2>&1 || true
  done < <(pgrep -f "$GATEWAY_MATCH_REGEX" 2>/dev/null || true)
  sleep 1
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    kill -KILL "$pid" >/dev/null 2>&1 || true
  done < <(pgrep -f "$GATEWAY_MATCH_REGEX" 2>/dev/null || true)
}

acquire_singleton

ENV_FILE="${OPENCLAW_ENV_FILE:-$HOME/.openclaw/openclaw.env}"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi
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
terminate_other_gateways
"$OPENCLAW_BIN" gateway --allow-unconfigured >>"$HOME/openclaw-logs/gateway.log" 2>&1 &
gateway_pid="$!"
while kill -0 "$gateway_pid" >/dev/null 2>&1; do
  ts="$(date +%s)"
  printf '{"ts":%s,"pid":%s,"source":"cloud-openclaw-launch"}\n' "$ts" "$gateway_pid" > "${heartbeat_file}.tmp" || true
  mv -f "${heartbeat_file}.tmp" "$heartbeat_file" || true
  sleep 30
done
wait "$gateway_pid"
