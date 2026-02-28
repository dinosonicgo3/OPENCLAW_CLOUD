#!/usr/bin/env bash
set -euo pipefail

HOME_DIR="${HOME:-/home/ubuntu}"
CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME_DIR/.openclaw/openclaw.json}"
ENV_FILE="${OPENCLAW_ENV_FILE:-$HOME_DIR/.openclaw/openclaw.env}"
LOG_FILE="${OPENCLAW_GATEWAY_LOG:-$HOME_DIR/openclaw-logs/gateway.log}"
STATE_DIR="${OPENCLAW_SUBAGENT_MONITOR_STATE_DIR:-$HOME_DIR/.openclaw-subagent-monitor}"
STATE_FILE="$STATE_DIR/state.json"
ALERT_COOLDOWN_SECONDS="${OPENCLAW_SUBAGENT_ALERT_COOLDOWN_SECONDS:-90}"
STARTUP_NOTIFY="${OPENCLAW_SUBAGENT_MONITOR_STARTUP_NOTIFY:-0}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/openclaw-logs"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

if [ -z "$TELEGRAM_OWNER_ID" ] && [ -f "$CONFIG_PATH" ]; then
  TELEGRAM_OWNER_ID="$(jq -r '.channels.telegram.allowFrom[0] // empty' "$CONFIG_PATH" 2>/dev/null || true)"
fi

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [subagent-sentinel] %s\n' "$ts" "$*" >>"$HOME_DIR/openclaw-logs/subagent-sentinel.log"
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_alert_key": "",
  "last_alert_ts": 0
}
EOF
  fi
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE" 2>/dev/null || echo ""
}

state_set() {
  local expr="$1"
  local tmp
  tmp="$(mktemp)"
  jq "$expr" "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

send_telegram() {
  local msg="$1"
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

model_info() {
  if [ ! -f "$CONFIG_PATH" ]; then
    echo "primary=unknown subagent=unknown fallbacks=[]"
    return 0
  fi
  local primary submodel fallbacks
  primary="$(jq -r '.agents.defaults.model.primary // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  submodel="$(jq -r '.agents.defaults.subagents.model // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  fallbacks="$(jq -c '.agents.defaults.model.fallbacks // []' "$CONFIG_PATH" 2>/dev/null || echo '[]')"
  echo "primary=${primary} subagent=${submodel} fallbacks=${fallbacks}"
}

is_benign_line() {
  local line="$1"
  printf '%s' "$line" | grep -Eiq 'sessions_spawn tool start|sessions_spawn tool end|waiting for run end: .*timeoutMs=|timeoutMs='
}

detect_reason() {
  local line="$1"
  local low
  low="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$low" | grep -Eq 'sessions_spawn' && printf '%s' "$low" | grep -Eq 'error|failed|iserror=true'; then
    echo "sessions-spawn-failed"
    return 0
  fi
  if printf '%s' "$low" | grep -Eq 'lane task error: lane=subagent.*timed out|subagent.*timed out'; then
    echo "subagent-timeout"
    return 0
  fi
  if printf '%s' "$low" | grep -Eq 'subagent' && printf '%s' "$low" | grep -Eq 'unauthorized|token_mismatch|forbidden'; then
    echo "subagent-auth-failed"
    return 0
  fi
  if printf '%s' "$low" | grep -Eq 'subagent' && printf '%s' "$low" | grep -Eq 'error|failed|panic|exception'; then
    echo "subagent-failed"
    return 0
  fi
  echo ""
}

maybe_alert_line() {
  local line="$1"
  local reason now key last_key last_ts info
  [ -n "$line" ] || return 0
  if is_benign_line "$line"; then
    return 0
  fi
  reason="$(detect_reason "$line")"
  [ -n "$reason" ] || return 0

  now="$(date +%s)"
  key="$(printf '%s|%s' "$reason" "$line" | sha1sum | awk '{print $1}')"
  last_key="$(state_get '.last_alert_key // ""')"
  last_ts="$(state_get '.last_alert_ts // 0')"
  [ -n "$last_ts" ] || last_ts=0
  if [ "$key" = "$last_key" ] && [ "$((now - last_ts))" -lt "$ALERT_COOLDOWN_SECONDS" ]; then
    return 0
  fi

  info="$(model_info)"
  send_telegram "🚨 主系統子代理告警：${reason}
- ${info}
- 摘要：$(printf '%s' "$line" | sed -E 's/[[:space:]]+/ /g' | cut -c1-220)"
  log "alert reason=${reason} key=${key} line=$(printf '%s' "$line" | cut -c1-220)"
  state_set ".last_alert_key=\"${key}\" | .last_alert_ts=${now}"
}

monitor_loop() {
  touch "$LOG_FILE"
  tail -n 0 -F "$LOG_FILE" 2>/dev/null | while IFS= read -r line; do
    maybe_alert_line "$line"
  done
}

main() {
  state_init
  if [ "$STARTUP_NOTIFY" = "1" ]; then
    send_telegram "🧭 主系統子代理監控已啟動（雙層監控：主系統+Nanobot）。"
  fi
  log "started, log_file=$LOG_FILE, cooldown=${ALERT_COOLDOWN_SECONDS}s"
  monitor_loop
}

main "$@"
