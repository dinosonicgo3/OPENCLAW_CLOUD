#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

NANOBOT_NAME="${NANOBOT_NAME:-run-tian-xie}"
NANOBOT_VERSION="1.1.0"

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME_DIR/DINO_OPENCLAW}"
STATE_DIR="${NANOBOT_STATE_DIR:-$HOME_DIR/.openclaw-nanobot}"
STATE_FILE="$STATE_DIR/state.json"
ENV_FILE="${NANOBOT_ENV_FILE:-$HOME_DIR/.openclaw-nanobot.env}"
LOG_FILE="${NANOBOT_LOG_FILE:-$HOME_DIR/openclaw-logs/nanobot.log}"

WATCHDOG_SCRIPT="${WATCHDOG_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-watchdog.sh}"
CORE_GUARD_SCRIPT="${CORE_GUARD_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-core-guard.sh}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME_DIR/.termux/boot/openclaw-launch.sh}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
NANOBOT_MODEL="${NANOBOT_MODEL:-z-ai/glm4.7}"
NANOBOT_BASE_URL="${NANOBOT_BASE_URL:-https://integrate.api.nvidia.com/v1}"
NANOBOT_ENABLED="${NANOBOT_ENABLED:-0}"

POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-15}"
HEALTHCHECK_INTERVAL_SECONDS="${HEALTHCHECK_INTERVAL_SECONDS:-300}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-35}"
AUTO_RESCUE_ON_UNHEALTHY="${AUTO_RESCUE_ON_UNHEALTHY:-1}"
NANOBOT_STARTUP_GRACE_SECONDS="${NANOBOT_STARTUP_GRACE_SECONDS:-600}"
NANOBOT_FAIL_THRESHOLD="${NANOBOT_FAIL_THRESHOLD:-3}"
NANOBOT_RESCUE_COOLDOWN_SECONDS="${NANOBOT_RESCUE_COOLDOWN_SECONDS:-900}"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [nanobot] %s\n' "$ts" "$*" >>"$LOG_FILE"
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_update_id": 0,
  "last_healthcheck_ts": 0,
  "started_at": 0,
  "consecutive_health_failures": 0,
  "last_action_ts": 0,
  "last_action": "",
  "last_reason": ""
}
EOF
  fi
  state_migrate
}

state_migrate() {
  local tmp
  tmp="$(mktemp)"
  jq '
    .last_update_id = (.last_update_id // 0) |
    .last_healthcheck_ts = (.last_healthcheck_ts // 0) |
    .started_at = (.started_at // 0) |
    .consecutive_health_failures = (.consecutive_health_failures // 0) |
    .last_action_ts = (.last_action_ts // 0) |
    .last_action = (.last_action // "") |
    .last_reason = (.last_reason // "")
  ' "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE"
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

openclaw_healthy() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${HEALTH_TIMEOUT_SECONDS}s" openclaw health --json --timeout 12000 >/dev/null 2>&1
  else
    openclaw health --json --timeout 12000 >/dev/null 2>&1
  fi
}

restart_openclaw() {
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script missing: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$OPENCLAW_BOOT_SCRIPT"
  sleep 8
  openclaw_healthy
}

structured_rescue_action() {
  local health_state prompt payload resp content action reason
  action="watchdog_rescue"
  reason="default-policy"

  if [ -z "$NVIDIA_API_KEY" ]; then
    printf '%s\t%s\n' "$action" "$reason"
    return 0
  fi

  health_state="unhealthy"
  if openclaw_healthy; then
    health_state="healthy"
  fi

  prompt="OpenClaw state=${health_state}. Choose one action to recover safely.
Allowed actions:
1) none
2) coreguard_restart
3) watchdog_rescue
Return only JSON object with keys: action, reason."

  payload="$(jq -n --arg model "$NANOBOT_MODEL" --arg prompt "$prompt" '
    {
      model: $model,
      temperature: 0,
      messages: [
        {
          role: "system",
          content: "You are a rescue planner. Output strict JSON only."
        },
        {
          role: "user",
          content: $prompt
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "rescue_plan",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              action: {
                type: "string",
                enum: ["none","coreguard_restart","watchdog_rescue"]
              },
              reason: { type: "string" }
            },
            required: ["action","reason"]
          }
        }
      }
    }')"

  resp="$(curl -fsS --max-time 30 \
    -X POST "${NANOBOT_BASE_URL}/chat/completions" \
    -H "Authorization: Bearer ${NVIDIA_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"

  content="$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  if [ -n "$content" ]; then
    action="$(printf '%s' "$content" | jq -r 'try (fromjson.action) catch .action // "watchdog_rescue"' 2>/dev/null || echo watchdog_rescue)"
    reason="$(printf '%s' "$content" | jq -r 'try (fromjson.reason) catch .reason // "model-empty-reason"' 2>/dev/null || echo model-parse-failed)"
  fi

  case "$action" in
    none|coreguard_restart|watchdog_rescue) ;;
    *) action="watchdog_rescue"; reason="invalid-action-fallback" ;;
  esac

  printf '%s\t%s\n' "$action" "$reason"
}

model_chat_reply() {
  local user_text="$1" payload resp content
  if [ -z "$NVIDIA_API_KEY" ]; then
    printf '%s' "🦀 潤天蟹：我只負責救援修復。可用 /status、/rescue、/fix、/model。"
    return 0
  fi

  payload="$(jq -n --arg model "$NANOBOT_MODEL" --arg text "$user_text" '
    {
      model: $model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content: "You are a concise rescue bot for OpenClaw runtime on Android. Keep replies under 3 short lines and focus on status/recovery actions."
        },
        {
          role: "user",
          content: $text
        }
      ]
    }')"

  resp="$(curl -fsS --max-time 35 \
    -X POST "${NANOBOT_BASE_URL}/chat/completions" \
    -H "Authorization: Bearer ${NVIDIA_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"
  content="$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  if [ -z "$content" ]; then
    printf '%s' "🦀 潤天蟹：收到。可直接用 /status 或 /rescue。"
  else
    printf '%s' "$content"
  fi
}

watchdog_maintenance_active() {
  local wd_state
  wd_state="$HOME_DIR/.openclaw-watchdog/state.json"
  [ -f "$wd_state" ] || return 1
  [ "$(jq -r '.maintenance.active // false' "$wd_state" 2>/dev/null || echo false)" = "true" ]
}

run_rescue() {
  local reason="$1" pair action plan_reason now
  now="$(date +%s)"
  pair="$(structured_rescue_action)"
  action="$(printf '%s' "$pair" | awk -F'\t' '{print $1}')"
  plan_reason="$(printf '%s' "$pair" | awk -F'\t' '{print $2}')"
  log "rescue requested: reason=${reason}, action=${action}, plan_reason=${plan_reason}"

  case "$action" in
    none)
      send_telegram "🦀 潤天蟹：偵測到事件（${reason}），模型判定暫不執行修復。"
      ;;
    coreguard_restart)
      if [ -x "$CORE_GUARD_SCRIPT" ]; then
        "$CORE_GUARD_SCRIPT" --fix >>"$LOG_FILE" 2>&1 || true
      fi
      if restart_openclaw; then
        send_telegram "🦀 潤天蟹：已執行 core-guard + restart（${reason}）。"
      else
        if [ -x "$WATCHDOG_SCRIPT" ]; then
          "$WATCHDOG_SCRIPT" --rescue "nanobot:${reason}" >>"$LOG_FILE" 2>&1 || true
        fi
        send_telegram "🦀 潤天蟹：restart 失敗，已改走 watchdog rescue（${reason}）。"
      fi
      ;;
    watchdog_rescue|*)
      if [ -x "$WATCHDOG_SCRIPT" ]; then
        "$WATCHDOG_SCRIPT" --rescue "nanobot:${reason}" >>"$LOG_FILE" 2>&1 || true
        send_telegram "🦀 潤天蟹：已觸發 watchdog rescue（${reason}）。"
      else
        send_telegram "🦀 潤天蟹：watchdog 腳本不存在，無法救援（${reason}）。"
      fi
      ;;
  esac

  state_set ".last_action_ts=${now} | .last_action=\"${action}\" | .last_reason=\"${reason}\""
}

handle_command() {
  local text="$1" reply
  case "$text" in
    "/status"|"/status@"*)
      if openclaw_healthy; then
        send_telegram "🦀 潤天蟹：OpenClaw healthy。"
      else
        send_telegram "🦀 潤天蟹：OpenClaw unhealthy。"
      fi
      ;;
    "/rescue"|"/helpdog"|"/rescue@"*|"/helpdog@"*)
      run_rescue "telegram-command"
      ;;
    "/fix"|"/repair"|"/fix@"*|"/repair@"*)
      run_rescue "telegram-repair"
      ;;
    "/model"|"/model@"*)
      send_telegram "🦀 潤天蟹模型：${NANOBOT_MODEL}"
      ;;
    *)
      reply="$(model_chat_reply "$text")"
      send_telegram "$reply"
      ;;
  esac
}

poll_telegram_updates() {
  local last_id offset resp ids id max_id chat_id text
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0

  last_id="$(state_get '.last_update_id // 0')"
  offset="$((last_id + 1))"
  resp="$(curl -fsS --max-time 35 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?timeout=20&offset=${offset}" 2>/dev/null || true)"
  [ -n "$resp" ] || return 0
  if [ "$(printf '%s' "$resp" | jq -r '.ok // false')" != "true" ]; then
    return 0
  fi

  max_id="$last_id"
  ids="$(printf '%s' "$resp" | jq -r '.result[].update_id // empty')"
  for id in $ids; do
    [ "$id" -gt "$max_id" ] && max_id="$id"
    chat_id="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.chat.id // .edited_message.chat.id // empty)")"
    text="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.text // .edited_message.text // empty)")"
    [ -n "$chat_id" ] || continue
    [ -n "$text" ] || continue
    [ "$chat_id" = "$TELEGRAM_OWNER_ID" ] || continue
    handle_command "$text"
  done

  state_set ".last_update_id=${max_id}"
}

check_health_cycle() {
  local now last_hc started_at fail_count last_action_ts
  now="$(date +%s)"
  last_hc="$(state_get '.last_healthcheck_ts // 0')"
  if [ "$((now - last_hc))" -lt "$HEALTHCHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_healthcheck_ts=${now}"
  if watchdog_maintenance_active; then
    log "skip health rescue: watchdog maintenance active"
    state_set '.consecutive_health_failures=0'
    return 0
  fi
  started_at="$(state_get '.started_at // 0')"
  if [ "$started_at" -gt 0 ] && [ "$((now - started_at))" -lt "$NANOBOT_STARTUP_GRACE_SECONDS" ]; then
    log "startup grace active (${now}-${started_at} < ${NANOBOT_STARTUP_GRACE_SECONDS}); skip auto rescue"
    return 0
  fi
  if openclaw_healthy; then
    state_set '.consecutive_health_failures=0'
    return 0
  fi
  fail_count="$(state_get '.consecutive_health_failures // 0')"
  fail_count="$((fail_count + 1))"
  state_set ".consecutive_health_failures=${fail_count}"
  if [ "$fail_count" -lt "$NANOBOT_FAIL_THRESHOLD" ]; then
    log "health failed (${fail_count}/${NANOBOT_FAIL_THRESHOLD}); waiting before rescue"
    return 0
  fi
  last_action_ts="$(state_get '.last_action_ts // 0')"
  if [ "$last_action_ts" -gt 0 ] && [ "$((now - last_action_ts))" -lt "$NANOBOT_RESCUE_COOLDOWN_SECONDS" ]; then
    log "rescue cooldown active; skip auto rescue"
    return 0
  fi
  case "$(printf '%s' "$AUTO_RESCUE_ON_UNHEALTHY" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      run_rescue "auto-healthcheck-failed"
      ;;
    *)
      send_telegram "🦀 潤天蟹：偵測到 OpenClaw unhealthy，但自動救援已關閉。"
      ;;
  esac
}

run_daemon() {
  state_init
  if [ "$NANOBOT_ENABLED" != "1" ] && [ "$NANOBOT_ENABLED" != "true" ]; then
    log "nanobot disabled; exit"
    exit 0
  fi
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    log "missing telegram credentials; exit"
    exit 1
  fi
  log "started v${NANOBOT_VERSION}, model=${NANOBOT_MODEL}"
  state_set ".started_at=$(date +%s) | .consecutive_health_failures=0"
  send_telegram "🦀 潤天蟹已啟動（v${NANOBOT_VERSION}，model=${NANOBOT_MODEL}）"
  while true; do
    poll_telegram_updates
    check_health_cycle
    sleep "$POLL_INTERVAL_SECONDS"
  done
}

print_status() {
  state_init
  jq . "$STATE_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  termux-rescue-nanobot.sh --daemon
  termux-rescue-nanobot.sh --once
  termux-rescue-nanobot.sh --status
  termux-rescue-nanobot.sh --rescue <reason>
EOF
}

case "${1:---daemon}" in
  --daemon)
    run_daemon
    ;;
  --once)
    state_init
    poll_telegram_updates
    check_health_cycle
    ;;
  --status)
    print_status
    ;;
  --rescue)
    state_init
    run_rescue "${2:-manual}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
