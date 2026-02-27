#!/usr/bin/env bash
set -euo pipefail

NANOBOT_NAME="${NANOBOT_NAME:-runtianxie}"
NANOBOT_VERSION="1.3.0"

HOME_DIR="${HOME:-/home/ubuntu}"
REPO_DIR="${OPENCLAW_REPO_DIR:-${OPENCLAW_TERMUX_REPO_DIR:-$HOME_DIR/DINO_OPENCLAW}}"
STATE_DIR="${NANOBOT_STATE_DIR:-$HOME_DIR/.openclaw-nanobot}"
STATE_FILE="$STATE_DIR/state.json"
PID_FILE="$STATE_DIR/daemon.pid"
LOCK_DIR="$STATE_DIR/daemon.lock"
ENV_FILE="${NANOBOT_ENV_FILE:-$HOME_DIR/.openclaw-nanobot.env}"
LOG_FILE="${NANOBOT_LOG_FILE:-$HOME_DIR/openclaw-logs/nanobot.log}"

CORE_GUARD_SCRIPT="${CORE_GUARD_SCRIPT:-}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-}"
OPENCLAW_REBUILD_SCRIPT="${OPENCLAW_REBUILD_SCRIPT:-}"
OPENCLAW_REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
NANOBOT_RUNTIME_ENV="${NANOBOT_RUNTIME_ENV:-auto}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
NANOBOT_MODEL="${NANOBOT_MODEL:-z-ai/glm4.7}"
NANOBOT_BASE_URL="${NANOBOT_BASE_URL:-https://integrate.api.nvidia.com/v1}"
NANOBOT_ENABLED="${NANOBOT_ENABLED:-0}"
OPENCLAW_PORT="${OPENCLAW_PORT:-}"
NANOBOT_DIAG_LOG_LINES="${NANOBOT_DIAG_LOG_LINES:-60}"
NANOBOT_GITHUB_REPO="${NANOBOT_GITHUB_REPO:-openclaw/openclaw}"

# Keep nanobot mostly dormant: only react to user messages by default.
AUTO_HEALTHCHECK_ENABLED="${AUTO_HEALTHCHECK_ENABLED:-0}"
AUTO_RESCUE_ON_UNHEALTHY="${AUTO_RESCUE_ON_UNHEALTHY:-0}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-1}"
TELEGRAM_LONGPOLL_TIMEOUT="${TELEGRAM_LONGPOLL_TIMEOUT:-25}"
HEALTHCHECK_INTERVAL_SECONDS="${HEALTHCHECK_INTERVAL_SECONDS:-600}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-35}"
NANOBOT_STARTUP_GRACE_SECONDS="${NANOBOT_STARTUP_GRACE_SECONDS:-900}"
NANOBOT_FAIL_THRESHOLD="${NANOBOT_FAIL_THRESHOLD:-2}"
NANOBOT_RESCUE_COOLDOWN_SECONDS="${NANOBOT_RESCUE_COOLDOWN_SECONDS:-1800}"
NANOBOT_STARTUP_NOTIFY="${NANOBOT_STARTUP_NOTIFY:-0}"
MAX_TELEGRAM_TEXT_BYTES="${MAX_TELEGRAM_TEXT_BYTES:-3500}"
NANOBOT_INCLUDE_UPSTREAM_CHECK="${NANOBOT_INCLUDE_UPSTREAM_CHECK:-0}"
INTENT_CLASS="chat"
INTENT_REASON="default"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi
if [ "${NANOBOT_RUNTIME_ENV:-auto}" = "auto" ]; then
  case "$HOME_DIR" in
    /data/data/com.termux/files/home*) NANOBOT_RUNTIME_ENV="termux" ;;
    *) NANOBOT_RUNTIME_ENV="cloud" ;;
  esac
fi
if [ -z "${CORE_GUARD_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-coreguard.sh" ]; then
    CORE_GUARD_SCRIPT="$HOME_DIR/cloud/openclaw-coreguard.sh"
  else
    CORE_GUARD_SCRIPT="$REPO_DIR/scripts/termux-openclaw-core-guard.sh"
  fi
fi
if [ -z "${OPENCLAW_BOOT_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-launch.sh" ]; then
    OPENCLAW_BOOT_SCRIPT="$HOME_DIR/cloud/openclaw-launch.sh"
  else
    OPENCLAW_BOOT_SCRIPT="$HOME_DIR/.termux/boot/openclaw-launch.sh"
  fi
fi
if [ -z "${OPENCLAW_REBUILD_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-rebuild.sh" ]; then
    OPENCLAW_REBUILD_SCRIPT="$HOME_DIR/cloud/openclaw-rebuild.sh"
  else
    OPENCLAW_REBUILD_SCRIPT="$REPO_DIR/scripts/termux-rebuild-openclaw.sh"
  fi
fi
if [ -z "${OPENCLAW_PORT:-}" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  OPENCLAW_PORT="$(jq -r '.gateway.port // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [ -z "$OPENCLAW_BIN" ] && [ -x "$HOME_DIR/.npm-global/bin/openclaw" ]; then
  OPENCLAW_BIN="$HOME_DIR/.npm-global/bin/openclaw"
fi
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"

latest_openclaw_runtime_log() {
  {
    find /tmp/openclaw -maxdepth 1 -type f -name 'openclaw-*.log' 2>/dev/null
    find "$HOME_DIR/tmp" -maxdepth 2 -type f -name 'openclaw-*.log' 2>/dev/null
  } | sort | tail -n1
}

recent_error_excerpt() {
  local src="$1"
  [ -f "$src" ] || return 0
  tail -n "$NANOBOT_DIAG_LOG_LINES" "$src" 2>/dev/null \
    | sanitize_issue_lines \
    | tail -n 6 || true
}

sanitize_issue_lines() {
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' \
    | sed -E 's/[[:space:]]+/ /g; s/^ +//; s/ +$//' \
    | grep -Eiv '(^\{)|(^\[)|("_meta")|(subsystem\\":)|(isError=false)|(memory embeddings: batch start)|(memory embeddings: query start)|(embedded run agent end)' \
    | grep -Ei 'error|failed|timeout|exception|panic|denied|forbidden|unhealthy|crash|invalid|refused|conflict|429|500|503' \
    | awk 'length($0)>0 { print substr($0,1,220) }' || true
}

truncate_telegram_text() {
  local msg="$1" bytes
  bytes="$(printf '%s' "$msg" | wc -c | tr -d ' ')"
  if [ "${bytes:-0}" -gt "$MAX_TELEGRAM_TEXT_BYTES" ]; then
    printf '%s\n%s' "$(printf '%s' "$msg" | head -c "$MAX_TELEGRAM_TEXT_BYTES")" "...(訊息過長，已截斷)"
  else
    printf '%s' "$msg"
  fi
}

fetch_upstream_versions() {
  local npm_latest gh_tag gh_updated
  npm_latest="$(timeout 10s npm view openclaw version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  gh_tag="$(curl -fsS --max-time 10 "https://api.github.com/repos/${NANOBOT_GITHUB_REPO}/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' || true)"
  gh_updated="$(curl -fsS --max-time 10 "https://api.github.com/repos/${NANOBOT_GITHUB_REPO}/releases/latest" 2>/dev/null | jq -r '.published_at // empty' || true)"
  jq -n --arg npm "$npm_latest" --arg gh "$gh_tag" --arg gh_updated "$gh_updated" \
    '{npm_latest:$npm, github_latest_tag:$gh, github_published_at:$gh_updated}'
}

collect_openclaw_snapshot_json() {
  local cfg gateway_port tmux_sessions openclaw_pid nanobot_pid healthy openclaw_ver git_head stable_tag runtime_log
  local gateway_err runtime_err upstream_json
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  gateway_port="$OPENCLAW_PORT"
  if [ -f "$cfg" ]; then
    gateway_port="$(jq -r '.gateway.port // empty' "$cfg" 2>/dev/null || true)"
    [ -n "$gateway_port" ] || gateway_port="$OPENCLAW_PORT"
  fi
  gateway_port="${gateway_port:-18789}"
  tmux_sessions="$(tmux ls 2>/dev/null | awk -F: '{print $1}' | jq -R . | jq -s . 2>/dev/null || echo '[]')"
  openclaw_pid="$(pgrep -f 'openclaw-gateway|openclaw gateway' | head -n1 || true)"
  nanobot_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  openclaw_ver="$("$OPENCLAW_BIN" --version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  git_head="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || true)"
  stable_tag="$(resolve_stable_tag)"
  runtime_log="$(latest_openclaw_runtime_log)"
  if openclaw_healthy; then
    healthy=true
  else
    healthy=false
  fi

  gateway_err="$(recent_error_excerpt "$HOME_DIR/openclaw-logs/gateway.log" | tail -n 6)"
  runtime_err="$(recent_error_excerpt "$runtime_log" | tail -n 6)"
  if [ "$NANOBOT_INCLUDE_UPSTREAM_CHECK" = "1" ]; then
    upstream_json="$(fetch_upstream_versions)"
  else
    upstream_json='{"npm_latest":"","github_latest_tag":"","github_published_at":""}'
  fi

  jq -n \
    --argjson healthy "$healthy" \
    --arg openclaw_pid "$openclaw_pid" \
    --arg nanobot_pid "$nanobot_pid" \
    --arg gateway_port "$gateway_port" \
    --arg openclaw_ver "$openclaw_ver" \
    --arg git_head "$git_head" \
    --arg stable_tag "$stable_tag" \
    --arg runtime_log "${runtime_log:-}" \
    --arg gateway_err "$gateway_err" \
    --arg runtime_err "$runtime_err" \
    --argjson tmux "$tmux_sessions" \
    --argjson upstream "$upstream_json" \
    '{
      healthy: $healthy,
      gateway_port: $gateway_port,
      openclaw_pid: $openclaw_pid,
      nanobot_pid: $nanobot_pid,
      openclaw_version: $openclaw_ver,
      git_head: $git_head,
      stable_tag: $stable_tag,
      runtime_log: $runtime_log,
      tmux_sessions: $tmux,
      recent_gateway_errors: $gateway_err,
      recent_runtime_errors: $runtime_err,
      upstream: $upstream
    }'
}

build_status_report() {
  local snapshot healthy port opid npid ver head stable npm_latest gh_tag issues
  snapshot="$(collect_openclaw_snapshot_json)"
  healthy="$(printf '%s' "$snapshot" | jq -r '.healthy')"
  port="$(printf '%s' "$snapshot" | jq -r '.gateway_port')"
  opid="$(printf '%s' "$snapshot" | jq -r '.openclaw_pid // ""')"
  npid="$(printf '%s' "$snapshot" | jq -r '.nanobot_pid // ""')"
  ver="$(printf '%s' "$snapshot" | jq -r '.openclaw_version // ""')"
  head="$(printf '%s' "$snapshot" | jq -r '.git_head // ""')"
  stable="$(printf '%s' "$snapshot" | jq -r '.stable_tag // ""')"
  npm_latest="$(printf '%s' "$snapshot" | jq -r '.upstream.npm_latest // ""')"
  gh_tag="$(printf '%s' "$snapshot" | jq -r '.upstream.github_latest_tag // ""')"
  issues="$(printf '%s' "$snapshot" \
    | jq -r '.recent_gateway_errors, .recent_runtime_errors' 2>/dev/null \
    | sed '/^null$/d;/^$/d' \
    | sanitize_issue_lines \
    | tail -n 6 || true)"

  printf '🦀 潤天蟹自動診斷報告\n'
  if [ "$healthy" = "true" ]; then
    printf -- '- OpenClaw: 正常（port=%s, pid=%s）\n' "$port" "${opid:-n/a}"
  else
    printf -- '- OpenClaw: 異常（port=%s, pid=%s）\n' "$port" "${opid:-n/a}"
  fi
  printf -- '- Nanobot: 在線（pid=%s）\n' "${npid:-n/a}"
  printf -- '- 環境: %s\n' "${NANOBOT_RUNTIME_ENV}"
  printf -- '- 版本: local=%s, git=%s, 穩定標籤=%s\n' "${ver:-unknown}" "${head:-unknown}" "${stable:-none}"
  printf -- '- 上游: npm=%s, github=%s\n' "${npm_latest:-unknown}" "${gh_tag:-unknown}"
  if [ -n "$issues" ]; then
    printf -- '- 最近異常摘要:\n%s\n' "$(printf '%s' "$issues" | tail -n 6)"
  fi
}

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [nanobot] %s\n' "$ts" "$*" >>"$LOG_FILE"
}

is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
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
  "last_reason": "",
  "last_report": ""
}
EOF
  fi
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
  local msg_to_send
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0
  msg_to_send="$(truncate_telegram_text "$msg")"
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg_to_send}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

send_telegram_to_chat() {
  local chat_id="$1"
  local msg="$2"
  local msg_to_send
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$chat_id" ] || chat_id="$TELEGRAM_OWNER_ID"
  [ -n "$chat_id" ] || return 0
  msg_to_send="$(truncate_telegram_text "$msg")"
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${chat_id}" \
    --data-urlencode "text=${msg_to_send}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

start_typing_loop() {
  local chat_id="${1:-$TELEGRAM_OWNER_ID}"
  TYPING_PID=""
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$chat_id" ] || return 0
  (
    while true; do
      curl -fsS --max-time 10 \
        -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendChatAction" \
        -d "chat_id=${chat_id}" \
        -d "action=typing" >/dev/null 2>&1 || true
      sleep 3
    done
  ) &
  TYPING_PID="$!"
}

stop_typing_loop() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

openclaw_healthy() {
  if ! pgrep -f "openclaw gateway" >/dev/null 2>&1 \
    && ! pgrep -f "openclaw-gateway" >/dev/null 2>&1 \
    && ! pgrep -x openclaw >/dev/null 2>&1; then
    return 1
  fi
  python - "$OPENCLAW_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", port))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

restart_openclaw() {
  if [ ! -f "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script missing: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    chmod +x "$OPENCLAW_BOOT_SCRIPT" >/dev/null 2>&1 || true
  fi
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script not executable: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t =openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$OPENCLAW_BOOT_SCRIPT"
  sleep 10
  openclaw_healthy
}

resolve_stable_tag() {
  [ -d "$REPO_DIR/.git" ] || return 0
  git -C "$REPO_DIR" tag -l '穩定版*' --sort=-creatordate | head -n1
}

rebuild_rescue() {
  local reason="$1" target ok i
  if [ ! -x "$OPENCLAW_REBUILD_SCRIPT" ]; then
    log "rebuild script missing: $OPENCLAW_REBUILD_SCRIPT"
    return 1
  fi
  target="$(resolve_stable_tag)"
  if [ -z "$target" ]; then
    target="origin/${OPENCLAW_REPO_BRANCH}"
  fi
  send_telegram "🦀 潤天蟹修復前回報：準備回滾重建 OpenClaw。原因：${reason}，目標：${target}"

  OPENCLAW_REBUILD_MODE="rescue" \
  OPENCLAW_REBUILD_PRESERVE_CONFIG=1 \
  OPENCLAW_REBUILD_PRESERVE_STATE=1 \
  OPENCLAW_REBUILD_SKIP_WATCHDOG=1 \
  OPENCLAW_REBUILD_SKIP_NANOBOT=1 \
  OPENCLAW_WATCHDOG_ENABLED=0 \
  NANOBOT_ENABLED=1 \
  NANOBOT_TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" \
  TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID" \
  NVIDIA_API_KEY="$NVIDIA_API_KEY" \
  OPENCLAW_PORT="$OPENCLAW_PORT" \
  bash "$OPENCLAW_REBUILD_SCRIPT" >>"$LOG_FILE" 2>&1 || return 1

  ok=0
  for i in 1 2 3; do
    sleep 8
    if openclaw_healthy; then
      ok=1
      break
    fi
  done

  if [ "$ok" = "1" ]; then
    send_telegram "✅ 潤天蟹修復後回報：回滾重建成功，OpenClaw 已恢復。原因：${reason}，目標：${target}"
    return 0
  fi

  send_telegram "❌ 潤天蟹修復後回報：回滾重建後仍不健康。原因：${reason}，目標：${target}"
  return 1
}

call_model_json() {
  local prompt="$1" schema_json="$2" out_var="$3"
  local payload resp response_content
  if [ -z "$NVIDIA_API_KEY" ]; then
    printf -v "$out_var" '%s' ""
    return 1
  fi
  payload="$(jq -n \
    --arg model "$NANOBOT_MODEL" \
    --arg prompt "$prompt" \
    --argjson schema "$schema_json" '
    {
      model: $model,
      temperature: 0,
      messages: [
        { role: "system", content: "Output strict JSON only." },
        { role: "user", content: $prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "nanobot_structured",
          strict: true,
          schema: $schema
        }
      }
    }')"
  resp="$(curl -fsS --max-time 30 \
    -X POST "${NANOBOT_BASE_URL}/chat/completions" \
    -H "Authorization: Bearer ${NVIDIA_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"
  response_content="$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  printf -v "$out_var" '%s' "$response_content"
  [ -n "$response_content" ]
}

model_chat_reply() {
  local user_text="$1" payload resp content snapshot_json
  snapshot_json="$(collect_openclaw_snapshot_json)"
  if [ -z "$NVIDIA_API_KEY" ]; then
    printf '%s\n' "我已先完成自動診斷。你直接說需求，我會直接檢查並處理，不需要你用斜線指令。"
    return 0
  fi
  payload="$(jq -n --arg model "$NANOBOT_MODEL" --arg text "$user_text" --arg snapshot "$snapshot_json" '
    {
      model: $model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content: "你是潤天蟹，OpenClaw 醫護兵。部署環境是 Oracle Cloud Ubuntu（非手機 Termux）。請用繁體中文簡潔回覆。你必須根據系統診斷資訊回答，不要叫使用者輸入斜線指令。若可直接處理，直接處理；若需要修復，清楚說明你將執行什麼。"
        },
        {
          role: "system",
          content: ("系統診斷快照(JSON): " + $snapshot)
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
    printf '%s\n' "我已自動診斷完成。你直接描述需求，我會直接檢查並處理，不需要你輸入任何指令格式。"
  else
    printf '%s\n' "$content"
  fi
}

classify_natural_intent() {
  local user_text="$1" text_norm schema content intent reason
  INTENT_CLASS="chat"
  INTENT_REASON="natural-chat"
  text_norm="$(printf '%s' "$user_text" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$text_norm" | grep -Eiq '救援|修復|修好|修正|除錯|排錯|回滾|復原|掛了|當機|故障|失聯|沒反應|crash|broken|fix|repair|rescue'; then
    INTENT_CLASS="repair"
    INTENT_REASON="keyword-repair"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '日誌|log|後台|系統資訊|診斷|檢查|狀況|github|版本|更新|運行'; then
    INTENT_CLASS="diagnose"
    INTENT_REASON="keyword-diagnose"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '狀態|健康|還在嗎|有沒有運作|運作嗎|在線|online|health|status'; then
    INTENT_CLASS="status"
    INTENT_REASON="keyword-status"
    return 0
  fi
  if [ -z "$NVIDIA_API_KEY" ]; then
    INTENT_CLASS="chat"
    INTENT_REASON="fallback-no-model"
    return 0
  fi

  schema='{
    "type":"object",
    "additionalProperties":false,
    "properties":{
      "intent":{"type":"string","enum":["repair","diagnose","status","chat"]},
      "reason":{"type":"string"}
    },
    "required":["intent","reason"]
  }'
  if call_model_json "Text: ${user_text}\nClassify intent into repair|diagnose|status|chat." "$schema" content; then
    intent="$(printf '%s' "$content" | jq -r 'try (fromjson.intent) catch .intent // "chat"' 2>/dev/null || echo chat)"
    reason="$(printf '%s' "$content" | jq -r 'try (fromjson.reason) catch .reason // "model-intent"' 2>/dev/null || echo model-intent)"
    case "$intent" in
      repair|diagnose|status|chat) ;;
      *) intent="chat"; reason="invalid-intent-fallback" ;;
    esac
    INTENT_CLASS="$intent"
    INTENT_REASON="$reason"
    return 0
  fi
  INTENT_CLASS="chat"
  INTENT_REASON="model-timeout"
}

run_repair_playbook() {
  local reason="$1" now
  now="$(date +%s)"
  send_telegram "🦀 潤天蟹修復前回報：開始修復流程。原因：${reason}"
  log "repair playbook start: reason=${reason}"

  if [ -f "$CORE_GUARD_SCRIPT" ]; then
    bash "$CORE_GUARD_SCRIPT" --fix >>"$LOG_FILE" 2>&1 || true
  fi

  if restart_openclaw; then
    send_telegram "✅ 潤天蟹修復後回報：core-guard + restart 成功。原因：${reason}"
    state_set ".last_action_ts=${now} | .last_action=\"coreguard_restart\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0"
    return 0
  fi

  if rebuild_rescue "$reason"; then
    state_set ".last_action_ts=${now} | .last_action=\"rebuild_rescue\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0"
    return 0
  fi

  send_telegram "❌ 潤天蟹修復後回報：修復失敗，需要人工介入。原因：${reason}"
  state_set ".last_action_ts=${now} | .last_action=\"repair_failed\" | .last_reason=\"${reason}\" | .last_report=\"failed\""
  return 1
}

handle_command() {
  local text="$1" chat_id="${2:-$TELEGRAM_OWNER_ID}" intent reason reply typing_pid rc
  rc=0
  start_typing_loop "$chat_id"
  typing_pid="${TYPING_PID:-}"
  trap 'stop_typing_loop "$typing_pid"' RETURN
  {
    case "$text" in
      "/status"|"/status@"*)
        send_telegram_to_chat "$chat_id" "$(build_status_report)"
        ;;
      "/repair"|"/rescue"|"/fix"|"/repair@"*|"/rescue@"*|"/fix@"*)
        run_repair_playbook "telegram-command"
        ;;
      "/model"|"/model@"*)
        send_telegram_to_chat "$chat_id" "🦀 潤天蟹目前模型：${NANOBOT_MODEL}"
        ;;
      "/help"|"/help@"*)
        send_telegram_to_chat "$chat_id" "🦀 我會先自動診斷，再直接處理。你用自然語言描述需求即可。"
        ;;
      *)
        classify_natural_intent "$text"
        intent="$INTENT_CLASS"
        reason="$INTENT_REASON"
        case "$intent" in
          repair)
            run_repair_playbook "natural:${reason}"
            ;;
          diagnose)
            send_telegram_to_chat "$chat_id" "$(build_status_report)"
            ;;
          status)
            send_telegram_to_chat "$chat_id" "$(build_status_report)"
            ;;
          chat|*)
            reply="$(model_chat_reply "$text")"
            send_telegram_to_chat "$chat_id" "$reply"
            ;;
        esac
        ;;
    esac
  } || rc=$?
  trap - RETURN
  stop_typing_loop "$typing_pid"
  return "$rc"
}

poll_telegram_updates() {
  local last_id offset resp_file ids id max_id chat_id text
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0

  last_id="$(state_get '.last_update_id // 0')"
  offset="$((last_id + 1))"
  resp_file="$(mktemp)"
  if ! curl -fsS --max-time $((TELEGRAM_LONGPOLL_TIMEOUT + 10)) \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?timeout=${TELEGRAM_LONGPOLL_TIMEOUT}&offset=${offset}" \
    -o "$resp_file" 2>/dev/null; then
    rm -f "$resp_file"
    return 0
  fi
  if [ "$(jq -r '.ok // false' "$resp_file" 2>/dev/null || echo false)" != "true" ]; then
    local desc
    desc="$(jq -r '.description // empty' "$resp_file" 2>/dev/null || true)"
    [ -n "$desc" ] && log "getUpdates not-ok: ${desc}"
    rm -f "$resp_file"
    return 0
  fi

  max_id="$last_id"
  ids="$(jq -r '.result[].update_id // empty' "$resp_file" 2>/dev/null || true)"
  for id in $ids; do
    [ "$id" -gt "$max_id" ] && max_id="$id"
    chat_id="$(jq -r ".result[] | select(.update_id==${id}) | (.message.chat.id // .edited_message.chat.id // empty)" "$resp_file" 2>/dev/null || true)"
    text="$(jq -r ".result[] | select(.update_id==${id}) | (.message.text // .edited_message.text // empty)" "$resp_file" 2>/dev/null || true)"
    [ -n "$chat_id" ] || continue
    [ -n "$text" ] || continue
    [ "$chat_id" = "$TELEGRAM_OWNER_ID" ] || continue
    handle_command "$text" "$chat_id"
  done

  rm -f "$resp_file"
  state_set ".last_update_id=${max_id}"
}

check_health_cycle() {
  local now last_hc started_at fail_count last_action_ts
  if ! is_true_flag "$AUTO_HEALTHCHECK_ENABLED"; then
    return 0
  fi

  now="$(date +%s)"
  last_hc="$(state_get '.last_healthcheck_ts // 0')"
  if [ "$((now - last_hc))" -lt "$HEALTHCHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_healthcheck_ts=${now}"

  started_at="$(state_get '.started_at // 0')"
  if [ "$started_at" -gt 0 ] && [ "$((now - started_at))" -lt "$NANOBOT_STARTUP_GRACE_SECONDS" ]; then
    log "startup grace active; skip auto health rescue"
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
    log "health failed (${fail_count}/${NANOBOT_FAIL_THRESHOLD}); wait next cycle"
    return 0
  fi

  last_action_ts="$(state_get '.last_action_ts // 0')"
  if [ "$last_action_ts" -gt 0 ] && [ "$((now - last_action_ts))" -lt "$NANOBOT_RESCUE_COOLDOWN_SECONDS" ]; then
    log "rescue cooldown active; skip auto rescue"
    return 0
  fi

  if is_true_flag "$AUTO_RESCUE_ON_UNHEALTHY"; then
    run_repair_playbook "auto-healthcheck-failed"
  else
    send_telegram "🦀 潤天蟹提醒：偵測到 OpenClaw 不健康，但自動救援已關閉。"
  fi
}

run_daemon() {
  local existing
  state_init
  if ! mkdir "$LOCK_DIR" >/dev/null 2>&1; then
    existing="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing" ] && kill -0 "$existing" >/dev/null 2>&1; then
      log "already running (pid=${existing})"
      exit 0
    fi
    rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
    mkdir "$LOCK_DIR" >/dev/null 2>&1 || {
      log "failed to acquire lock"
      exit 1
    }
  fi

  echo "$$" >"$PID_FILE"
  trap 'pkill -P $$ >/dev/null 2>&1 || true; rm -f "$PID_FILE"; rm -rf "$LOCK_DIR"' EXIT
  trap 'exit 0' INT TERM HUP

  if ! is_true_flag "$NANOBOT_ENABLED"; then
    log "nanobot disabled; exit"
    exit 0
  fi
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    log "missing telegram credentials; exit"
    exit 1
  fi

  log "started v${NANOBOT_VERSION}, env=${NANOBOT_RUNTIME_ENV}, model=${NANOBOT_MODEL}, auto_healthcheck=${AUTO_HEALTHCHECK_ENABLED}, auto_rescue=${AUTO_RESCUE_ON_UNHEALTHY}"
  state_set ".started_at=$(date +%s) | .consecutive_health_failures=0"
  if is_true_flag "$NANOBOT_STARTUP_NOTIFY"; then
    send_telegram "🦀 潤天蟹已啟動（v${NANOBOT_VERSION}）。我會自動讀取引天渡狀態/日誌/版本並待命，你只要自然語言描述需求。"
  fi

  while true; do
    poll_telegram_updates
    check_health_cycle
    sleep "$POLL_INTERVAL_SECONDS"
  done
}

print_status() {
  state_init
  jq --arg version "$NANOBOT_VERSION" \
     --arg model "$NANOBOT_MODEL" \
     --arg auto_hc "$AUTO_HEALTHCHECK_ENABLED" \
     --arg auto_rescue "$AUTO_RESCUE_ON_UNHEALTHY" \
     '. + {version:$version, model:$model, auto_healthcheck:$auto_hc, auto_rescue:$auto_rescue}' \
     "$STATE_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  termux-rescue-nanobot.sh --daemon
  termux-rescue-nanobot.sh --once
  termux-rescue-nanobot.sh --status
  termux-rescue-nanobot.sh --diagnose
  termux-rescue-nanobot.sh --repair <reason>
  termux-rescue-nanobot.sh --simulate-text "<text>"
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
  --diagnose)
    state_init
    build_status_report
    ;;
  --repair|--rescue)
    state_init
    run_repair_playbook "${2:-manual}"
    ;;
  --simulate-text)
    state_init
    handle_command "${2:-}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
