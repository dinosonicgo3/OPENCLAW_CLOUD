#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

WATCHDOG_NAME="openclaw-watchdog"
WATCHDOG_VERSION="1.5.0"

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
STATE_DIR="${OPENCLAW_WATCHDOG_STATE_DIR:-$HOME_DIR/.openclaw-watchdog}"
STATE_FILE="$STATE_DIR/state.json"
MANIFEST_FILE="$STATE_DIR/critical-manifest.json"
LOG_FILE="${OPENCLAW_WATCHDOG_LOG:-$HOME_DIR/openclaw-logs/watchdog.log}"
ENV_FILE="${OPENCLAW_WATCHDOG_ENV:-$HOME_DIR/.openclaw-watchdog.env}"
PID_FILE="$STATE_DIR/daemon.pid"

REPO_DIR_DEFAULT="$HOME_DIR/DINO_OPENCLAW"
REPO_DIR="${OPENCLAW_REPO_DIR:-$REPO_DIR_DEFAULT}"
REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-core-guard.sh}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME_DIR/.termux/boot/openclaw-launch.sh}"

POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-180}"
MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-1800}"
MAINTENANCE_TIMEOUT_SECONDS="${MAINTENANCE_TIMEOUT_SECONDS:-1800}"
RESCUE_COOLDOWN_SECONDS="${RESCUE_COOLDOWN_SECONDS:-300}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-45}"
STARTUP_GRACE_SECONDS="${STARTUP_GRACE_SECONDS:-300}"

OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
WATCHDOG_TELEGRAM_BOT_TOKEN="${WATCHDOG_TELEGRAM_BOT_TOKEN:-}"
WATCHDOG_TELEGRAM_POLL_ENABLED="${WATCHDOG_TELEGRAM_POLL_ENABLED:-0}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

REPO_DIR="${OPENCLAW_REPO_DIR:-$REPO_DIR_DEFAULT}"
REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-core-guard.sh}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME_DIR/.termux/boot/openclaw-launch.sh}"

if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  TELEGRAM_BOT_TOKEN="$(jq -r '.channels.telegram.botToken // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
if [ -z "$TELEGRAM_OWNER_ID" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  TELEGRAM_OWNER_ID="$(jq -r '.channels.telegram.allowFrom[0] // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
if [ -z "$NVIDIA_API_KEY" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  NVIDIA_API_KEY="$(jq -r '.models.providers.nvidia.apiKey // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  mkdir -p "$(dirname "$LOG_FILE")"
  printf '[%s] [%s] %s\n' "$ts" "$WATCHDOG_NAME" "$*" >>"$LOG_FILE"
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_update_id": 0,
  "last_monitor_ts": 0,
  "last_rescue_ts": 0,
  "last_rescue_reason": "",
  "started_at": 0,
  "maintenance": {
    "active": false,
    "reason": "",
    "started_at": 0,
    "deadline_at": 0
  }
}
EOF
  fi
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE"
}

state_set() {
  local jq_expr="$1"
  local tmp
  tmp="$(mktemp)"
  jq "$jq_expr" "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

sha_path() {
  local file="$1"
  if [ ! -f "$file" ]; then
    printf 'missing'
    return 0
  fi
  sha256sum "$file" | awk '{print $1}'
}

critical_paths() {
  cat <<EOF
$REPO_DIR/scripts/termux-openclaw-core-guard.sh
$REPO_DIR/scripts/termux-openclaw-watchdog.sh
$REPO_DIR/scripts/termux-rebuild-openclaw.sh
$OPENCLAW_BOOT_SCRIPT
$HOME_DIR/.termux/boot/openclaw-watchdog-launch.sh
$HOME_DIR/.termux/boot/start-openclaw.sh
EOF
}

refresh_critical_manifest() {
  local tmp tmp2 path sha now
  tmp="$(mktemp)"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n --arg now "$now" '{generated_at_utc:$now, entries:[]}' >"$tmp"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    sha="$(sha_path "$path")"
    tmp2="$(mktemp)"
    jq --arg p "$path" --arg s "$sha" '.entries += [{"path":$p,"sha256":$s}]' "$tmp" >"$tmp2"
    mv "$tmp2" "$tmp"
  done < <(critical_paths)
  mv "$tmp" "$MANIFEST_FILE"
  chmod 600 "$MANIFEST_FILE"
  log "critical manifest refreshed: $MANIFEST_FILE"
}

critical_drift_detected() {
  local line path expected actual
  if [ ! -f "$MANIFEST_FILE" ]; then
    refresh_critical_manifest
    return 1
  fi

  while IFS=$'\t' read -r path expected; do
    [ -n "${path:-}" ] || continue
    actual="$(sha_path "$path")"
    if [ "$actual" != "$expected" ]; then
      log "critical drift: path=$path expected=$expected actual=$actual"
      printf '%s\n' "$path"
      return 0
    fi
  done < <(jq -r '.entries[]? | [.path, .sha256] | @tsv' "$MANIFEST_FILE" 2>/dev/null || true)

  return 1
}

send_telegram() {
  local msg="$1"
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    return 0
  fi
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

run_core_guard() {
  if [ ! -x "$CORE_GUARD_SCRIPT" ]; then
    log "core guard script missing: $CORE_GUARD_SCRIPT"
    printf 'missing\n'
    return 1
  fi

  local out rc
  out="$("$CORE_GUARD_SCRIPT" --fix 2>/dev/null)" || rc=$?
  rc="${rc:-0}"
  case "$rc:$out" in
    0:changed)
      log "core guard healed unsafe config"
      printf 'changed\n'
      return 0
      ;;
    0:unchanged)
      printf 'unchanged\n'
      return 0
      ;;
    *)
      log "core guard failed: rc=${rc}"
      printf 'error\n'
      return 1
      ;;
  esac
}

restart_openclaw_after_guard() {
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script missing for guarded restart: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$OPENCLAW_BOOT_SCRIPT"
  sleep 10
  openclaw_healthy
}

enter_maintenance() {
  local reason="$1"
  local now deadline
  now="$(date +%s)"
  deadline="$((now + MAINTENANCE_TIMEOUT_SECONDS))"
  state_set ".maintenance.active=true | .maintenance.reason=\"${reason}\" | .maintenance.started_at=${now} | .maintenance.deadline_at=${deadline}"
  log "maintenance start: ${reason}, deadline=${deadline}"
  send_telegram "🛠️ Watchdog: 進入更新握手模式（${reason}），${MAINTENANCE_TIMEOUT_SECONDS} 秒內允許 OpenClaw 失聯。"
}

finish_maintenance() {
  local reason="${1:-manual}"
  local guard_result
  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    log "maintenance finish: config healed, restarting openclaw before ack"
    restart_openclaw_after_guard || true
  fi
  if ! openclaw_healthy; then
    log "maintenance finish rejected: openclaw unhealthy"
    send_telegram "❌ Watchdog: 更新成功握手被拒絕，OpenClaw 健康檢查未通過，啟動救援回滾。"
    state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
    trigger_rescue "maintenance-finish-unhealthy"
    return 1
  fi
  refresh_critical_manifest
  state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
  log "maintenance finished: ${reason}"
  send_telegram "✅ Watchdog: 收到更新成功握手（${reason}），恢復正常監控。"
}

openclaw_healthy() {
  if ! pgrep -f "openclaw gateway" >/dev/null 2>&1 && ! pgrep -f "openclaw-gateway" >/dev/null 2>&1; then
    return 1
  fi
  ss -ltn 2>/dev/null | grep -q ":${OPENCLAW_PORT} " || return 1
  return 0
}

resolve_stable_tag() {
  git -C "$REPO_DIR" fetch --all --tags --prune >/dev/null 2>&1 || true
  git -C "$REPO_DIR" tag -l '穩定版*' --sort=-creatordate | head -n1
}

rollback_and_rebuild() {
  local reason="$1"
  local stable_tag target
  stable_tag="$(resolve_stable_tag)"
  target="${stable_tag:-origin/${REPO_BRANCH}}"

  log "rescue start: reason=${reason}, target=${target}"
  send_telegram "🚨 Watchdog 救援啟動：${reason}\n目標版本：${target}"

  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux kill-session -t openclaw >/dev/null 2>&1 || true

  if [ ! -d "$REPO_DIR/.git" ]; then
    log "repo not found: $REPO_DIR"
    send_telegram "❌ Watchdog 救援失敗：找不到 repo ${REPO_DIR}"
    return 1
  fi

  git -C "$REPO_DIR" checkout "$REPO_BRANCH" >/dev/null 2>&1 || git -C "$REPO_DIR" checkout -B "$REPO_BRANCH" "origin/${REPO_BRANCH}" >/dev/null 2>&1
  git -C "$REPO_DIR" reset --hard "$target" >/dev/null 2>&1

  TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" \
  TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID" \
  NVIDIA_API_KEY="$NVIDIA_API_KEY" \
  OPENCLAW_PORT="$OPENCLAW_PORT" \
  OPENCLAW_REBUILD_SKIP_WATCHDOG=1 \
  bash "$REPO_DIR/scripts/termux-rebuild-openclaw.sh" >>"$LOG_FILE" 2>&1 || {
    log "rescue failed: rebuild script exited non-zero"
    send_telegram "❌ Watchdog 救援失敗：重建腳本執行失敗（${target}）"
    return 1
  }
  run_core_guard >/dev/null 2>&1 || true

  sleep 8
  if openclaw_healthy; then
    refresh_critical_manifest || true
    log "rescue success: ${target}"
    send_telegram "✅ Watchdog 救援成功：已回滾並重建到 ${target}"
    return 0
  fi

  log "rescue failed after rebuild: ${target}"
  send_telegram "❌ Watchdog 救援失敗：回滾重建後仍無法恢復（${target}）"
  return 1
}

trigger_rescue() {
  local reason="$1"
  local now last
  now="$(date +%s)"
  last="$(state_get '.last_rescue_ts // 0')"
  if [ "$((now - last))" -lt "$RESCUE_COOLDOWN_SECONDS" ]; then
    log "rescue skipped due to cooldown: ${reason}"
    return 0
  fi
  state_set ".last_rescue_ts=${now} | .last_rescue_reason=\"${reason}\""
  rollback_and_rebuild "$reason" || true
}

handle_command() {
  local text="$1"
  local normalized
  normalized="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    "/helpdog"|"/helpdog@"*)
      log "telegram command detected: /helpdog"
      trigger_rescue "telegram:/helpdog"
      ;;
    *"更新主系統"*|"/update_system"|"/updatesystem")
      log "telegram command detected: update-start"
      enter_maintenance "telegram:更新主系統"
      ;;
    *"更新成功"*|*"更新完成"*|"/update_ok"|"/update_done")
      log "telegram command detected: update-success"
      finish_maintenance "telegram:update-success"
      ;;
    "/dogstatus")
      local active reason deadline
      active="$(state_get '.maintenance.active')"
      reason="$(state_get '.maintenance.reason')"
      deadline="$(state_get '.maintenance.deadline_at')"
      send_telegram "🐶 Watchdog 狀態\nactive=${active}\nmaintenance_reason=${reason}\ndeadline=${deadline}"
      ;;
    *)
      ;;
  esac
}

poll_telegram_updates() {
  local poll_flag
  poll_flag="$(printf '%s' "$WATCHDOG_TELEGRAM_POLL_ENABLED" | tr '[:upper:]' '[:lower:]')"
  case "$poll_flag" in
    1|true|yes|on)
      ;;
    *)
      return 0
      ;;
  esac

  if [ -z "$WATCHDOG_TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    log "telegram polling disabled: missing WATCHDOG_TELEGRAM_BOT_TOKEN or TELEGRAM_OWNER_ID"
    WATCHDOG_TELEGRAM_POLL_ENABLED="0"
    return 0
  fi
  if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ "$WATCHDOG_TELEGRAM_BOT_TOKEN" = "$TELEGRAM_BOT_TOKEN" ]; then
    log "telegram polling disabled: watchdog token matches primary bot token"
    WATCHDOG_TELEGRAM_POLL_ENABLED="0"
    return 0
  fi

  local last_id offset resp ids id max_id
  last_id="$(state_get '.last_update_id // 0')"
  offset="$((last_id + 1))"
  resp="$(curl -fsS --max-time 40 "https://api.telegram.org/bot${WATCHDOG_TELEGRAM_BOT_TOKEN}/getUpdates?timeout=25&offset=${offset}" 2>/dev/null || true)"
  [ -z "$resp" ] && return 0
  if [ "$(printf '%s' "$resp" | jq -r '.ok // false')" != "true" ]; then
    return 0
  fi

  max_id="$last_id"
  ids="$(printf '%s' "$resp" | jq -r '.result[].update_id // empty')"
  for id in $ids; do
    [ "$id" -gt "$max_id" ] && max_id="$id"
    local chat_id text
    chat_id="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.chat.id // .edited_message.chat.id // empty)")"
    text="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.text // .edited_message.text // empty)")"
    [ -z "$chat_id" ] && continue
    [ -z "$text" ] && continue
    [ "$chat_id" != "$TELEGRAM_OWNER_ID" ] && continue
    handle_command "$text"
  done
  state_set ".last_update_id=${max_id}"
}

monitor_once() {
  local now active deadline last_monitor guard_result drift_path
  now="$(date +%s)"
  poll_telegram_updates

  active="$(state_get '.maintenance.active')"
  deadline="$(state_get '.maintenance.deadline_at // 0')"

  if [ "$active" = "true" ]; then
    if [ "$now" -gt "$deadline" ]; then
      log "maintenance timeout reached"
      send_telegram "⚠️ Watchdog: 更新握手逾時，啟動自動回滾救援。"
      state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
      trigger_rescue "maintenance-timeout"
    fi
    return 0
  fi

  drift_path="$(critical_drift_detected 2>/dev/null || true)"
  if [ -n "$drift_path" ]; then
    send_telegram "🚨 Watchdog: 偵測到底層檔案漂移（${drift_path}），啟動救援回滾。"
    trigger_rescue "critical-drift"
    return 0
  fi

  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    send_telegram "🩹 Watchdog: 偵測到危險配置已自動修復，正在重啟 OpenClaw。"
    if restart_openclaw_after_guard; then
      log "guard-triggered restart success"
    else
      log "guard-triggered restart failed; rescue may be required"
    fi
  fi

  last_monitor="$(state_get '.last_monitor_ts // 0')"
  local started_at
  started_at="$(state_get '.started_at // 0')"
  if [ "$((now - started_at))" -lt "$STARTUP_GRACE_SECONDS" ]; then
    return 0
  fi
  if [ "$((now - last_monitor))" -lt "$MONITOR_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_monitor_ts=${now}"

  if ! openclaw_healthy; then
    log "health check failed"
    trigger_rescue "healthcheck-failed"
  else
    log "health check ok"
  fi
}

run_daemon() {
  local existing now poll_mode guard_result
  state_init
  if [ -f "$PID_FILE" ]; then
    existing="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing" ] && kill -0 "$existing" >/dev/null 2>&1; then
      log "already running (pid=${existing})"
      exit 0
    fi
  fi
  echo "$$" >"$PID_FILE"
  trap 'rm -f "$PID_FILE"' EXIT

  now="$(date +%s)"
  state_set ".started_at=${now} | .last_monitor_ts=${now}"
  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    send_telegram "🩹 Watchdog: 開機時修復了 OpenClaw 危險配置。"
  fi
  refresh_critical_manifest || true
  poll_mode="disabled"
  case "$(printf '%s' "$WATCHDOG_TELEGRAM_POLL_ENABLED" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) poll_mode="enabled" ;;
  esac
  log "started v${WATCHDOG_VERSION}, poll=${POLL_INTERVAL_SECONDS}s, monitor=${MONITOR_INTERVAL_SECONDS}s, telegram_command_poll=${poll_mode}"
  send_telegram "🐶 Watchdog 已啟動（v${WATCHDOG_VERSION}）"
  while true; do
    monitor_once
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
  termux-openclaw-watchdog.sh --daemon
  termux-openclaw-watchdog.sh --once
  termux-openclaw-watchdog.sh --status
  termux-openclaw-watchdog.sh --baseline-refresh
  termux-openclaw-watchdog.sh --rescue <reason>
  termux-openclaw-watchdog.sh --maintenance-start <reason>
  termux-openclaw-watchdog.sh --maintenance-ok <reason>
EOF
}

case "${1:---daemon}" in
  --daemon)
    run_daemon
    ;;
  --once)
    state_init
    monitor_once
    ;;
  --status)
    print_status
    ;;
  --baseline-refresh)
    refresh_critical_manifest
    ;;
  --rescue)
    state_init
    trigger_rescue "${2:-manual-rescue}"
    ;;
  --maintenance-start)
    state_init
    enter_maintenance "${2:-manual-start}"
    ;;
  --maintenance-ok)
    state_init
    finish_maintenance "${2:-manual-ok}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
