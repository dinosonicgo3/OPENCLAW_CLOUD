#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME_DIR/DINO_OPENCLAW}"
WATCHDOG_SCRIPT="${REPO_DIR}/scripts/termux-openclaw-watchdog.sh"
BOOT_SCRIPT="${HOME_DIR}/.termux/boot/openclaw-launch.sh"
LOG_DIR="${HOME_DIR}/openclaw-logs"
UPDATE_LOG="${LOG_DIR}/main-system-update.log"
TMP_DIR="${HOME_DIR}/tmp"
LOCK_DIR="${HOME_DIR}/.openclaw/.update-lock"
NPM_PREFIX_DIR="${HOME_DIR}/.npm-global"

MAINT_REASON="${MAINT_REASON:-manual:update-main-system}"
ENABLE_AUTO_UPDATE="${ENABLE_AUTO_UPDATE:-1}"
CHANNEL_TARGET="${CHANNEL_TARGET:-stable}"
STATE_FILE="${HOME_DIR}/.openclaw-watchdog/state.json"
FORCE_NPM_UPDATE="${FORCE_NPM_UPDATE:-0}"
OPENCLAW_NPM_TARGET="${OPENCLAW_NPM_TARGET:-latest}"
OPENCLAW_WATCHDOG_ENABLED="${OPENCLAW_WATCHDOG_ENABLED:-0}"
OPENCLAW_PORT="${OPENCLAW_PORT:-}"

if [ -f "${HOME_DIR}/.openclaw-nanobot.env" ]; then
  # shellcheck disable=SC1090
  . "${HOME_DIR}/.openclaw-nanobot.env"
fi
if [ -z "${OPENCLAW_PORT:-}" ] && [ -f "${HOME_DIR}/.openclaw/openclaw.json" ]; then
  OPENCLAW_PORT="$(jq -r '.gateway.port // empty' "${HOME_DIR}/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"

export PATH="${NPM_PREFIX_DIR}/bin:/data/data/com.termux/files/usr/bin:$PATH"
mkdir -p "$LOG_DIR" "$TMP_DIR" "${HOME_DIR}/backups" "${HOME_DIR}/.openclaw"

maintenance_started=0
update_success=0
had_errors=0
lock_acquired=0
before_version=""
after_version=""
latest_version=""
cli_update_rc=0

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [main-system-update] %s\n' "$ts" "$*" | tee -a "$UPDATE_LOG"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing command: $1"
    exit 1
  }
}

bool_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

watchdog_enabled() {
  bool_true "$OPENCLAW_WATCHDOG_ENABLED"
}

acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    lock_acquired=1
    printf '%s\n' "$$" >"${LOCK_DIR}/pid"
    return 0
  fi

  if [ -f "${LOCK_DIR}/pid" ]; then
    log "another update appears running (pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || echo unknown)); abort"
  else
    log "another update appears running; abort"
  fi
  exit 1
}

release_lock() {
  if [ "$lock_acquired" -eq 1 ]; then
    rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
    lock_acquired=0
  fi
}

ensure_npm_prefix() {
  mkdir -p "${NPM_PREFIX_DIR}/bin"
  npm config set prefix "$NPM_PREFIX_DIR" >/dev/null 2>&1 || true
}

current_openclaw_version() {
  openclaw -V 2>/dev/null | tr -d '\r' | tail -n1 || true
}

detect_latest_version() {
  npm view openclaw version 2>/dev/null | tr -d '\r' | tail -n1 || true
}

start_maintenance() {
  if watchdog_enabled && [ -x "$WATCHDOG_SCRIPT" ]; then
    bash "$WATCHDOG_SCRIPT" --maintenance-start "$MAINT_REASON" >/dev/null 2>&1 || true
    maintenance_started=1
    log "maintenance started: ${MAINT_REASON}"
  else
    log "watchdog disabled or missing; maintenance handshake skipped"
  fi
}

finish_maintenance() {
  local reason="$1"
  if [ "$maintenance_started" -eq 1 ] && watchdog_enabled && [ -x "$WATCHDOG_SCRIPT" ]; then
    bash "$WATCHDOG_SCRIPT" --maintenance-ok "$reason" >/dev/null 2>&1 || true
    log "maintenance finished: ${reason}"
  fi
}

rescue_if_needed() {
  local reason="$1"
  if [ "$maintenance_started" -eq 1 ] && watchdog_enabled && [ -x "$WATCHDOG_SCRIPT" ]; then
    bash "$WATCHDOG_SCRIPT" --rescue "$reason" >/dev/null 2>&1 || true
    log "rescue requested: ${reason}"
  fi
}

clear_maintenance_state() {
  local tmp
  [ -f "$STATE_FILE" ] || return 0
  tmp="$(mktemp)"
  jq '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0' "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
  log "maintenance state cleared directly"
}

is_healthy() {
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

wait_healthy() {
  local i
  for i in $(seq 1 24); do
    if is_healthy; then
      return 0
    fi
    sleep 5
  done
  return 1
}

restart_gateway() {
  if [ ! -x "$BOOT_SCRIPT" ]; then
    log "boot script missing: $BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new-session -d -s openclaw "$BOOT_SCRIPT"
  log "gateway restarted"
}

on_exit() {
  local rc=$?
  trap - EXIT

  if [ "$maintenance_started" -eq 1 ] && [ "$update_success" -ne 1 ]; then
    log "update aborted (rc=${rc}); attempting runtime recovery"
    restart_gateway || true
    if wait_healthy; then
      finish_maintenance "update-abort-recovered"
    else
      clear_maintenance_state || true
      rescue_if_needed "update-abort-unhealthy"
      log "runtime still unhealthy after abort; rescue requested"
    fi
  fi

  release_lock
  exit "$rc"
}
trap on_exit EXIT

require_cmd openclaw
require_cmd npm
require_cmd tmux
require_cmd jq
require_cmd timeout

acquire_lock
ensure_npm_prefix

log "update started"
start_maintenance

ts="$(date +%Y%m%d-%H%M%S)"
tar -czf "${HOME_DIR}/backups/openclaw-state-${ts}.tar.gz" \
  "${HOME_DIR}/.openclaw" \
  "${HOME_DIR}/.termux" \
  "${HOME_DIR}/.openclaw-watchdog.env" >/dev/null 2>&1 || true
log "backup snapshot created: openclaw-state-${ts}.tar.gz"

log "checking status before update"
openclaw update status --json >"${TMP_DIR}/openclaw-update-status-before.json" 2>&1 || true
before_version="$(current_openclaw_version)"
latest_version="$(detect_latest_version)"
log "version before=${before_version:-unknown}, npm_latest=${latest_version:-unknown}, npm_target=${OPENCLAW_NPM_TARGET}"

log "running openclaw update"
if openclaw update --yes --json >"${TMP_DIR}/openclaw-update-result.json" 2>&1; then
  cli_update_rc=0
else
  cli_update_rc=$?
  had_errors=1
  log "openclaw update command returned non-zero (${cli_update_rc}); continue with npm fallback"
fi

after_version="$(current_openclaw_version)"
needs_npm_fallback=0
if bool_true "$FORCE_NPM_UPDATE"; then
  needs_npm_fallback=1
elif [ "$cli_update_rc" -ne 0 ]; then
  needs_npm_fallback=1
elif [ "$OPENCLAW_NPM_TARGET" != "latest" ] && [ "$after_version" != "$OPENCLAW_NPM_TARGET" ]; then
  needs_npm_fallback=1
elif [ -n "$latest_version" ] && [ "$after_version" != "$latest_version" ]; then
  needs_npm_fallback=1
fi

if [ "$needs_npm_fallback" -eq 1 ]; then
  if [ "$OPENCLAW_NPM_TARGET" = "latest" ]; then
    local_target="${latest_version:-latest}"
  else
    local_target="$OPENCLAW_NPM_TARGET"
  fi
  log "running termux npm fallback update (target=${local_target}, ignore-scripts=1)"
  # Termux often fails native postinstall (e.g. koffi/renameat2). ignore-scripts is safer here.
  if ! npm install -g "openclaw@${local_target}" \
      --prefix "$NPM_PREFIX_DIR" \
      --ignore-scripts \
      --no-audit \
      --no-fund >>"$UPDATE_LOG" 2>&1; then
    had_errors=1
    log "npm fallback update failed; continue with restart/health checks"
  else
    hash -r
    after_version="$(current_openclaw_version)"
    log "npm fallback applied; version now=${after_version:-unknown}"
  fi
else
  log "npm fallback skipped (already at target)"
fi

if bool_true "$ENABLE_AUTO_UPDATE"; then
  log "persisting update channel: ${CHANNEL_TARGET}"
  if ! openclaw update --channel "$CHANNEL_TARGET" --yes --no-restart --json >>"$UPDATE_LOG" 2>&1; then
    had_errors=1
    log "persist update channel failed"
  fi
fi

log "running doctor fix"
if ! openclaw doctor --fix >>"$UPDATE_LOG" 2>&1; then
  had_errors=1
  log "doctor fix returned non-zero"
fi

restart_gateway

if ! wait_healthy; then
  log "health check failed after update"
  clear_maintenance_state || true
  rescue_if_needed "main-system-update-healthcheck-failed"
  log "automatic rescue requested due to post-update unhealthy runtime"
  exit 1
fi

after_version="$(current_openclaw_version)"
if [ -n "$latest_version" ] && [ "$after_version" != "$latest_version" ]; then
  had_errors=1
  log "warning: runtime healthy but version mismatch (current=${after_version}, latest=${latest_version})"
fi

finish_maintenance "update-success"
update_success=1
if [ "$had_errors" -eq 1 ]; then
  log "update finished with warnings (runtime healthy)"
else
  log "update finished successfully"
fi
openclaw --version | tee -a "$UPDATE_LOG"
log "version summary: before=${before_version:-unknown}, after=${after_version:-unknown}, latest=${latest_version:-unknown}"
