#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
LOG_DIR="$HOME/openclaw-logs"
LOG_FILE="$LOG_DIR/cloud-rebuild.log"
mkdir -p "$LOG_DIR" "$HOME/.openclaw/backups"

log() {
  printf '[%s] [cloud-rebuild] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [ -z "$OPENCLAW_BIN" ] && [ -x "$HOME/.npm-global/bin/openclaw" ]; then
  OPENCLAW_BIN="$HOME/.npm-global/bin/openclaw"
fi
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
TARGET="${OPENCLAW_NPM_TARGET:-latest}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$HOME/cloud/openclaw-coreguard.sh}"
BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME/cloud/openclaw-launch.sh}"
CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
STACK_SERVICE="${OPENCLAW_STACK_SERVICE:-openclaw.service}"
ATOMIC_UPDATER="${OPENCLAW_ATOMIC_UPDATER:-$HOME/cloud/openclaw-config-atomic-update.sh}"
REPO_DIR="${OPENCLAW_REPO_DIR:-$HOME/DINO_OPENCLAW}"
REBUILD_MODE="${OPENCLAW_REBUILD_MODE:-standard}"
FORCE_STABLE_CONFIG="${OPENCLAW_REBUILD_FORCE_STABLE_CONFIG:-0}"
ROLLBACK_TAG="${OPENCLAW_ROLLBACK_TAG:-}"
STABLE_CONFIG_GIT_PATH="${OPENCLAW_STABLE_CONFIG_PATH_IN_REPO:-scripts/cloud/openclaw.stable.full.json}"
BASELINE_PROFILE_PATH="${OPENCLAW_BASELINE_PROFILE_PATH:-$REPO_DIR/$STABLE_CONFIG_GIT_PATH}"
STACK_WAS_ACTIVE=0

is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_stable_tag() {
  if [ -n "$ROLLBACK_TAG" ]; then
    printf '%s' "$ROLLBACK_TAG"
    return 0
  fi
  if [ -d "$REPO_DIR/.git" ]; then
    git -C "$REPO_DIR" tag -l '穩定版*' --sort=-creatordate | head -n1
  fi
}

materialize_stable_config() {
  local out_file="$1" tag
  tag="$(resolve_stable_tag)"
  if [ -n "$tag" ] && [ -d "$REPO_DIR/.git" ] && git -C "$REPO_DIR" cat-file -e "${tag}:${STABLE_CONFIG_GIT_PATH}" 2>/dev/null; then
    git -C "$REPO_DIR" show "${tag}:${STABLE_CONFIG_GIT_PATH}" >"$out_file"
    echo "tag:${tag}:${STABLE_CONFIG_GIT_PATH}"
    return 0
  fi
  if [ -f "$REPO_DIR/$STABLE_CONFIG_GIT_PATH" ]; then
    cp -f "$REPO_DIR/$STABLE_CONFIG_GIT_PATH" "$out_file"
    echo "worktree:$REPO_DIR/$STABLE_CONFIG_GIT_PATH"
    return 0
  fi
  return 1
}

apply_full_stable_config_if_needed() {
  local apply_needed cfg_tmp source_desc
  apply_needed=0
  if [ "$REBUILD_MODE" = "rescue" ]; then
    apply_needed=1
  fi
  if is_true_flag "$FORCE_STABLE_CONFIG"; then
    apply_needed=1
  fi
  [ "$apply_needed" -eq 1 ] || return 0

  if [ ! -x "$ATOMIC_UPDATER" ]; then
    log "stable-config apply skipped: atomic updater missing ($ATOMIC_UPDATER)"
    return 1
  fi

  cfg_tmp="$(mktemp)"
  if ! source_desc="$(materialize_stable_config "$cfg_tmp")"; then
    rm -f "$cfg_tmp"
    log "stable-config apply skipped: no git stable config found (path=$STABLE_CONFIG_GIT_PATH)"
    return 1
  fi

  log "applying full stable config source=${source_desc}"
  if ! OPENCLAW_BASELINE_PROFILE_PATH="$BASELINE_PROFILE_PATH" \
       OPENCLAW_DISALLOW_MINIMAL_TEMPLATE=1 \
       "$ATOMIC_UPDATER" --replace-with "$cfg_tmp" >>"$LOG_FILE" 2>&1; then
    rm -f "$cfg_tmp"
    log "stable-config apply failed"
    return 1
  fi
  rm -f "$cfg_tmp"
  return 0
}

if [ -f "$CONFIG_PATH" ]; then
  cp -f "$CONFIG_PATH" "$HOME/.openclaw/backups/openclaw.json.pre-rebuild.$(date +%Y%m%d-%H%M%S)"
fi

if systemctl is-active --quiet "$STACK_SERVICE"; then
  STACK_WAS_ACTIVE=1
  log "stopping stack service: $STACK_SERVICE"
  sudo systemctl stop "$STACK_SERVICE"
fi

if [ -f "$CORE_GUARD_SCRIPT" ]; then
  bash "$CORE_GUARD_SCRIPT" --fix >>"$LOG_FILE" 2>&1 || true
fi

log "stopping openclaw runtime"
tmux kill-session -t =openclaw >/dev/null 2>&1 || true
pkill -9 -f 'openclaw-gateway|openclaw gateway' >/dev/null 2>&1 || true
pkill -9 -x openclaw >/dev/null 2>&1 || true

log "reinstalling openclaw package target=$TARGET"
if [ "$TARGET" = "latest" ]; then
  npm install -g openclaw@latest --no-audit --no-fund >>"$LOG_FILE" 2>&1
else
  npm install -g "openclaw@$TARGET" --no-audit --no-fund >>"$LOG_FILE" 2>&1
fi

if ! apply_full_stable_config_if_needed; then
  log "warning: stable full-config restore did not complete"
fi

if [ -f "$CORE_GUARD_SCRIPT" ]; then
  bash "$CORE_GUARD_SCRIPT" --fix >>"$LOG_FILE" 2>&1 || true
fi

if [ ! -x "$BOOT_SCRIPT" ]; then
  chmod +x "$BOOT_SCRIPT" >/dev/null 2>&1 || true
fi

if [ "$STACK_WAS_ACTIVE" -eq 1 ]; then
  log "starting stack service: $STACK_SERVICE"
  sudo systemctl start "$STACK_SERVICE"
else
  log "starting openclaw runtime"
  tmux kill-session -t =openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "bash $BOOT_SCRIPT"
fi

PORT="$(jq -r '.gateway.port // 29876' "$CONFIG_PATH" 2>/dev/null || echo 29876)"
for _ in $(seq 1 30); do
  if pgrep -f 'openclaw-gateway|openclaw gateway' >/dev/null 2>&1; then
    if python3 - "$PORT" <<'PY' >/dev/null 2>&1
import socket,sys
p=int(sys.argv[1])
s=socket.socket(); s.settimeout(1)
try:
    s.connect(('127.0.0.1', p)); print('ok')
except Exception:
    raise SystemExit(1)
finally:
    s.close()
PY
    then
      ver="$($OPENCLAW_BIN --version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
      log "rebuild success version=${ver:-unknown} port=$PORT"
      exit 0
    fi
  fi
  sleep 2
done

log "rebuild failed: openclaw did not become healthy"
exit 1
