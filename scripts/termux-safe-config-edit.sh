#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
CFG_FILE="${OPENCLAW_CONFIG_PATH:-$HOME_DIR/.openclaw/openclaw.json}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$HOME_DIR/DINO_OPENCLAW/scripts/termux-openclaw-core-guard.sh}"
LOG_FILE="${OPENCLAW_SAFE_CONFIG_LOG:-$HOME_DIR/openclaw-logs/safe-config-edit.log}"

mkdir -p "$(dirname "$CFG_FILE")" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [safe-config-edit] %s\n' "$ts" "$*" >>"$LOG_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  termux-safe-config-edit.sh --jq '<jq filter>'

Examples:
  termux-safe-config-edit.sh --jq '.agents.defaults.model.primary = "nvidia/z-ai/glm4.7"'
  termux-safe-config-edit.sh --jq 'del(.models.providers.google.api)'
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing command: $1"
    exit 1
  }
}

main() {
  local jq_filter lock_dir tmp tmp2 backup
  jq_filter=""

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --jq)
        jq_filter="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage
        exit 1
        ;;
    esac
  done

  if [ -z "$jq_filter" ]; then
    usage
    exit 1
  fi

  if [ ! -f "$CFG_FILE" ]; then
    log "config missing: $CFG_FILE"
    exit 1
  fi

  require_cmd jq
  lock_dir="$CFG_FILE.lockdir"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    log "lock busy: $lock_dir"
    exit 1
  fi

  tmp="$(mktemp)"
  tmp2="$(mktemp)"
  cp -f "$CFG_FILE" "$tmp"

  if ! jq "$jq_filter" "$tmp" >"$tmp2"; then
    rm -f "$tmp" "$tmp2"
    rmdir "$lock_dir" >/dev/null 2>&1 || true
    log "jq patch failed"
    exit 1
  fi
  mv "$tmp2" "$tmp"

  if ! jq -e . "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"
    rmdir "$lock_dir" >/dev/null 2>&1 || true
    log "candidate is not valid json"
    exit 1
  fi

  if [ -x "$CORE_GUARD_SCRIPT" ]; then
    if ! OPENCLAW_CONFIG_PATH="$tmp" "$CORE_GUARD_SCRIPT" --check >/dev/null 2>&1; then
      if ! OPENCLAW_CONFIG_PATH="$tmp" "$CORE_GUARD_SCRIPT" --fix >/dev/null 2>&1; then
        rm -f "$tmp"
        rmdir "$lock_dir" >/dev/null 2>&1 || true
        log "candidate failed core-guard fix"
        exit 1
      fi
      if ! OPENCLAW_CONFIG_PATH="$tmp" "$CORE_GUARD_SCRIPT" --check >/dev/null 2>&1; then
        rm -f "$tmp"
        rmdir "$lock_dir" >/dev/null 2>&1 || true
        log "candidate failed core-guard check"
        exit 1
      fi
    fi
  fi

  if cmp -s "$CFG_FILE" "$tmp"; then
    rm -f "$tmp"
    rmdir "$lock_dir" >/dev/null 2>&1 || true
    log "no-op: candidate identical"
    printf 'unchanged\n'
    exit 0
  fi

  backup="$CFG_FILE.bak.safe-edit.$(date +%Y%m%d-%H%M%S)"
  cp -f "$CFG_FILE" "$backup" >/dev/null 2>&1 || true
  mv "$tmp" "$CFG_FILE"
  chmod 600 "$CFG_FILE" || true
  rmdir "$lock_dir" >/dev/null 2>&1 || true
  log "config updated via copy-test-swap (backup=$(basename "$backup"))"
  printf 'changed\n'
}

main "$@"
