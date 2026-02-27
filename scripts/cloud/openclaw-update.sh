#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
LOG_DIR="$HOME/openclaw-logs"
LOG_FILE="$LOG_DIR/cloud-update.log"
mkdir -p "$LOG_DIR"

log() {
  printf '[%s] [cloud-update] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [ -z "$OPENCLAW_BIN" ] && [ -x "$HOME/.npm-global/bin/openclaw" ]; then
  OPENCLAW_BIN="$HOME/.npm-global/bin/openclaw"
fi
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"

before="$($OPENCLAW_BIN --version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
log "before_version=${before:-unknown}"

update_ok=0
if $OPENCLAW_BIN update --yes --json >>"$LOG_FILE" 2>&1; then
  update_ok=1
else
  log "openclaw update failed/skipped, fallback to npm"
fi

if [ "$update_ok" -ne 1 ]; then
  npm install -g openclaw@latest --no-audit --no-fund >>"$LOG_FILE" 2>&1
fi

OPENCLAW_NPM_TARGET=latest bash "$HOME/cloud/openclaw-rebuild.sh" >>"$LOG_FILE" 2>&1

after="$($OPENCLAW_BIN --version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
log "after_version=${after:-unknown}"
log "update completed"
