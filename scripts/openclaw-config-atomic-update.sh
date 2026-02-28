#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
BACKUP_DIR="${OPENCLAW_CONFIG_BACKUP_DIR:-$HOME/.openclaw/backups}"
OPENCLAW_BIN="${OPENCLAW_BIN:-$HOME/.npm-global/bin/openclaw}"
SERVICE_NAME="${OPENCLAW_SERVICE_NAME:-openclaw.service}"

JQ_FILTER=""
JQ_FILE=""
REPLACE_FILE=""
DRY_RUN=0
RESTART=0

usage() {
  cat <<USAGE
Usage:
  openclaw-config-atomic-update.sh --jq '<jq_filter>' [--restart] [--dry-run]
  openclaw-config-atomic-update.sh --jq-file <jq_file> [--restart] [--dry-run]
  openclaw-config-atomic-update.sh --replace-with <json_file> [--restart] [--dry-run]

Rules:
  1) Always copy current openclaw.json to candidate
  2) Modify candidate only
  3) Validate candidate JSON + strict config schema + runtime loadability
  4) Swap atomically only when all validations pass
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --jq)
      JQ_FILTER="${2:-}"
      shift 2
      ;;
    --jq-file)
      JQ_FILE="${2:-}"
      shift 2
      ;;
    --replace-with)
      REPLACE_FILE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --restart)
      RESTART=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

apply_modes=0
[ -n "$JQ_FILTER" ] && apply_modes=$((apply_modes + 1))
[ -n "$JQ_FILE" ] && apply_modes=$((apply_modes + 1))
[ -n "$REPLACE_FILE" ] && apply_modes=$((apply_modes + 1))
if [ "$apply_modes" -ne 1 ]; then
  echo "Exactly one of --jq / --jq-file / --replace-with is required." >&2
  exit 2
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "Config not found: $CONFIG_PATH" >&2
  exit 3
fi

mkdir -p "$BACKUP_DIR"
LOCK_DIR="${CONFIG_PATH}.atomic.lock"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Atomic update already in progress: $LOCK_DIR" >&2
  exit 11
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR" >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

CANDIDATE="$TMP_DIR/openclaw.json.candidate"
cp -f "$CONFIG_PATH" "$CANDIDATE"
chmod 600 "$CANDIDATE" >/dev/null 2>&1 || true

if [ -n "$REPLACE_FILE" ]; then
  cp -f "$REPLACE_FILE" "$CANDIDATE"
else
  if [ -n "$JQ_FILE" ]; then
    jq -f "$JQ_FILE" "$CANDIDATE" > "$CANDIDATE.new"
  else
    jq "$JQ_FILTER" "$CANDIDATE" > "$CANDIDATE.new"
  fi
  mv -f "$CANDIDATE.new" "$CANDIDATE"
fi

# 1) JSON syntax validation
python3 -m json.tool "$CANDIDATE" >/dev/null

# 2) Strict schema validation (fails on unknown keys/types)
STRICT_OUT="$TMP_DIR/strict.json"
STRICT_ERR="$TMP_DIR/strict.err"
if ! OPENCLAW_CONFIG_PATH="$CANDIDATE" "$OPENCLAW_BIN" config get gateway.port --json >"$STRICT_OUT" 2>"$STRICT_ERR"; then
  echo "Validation failed: candidate failed strict config schema check." >&2
  tail -n 80 "$STRICT_ERR" >&2 || true
  exit 4
fi

# 3) Runtime loadability validation
STATUS_OUT="$TMP_DIR/status.json"
STATUS_ERR="$TMP_DIR/status.err"
if ! OPENCLAW_CONFIG_PATH="$CANDIDATE" "$OPENCLAW_BIN" status --json >"$STATUS_OUT" 2>"$STATUS_ERR"; then
  echo "Validation failed: OpenClaw could not load candidate runtime config." >&2
  tail -n 80 "$STATUS_ERR" >&2 || true
  exit 4
fi
python3 - <<'PY' "$STATUS_OUT"
import json, sys
json.load(open(sys.argv[1], 'r', encoding='utf-8'))
print('[atomic-update] candidate validation: strict+runtime ok')
PY

if [ "$DRY_RUN" -eq 1 ]; then
  echo "[atomic-update] dry-run complete. Original config unchanged."
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/openclaw.json.pre-atomic.$TS"
cp -f "$CONFIG_PATH" "$BACKUP_FILE"
install -m 600 "$CANDIDATE" "$CONFIG_PATH"

echo "[atomic-update] updated config: $CONFIG_PATH"
echo "[atomic-update] backup saved: $BACKUP_FILE"

if [ "$RESTART" -eq 1 ]; then
  sudo systemctl restart "$SERVICE_NAME"
  sleep 2
  state="$(systemctl is-active "$SERVICE_NAME" || true)"
  echo "[atomic-update] service $SERVICE_NAME state=$state"
fi
