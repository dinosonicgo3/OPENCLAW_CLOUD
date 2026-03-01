#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
BACKUP_DIR="${OPENCLAW_CONFIG_BACKUP_DIR:-$HOME/.openclaw/backups}"
OPENCLAW_BIN="${OPENCLAW_BIN:-$HOME/.npm-global/bin/openclaw}"
SERVICE_NAME="${OPENCLAW_SERVICE_NAME:-openclaw.service}"
BASELINE_PROFILE_PATH="${OPENCLAW_BASELINE_PROFILE_PATH:-$HOME/DINO_OPENCLAW/scripts/cloud/openclaw.stable.full.json}"
DISALLOW_MINIMAL_TEMPLATE="${OPENCLAW_DISALLOW_MINIMAL_TEMPLATE:-1}"
BACKUP_KEEP_COUNT="${OPENCLAW_BACKUP_KEEP_COUNT:-15}"
BACKUP_MAX_AGE_DAYS="${OPENCLAW_BACKUP_MAX_AGE_DAYS:-7}"

JQ_FILTER=""
JQ_FILE=""
REPLACE_FILE=""
DRY_RUN=0
RESTART=0

prune_openclaw_backups() {
  local keep max_age remaining
  keep="$BACKUP_KEEP_COUNT"
  max_age="$BACKUP_MAX_AGE_DAYS"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=15
  [[ "$max_age" =~ ^[0-9]+$ ]] || max_age=7

  if [ ! -d "$BACKUP_DIR" ]; then
    return 0
  fi

  if [ "$max_age" -gt 0 ]; then
    find "$BACKUP_DIR" -maxdepth 1 -type f \
      \( -name 'openclaw.json.pre-*' -o -name 'openclaw.json.bak.*' \) \
      -mtime +"$max_age" -delete 2>/dev/null || true
  fi

  if [ "$keep" -ge 0 ]; then
    local idx=0
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      idx=$((idx + 1))
      if [ "$idx" -le "$keep" ]; then
        continue
      fi
      rm -f "$file" >/dev/null 2>&1 || true
    done < <(
      find "$BACKUP_DIR" -maxdepth 1 -type f \
        \( -name 'openclaw.json.pre-*' -o -name 'openclaw.json.bak.*' \) \
        -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr \
        | awk '{ $1=""; sub(/^ /,""); print }'
    )
  fi

  remaining="$(find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'openclaw.json.pre-*' -o -name 'openclaw.json.bak.*' \) | wc -l | tr -d ' ' || echo 0)"
  echo "[atomic-update] backup prune keep=$keep ageDays=$max_age remaining=$remaining"
}

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

if [ -n "$REPLACE_FILE" ] && [ "$DISALLOW_MINIMAL_TEMPLATE" = "1" ]; then
  case "$REPLACE_FILE" in
    */OpenClawVault/config/openclaw-template.json|*/OpenClawVault/config/openclaw-backup-20260226.json|*/OpenClawVault/config/openclaw-backup-20260227.json)
      echo "Validation failed: replace-with source is a known minimal template/legacy backup and is blocked by policy." >&2
      exit 6
      ;;
  esac
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

# 4) Policy validation: block minimal-template profile and accidental model shrink.
POLICY_OUT="$TMP_DIR/policy.out"
POLICY_ERR="$TMP_DIR/policy.err"
if ! python3 - "$CANDIDATE" "$BASELINE_PROFILE_PATH" "$DISALLOW_MINIMAL_TEMPLATE" >"$POLICY_OUT" 2>"$POLICY_ERR" <<'PY'
import json
import pathlib
import sys

candidate_path = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])
disallow_minimal = str(sys.argv[3]).strip().lower() in ("1", "true", "yes", "on")

candidate = json.loads(candidate_path.read_text(encoding="utf-8"))

def provider_models_count(obj, provider):
    p = (((obj or {}).get("models") or {}).get("providers") or {}).get(provider)
    if not isinstance(p, dict):
        return 0
    m = p.get("models")
    return len(m) if isinstance(m, list) else 0

def provider_model_ids(obj, provider):
    p = (((obj or {}).get("models") or {}).get("providers") or {}).get(provider)
    if not isinstance(p, dict):
        return []
    out = []
    for item in (p.get("models") or []):
        if isinstance(item, dict):
            mid = str(item.get("id") or "").strip()
            if mid:
                out.append(mid)
    return out

def allow_count(obj):
    allow = ((((obj or {}).get("agents") or {}).get("defaults") or {}).get("models"))
    return len(allow) if isinstance(allow, dict) else 0

openrouter_ids = provider_model_ids(candidate, "openrouter")
known_minimal = {
    "anthropic/claude-3.5-sonnet",
    "google/gemini-pro-1.5",
    "openai/gpt-4o",
    "deepseek/deepseek-chat",
}
if disallow_minimal:
    if len(openrouter_ids) <= 4 and set(openrouter_ids).issubset(known_minimal):
        raise SystemExit("policy violation: candidate matches known minimal OpenRouter template signature")

baseline = None
if baseline_path.is_file():
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"policy violation: cannot parse baseline profile file: {baseline_path} ({exc})")

checks = ["openrouter", "nvidia", "google", "opencode"]
if baseline is not None:
    for name in checks:
        floor = provider_models_count(baseline, name)
        if floor <= 0:
            continue
        have = provider_models_count(candidate, name)
        if have < floor:
            raise SystemExit(f"policy violation: provider {name} models shrank below baseline ({have} < {floor})")
    allow_floor = allow_count(baseline)
    if allow_floor > 0:
        allow_have = allow_count(candidate)
        if allow_have < allow_floor:
            raise SystemExit(f"policy violation: allowlist shrank below baseline ({allow_have} < {allow_floor})")
else:
    # Fallback floor if baseline is absent.
    if provider_models_count(candidate, "openrouter") < 20:
        raise SystemExit("policy violation: openrouter model count too low without baseline (<20)")
    if provider_models_count(candidate, "nvidia") < 4:
        raise SystemExit("policy violation: nvidia model count too low without baseline (<4)")

print("[atomic-update] candidate validation: profile policy ok")
PY
then
  echo "Validation failed: candidate violates full-profile rescue policy." >&2
  tail -n 80 "$POLICY_ERR" >&2 || true
  exit 5
fi
cat "$POLICY_OUT"

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

prune_openclaw_backups
