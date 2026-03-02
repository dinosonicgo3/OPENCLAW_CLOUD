#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_ENV="${OPENCLAW_ENV:-/home/ubuntu/.openclaw/openclaw.env}"
KEYPOOL_URL="${KEYPOOL_URL:-http://127.0.0.1:18889/__keypool/status}"
STATE_DIR="${STATE_DIR:-/home/ubuntu/.openclaw-watchdog}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/keypool-daily-report-state.json}"
OWNER_ID="${TELEGRAM_OWNER_ID:-6002298888}"
TELEGRAM_CHUNK_BODY_CHARS="${TELEGRAM_CHUNK_BODY_CHARS:-3500}"
TEMP_CLEANUP_RETENTION_DAYS="${TEMP_CLEANUP_RETENTION_DAYS:-7}"

mkdir -p "$STATE_DIR"

if [ ! -f "$OPENCLAW_ENV" ]; then
  exit 0
fi

TOKEN="$(sed -n 's/^TELEGRAM_BOT_TOKEN="\(.*\)"$/\1/p' "$OPENCLAW_ENV" | head -n1)"
[ -n "$TOKEN" ] || exit 0

telegram_send_raw() {
  local chat_id="$1"
  local msg="$2"
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
    -d "chat_id=${chat_id}" \
    --data-urlencode "text=${msg}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

split_telegram_text_chunks() {
  local msg="$1" max_chars="${2:-$TELEGRAM_CHUNK_BODY_CHARS}"
  [[ "$max_chars" =~ ^[0-9]+$ ]] || max_chars=3500
  [ "$max_chars" -ge 200 ] || max_chars=3500
  printf '%s' "$msg" | python3 - "$max_chars" <<'PY'
import sys

max_chars = int(sys.argv[1]) if len(sys.argv) > 1 else 3500
if max_chars < 200:
    max_chars = 3500
text = sys.stdin.read()
if text is None:
    text = ""
chunks = []
remaining = text
while len(remaining) > max_chars:
    window = remaining[:max_chars]
    cut = max(window.rfind("\n\n"), window.rfind("\n"), window.rfind(" "))
    if cut < int(max_chars * 0.5):
        cut = max_chars
    chunk = remaining[:cut].rstrip()
    if not chunk:
        chunk = remaining[:max_chars]
    chunks.append(chunk)
    remaining = remaining[len(chunk):].lstrip()
chunks.append(remaining)
for part in chunks:
    sys.stdout.write(part)
    sys.stdout.write("\0")
PY
}

send_telegram_chunked() {
  local chat_id="$1"
  local msg="$2"
  local chunk part idx total prefix
  local -a chunks
  chunks=()
  while IFS= read -r -d '' chunk; do
    chunks+=("$chunk")
  done < <(split_telegram_text_chunks "$msg" "$TELEGRAM_CHUNK_BODY_CHARS")
  if [ "${#chunks[@]}" -eq 0 ]; then
    chunks+=("$msg")
  fi
  total="${#chunks[@]}"
  for idx in "${!chunks[@]}"; do
    part="${chunks[$idx]}"
    if [ "$total" -gt 1 ]; then
      prefix="[$((idx + 1))/${total}] "
      part="${prefix}${part}"
    fi
    telegram_send_raw "$chat_id" "$part"
  done
}

run_temp_cleanup_once() {
  local days
  days="$TEMP_CLEANUP_RETENTION_DAYS"
  [[ "$days" =~ ^[0-9]+$ ]] || days=7
  [ "$days" -ge 1 ] || days=7
  if [ -d "/home/ubuntu/tmp" ]; then
    find "/home/ubuntu/tmp" -mindepth 1 -type f -mtime +"$days" -delete 2>/dev/null || true
    find "/home/ubuntu/tmp" -mindepth 1 -type d -empty -mtime +"$days" -delete 2>/dev/null || true
  fi
  if [ -d "/tmp/openclaw" ]; then
    find "/tmp/openclaw" -mindepth 1 -type f -mtime +"$days" -delete 2>/dev/null || true
    find "/tmp/openclaw" -mindepth 1 -type d -empty -mtime +"$days" -delete 2>/dev/null || true
  fi
}

today="$(date +%F)"
last_day=""
if [ -f "$STATE_FILE" ]; then
  last_day="$(jq -r '.last_day // empty' "$STATE_FILE" 2>/dev/null || true)"
fi
if [ "$last_day" = "$today" ]; then
  exit 0
fi

status_file="$(mktemp)"
trap 'rm -f "$status_file"' EXIT
if ! curl -fsS --max-time 10 "$KEYPOOL_URL" -o "$status_file" 2>/dev/null; then
  exit 0
fi
if [ "$(jq -r '.ok // false' "$status_file" 2>/dev/null || echo false)" != "true" ]; then
  exit 0
fi

msg="$(python3 - "$status_file" "$OPENCLAW_ENV" <<'PY'
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
env_path = Path(sys.argv[2])
status = json.loads(status_path.read_text(encoding="utf-8"))
id_map = {}
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if not k.startswith("GOOGLE_API_KEY_"):
            continue
        v = v.strip().strip('"').strip("'")
        if not v:
            continue
        kid = hashlib.sha1(v.encode("utf-8", "ignore")).hexdigest()[:12]
        m = re.match(r"GOOGLE_API_KEY_([A-Z])$", k)
        user_label = "(未知序號)"
        if m:
            idx = ord(m.group(1)) - ord("A") + 3
            user_label = f"GOOGLE_KEY_{idx}"
        id_map[kid] = {"env_name": k, "user_label": user_label}

keys = status.get("keys", [])
blocked = [x for x in keys if bool(x.get("blocked"))]
total = len(keys)
avail = max(total - len(blocked), 0)

lines = [
    "📘 引天渡每日 Key 池回報",
    f"- 日期：{dt.datetime.now().strftime('%Y-%m-%d')}",
    f"- Google 可用：{avail}/{total}",
    f"- 已封鎖：{len(blocked)} 把",
]
if blocked:
    lines.append("- 封鎖清單：")
    for item in blocked:
        kid = str(item.get("id") or "")
        meta = id_map.get(kid, {})
        env_name = meta.get("env_name") or "(未知環境變數)"
        user_label = meta.get("user_label") or "(未知序號)"
        reason = ((item.get("last_error") or {}).get("reason") or "unknown").strip()
        code = (item.get("last_error") or {}).get("status")
        until = int(item.get("blocked_until") or 0)
        if until > 0:
            t = dt.datetime.fromtimestamp(until, tz=dt.timezone.utc).astimezone(dt.timezone(dt.timedelta(hours=8)))
            until_text = t.strftime("%Y-%m-%d %H:%M:%S")
        else:
            until_text = "未知"
        if reason == "invalid-key":
            reason_text = "金鑰無效/風險"
        elif reason == "quota":
            reason_text = "額度用盡"
        else:
            reason_text = "未知"
        lines.append(f"  - {user_label}（{env_name}）: {reason_text}, HTTP {code}, 解封 {until_text}")
print("\n".join(lines))
PY
)"

send_telegram_chunked "$OWNER_ID" "$msg"

tmp="$(mktemp)"
jq -n --arg d "$today" '{last_day:$d,updated_at:(now|floor)}' >"$tmp"
mv "$tmp" "$STATE_FILE"
run_temp_cleanup_once
