#!/usr/bin/env bash
set -euo pipefail

OPENCLAW_ENV="${OPENCLAW_ENV:-/home/ubuntu/.openclaw/openclaw.env}"
KEYPOOL_URL="${KEYPOOL_URL:-http://127.0.0.1:18889/__keypool/status}"
STATE_DIR="${STATE_DIR:-/home/ubuntu/.openclaw-watchdog}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/keypool-daily-report-state.json}"
OWNER_ID="${TELEGRAM_OWNER_ID:-6002298888}"

mkdir -p "$STATE_DIR"

if [ ! -f "$OPENCLAW_ENV" ]; then
  exit 0
fi

TOKEN="$(sed -n 's/^TELEGRAM_BOT_TOKEN="\(.*\)"$/\1/p' "$OPENCLAW_ENV" | head -n1)"
[ -n "$TOKEN" ] || exit 0

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

curl -fsS --max-time 20 \
  -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  -d "chat_id=${OWNER_ID}" \
  --data-urlencode "text=${msg}" \
  -d "disable_web_page_preview=true" >/dev/null 2>&1 || true

tmp="$(mktemp)"
jq -n --arg d "$today" '{last_day:$d,updated_at:(now|floor)}' >"$tmp"
mv "$tmp" "$STATE_FILE"
