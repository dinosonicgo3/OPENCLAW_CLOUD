#!/usr/bin/env bash
set -euo pipefail

HANDOFF_SCRIPT="${HANDOFF_SCRIPT:-/home/ubuntu/DINO_OPENCLAW/scripts/cloud/ai-handoff.sh}"
OPENCLAW_BIN="${OPENCLAW_BIN:-/home/ubuntu/.npm-global/bin/openclaw}"

if [ $# -lt 1 ]; then
  echo "Usage: request-nanobot-repair.sh <reason> [detail...]" >&2
  exit 2
fi

reason="$1"
shift || true
detail="${*:-}"

task_json="$("$HANDOFF_SCRIPT" enqueue \
  --from openclaw \
  --to nanobot \
  --type openclaw-core-fix \
  --reason "$reason" \
  --detail "$detail")"

task_id="$(printf '%s' "$task_json" | jq -r '.id // empty')"
task_file="$(printf '%s' "$task_json" | jq -r '.file // empty')"

msg="【跨代理委派任務】請潤天蟹協助修復 OpenClaw 核心。
任務ID：${task_id}
任務檔：${task_file}
原因：${reason}
細節：${detail}"

"$OPENCLAW_BIN" agent --message "$msg" --timeout 180 >/dev/null 2>&1 || true
echo "$task_json"
