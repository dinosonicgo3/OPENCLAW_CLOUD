#!/usr/bin/env bash
set -euo pipefail

HOME_DIR="${HOME:-/home/ubuntu}"
CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME_DIR/.openclaw/openclaw.json}"
ENV_FILE="${OPENCLAW_ENV_FILE:-$HOME_DIR/.openclaw/openclaw.env}"
GATEWAY_LOG_FILE="${OPENCLAW_GATEWAY_LOG:-$HOME_DIR/openclaw-logs/gateway.log}"
RUNTIME_LOG_DIR="${OPENCLAW_RUNTIME_LOG_DIR:-/tmp/openclaw}"
STATE_DIR="${OPENCLAW_SUBAGENT_MONITOR_STATE_DIR:-$HOME_DIR/.openclaw-subagent-monitor}"
STATE_FILE="$STATE_DIR/state.json"
LOCK_DIR="$STATE_DIR/sentinel.lock"
PID_FILE="$STATE_DIR/sentinel.pid"
ALERT_COOLDOWN_SECONDS="${OPENCLAW_SUBAGENT_ALERT_COOLDOWN_SECONDS:-180}"
SCAN_INTERVAL_SECONDS="${OPENCLAW_SUBAGENT_SCAN_INTERVAL_SECONDS:-5}"
SCAN_WINDOW_SECONDS="${OPENCLAW_SUBAGENT_SCAN_WINDOW_SECONDS:-420}"
SCAN_LINES="${OPENCLAW_SUBAGENT_SCAN_LINES:-2200}"
STARTUP_NOTIFY="${OPENCLAW_SUBAGENT_MONITOR_STARTUP_NOTIFY:-0}"
TELEGRAM_CHUNK_BODY_CHARS="${TELEGRAM_CHUNK_BODY_CHARS:-3500}"
TEMP_CLEANUP_RETENTION_DAYS="${TEMP_CLEANUP_RETENTION_DAYS:-7}"
TEMP_CLEANUP_INTERVAL_SECONDS="${TEMP_CLEANUP_INTERVAL_SECONDS:-21600}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"

mkdir -p "$STATE_DIR" "$(dirname "$GATEWAY_LOG_FILE")" "$HOME_DIR/openclaw-logs"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

if [ -z "$TELEGRAM_OWNER_ID" ] && [ -f "$CONFIG_PATH" ]; then
  TELEGRAM_OWNER_ID="$(jq -r '.channels.telegram.allowFrom[0] // empty' "$CONFIG_PATH" 2>/dev/null || true)"
fi

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [subagent-sentinel] %s\n' "$ts" "$*" >>"$HOME_DIR/openclaw-logs/subagent-sentinel.log"
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_alert_key": "",
  "last_alert_ts": 0,
  "last_scan_ts": 0,
  "last_cleanup_ts": 0
}
EOF
  fi
  state_set '.last_alert_key=(.last_alert_key // "") | .last_alert_ts=(.last_alert_ts // 0) | .last_scan_ts=(.last_scan_ts // 0) | .last_cleanup_ts=(.last_cleanup_ts // 0)'
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE" 2>/dev/null || echo ""
}

state_set() {
  local expr="$1"
  local tmp
  tmp="$(mktemp)"
  jq "$expr" "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

acquire_lock() {
  local existing
  if ! mkdir "$LOCK_DIR" >/dev/null 2>&1; then
    existing="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing" ] && kill -0 "$existing" >/dev/null 2>&1; then
      log "already running (pid=${existing})"
      exit 0
    fi
    rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
    mkdir "$LOCK_DIR" >/dev/null 2>&1 || {
      log "failed to acquire lock"
      exit 1
    }
  fi
  echo "$$" >"$PID_FILE"
}

cleanup_lock() {
  rm -f "$PID_FILE" >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}

send_telegram() {
  local msg="$1"
  local chunk part idx total prefix
  local -a chunks
  chunks=()
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0
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
    telegram_send_raw "$TELEGRAM_OWNER_ID" "$part"
  done
}

telegram_send_raw() {
  local chat_id="$1"
  local msg="$2"
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$chat_id" ] || return 0
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
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

cleanup_completed_handoff_tasks() {
  local task_dir="$HOME_DIR/OpenClawVault/interop/tasks"
  local retention_days="$1"
  [ -d "$task_dir" ] || {
    printf '0'
    return 0
  }
  python3 - "$task_dir" "$retention_days" <<'PY' 2>/dev/null || echo 0
import json
import pathlib
import sys
import time

task_dir = pathlib.Path(sys.argv[1])
days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
if days < 1:
    days = 7
cutoff = time.time() - days * 86400
removed = 0
for path in task_dir.glob("*.json"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    status = str(data.get("status") or "").lower()
    if status not in {"done", "failed", "skipped"}:
        continue
    ts = data.get("updated_at") or data.get("completed_at")
    try:
        ts = float(ts)
    except Exception:
        ts = path.stat().st_mtime
    if ts <= cutoff:
        try:
            path.unlink()
            removed += 1
        except Exception:
            pass
print(removed)
PY
}

run_temp_cleanup_once() {
  local days deleted_tmp deleted_runtime deleted_state deleted_logs deleted_handoff
  days="$TEMP_CLEANUP_RETENTION_DAYS"
  [[ "$days" =~ ^[0-9]+$ ]] || days=7
  [ "$days" -ge 1 ] || days=7
  deleted_tmp=0
  deleted_runtime=0
  deleted_state=0
  deleted_logs=0
  deleted_handoff=0

  if [ -d "$HOME_DIR/tmp" ]; then
    deleted_tmp="$(find "$HOME_DIR/tmp" -mindepth 1 -type f -mtime +"$days" -print -delete 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
    find "$HOME_DIR/tmp" -mindepth 1 -type d -empty -mtime +"$days" -delete 2>/dev/null || true
  fi
  if [ -d "$RUNTIME_LOG_DIR" ]; then
    deleted_runtime="$(find "$RUNTIME_LOG_DIR" -mindepth 1 -type f -mtime +"$days" -print -delete 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
    find "$RUNTIME_LOG_DIR" -mindepth 1 -type d -empty -mtime +"$days" -delete 2>/dev/null || true
  fi
  if [ -d "$STATE_DIR" ]; then
    deleted_state="$(find "$STATE_DIR" -maxdepth 3 -type f \( -name '*.tmp' -o -name '*.temp' -o -name '*test*' -o -name '*.partial' \) -mtime +"$days" -print -delete 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
  fi
  if [ -d "$HOME_DIR/openclaw-logs" ]; then
    deleted_logs="$(find "$HOME_DIR/openclaw-logs" -maxdepth 3 -type f \( -name '*.tmp' -o -name '*.temp' -o -name '*test*' -o -name '*.partial' \) -mtime +"$days" -print -delete 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
  fi
  deleted_handoff="$(cleanup_completed_handoff_tasks "$days")"
  log "temp cleanup: days=${days} home_tmp=${deleted_tmp} runtime_tmp=${deleted_runtime} state_tmp=${deleted_state} log_tmp=${deleted_logs} handoff_done=${deleted_handoff}"
}

maybe_run_temp_cleanup() {
  local now last interval
  now="$(date +%s)"
  interval="$TEMP_CLEANUP_INTERVAL_SECONDS"
  [[ "$interval" =~ ^[0-9]+$ ]] || interval=21600
  [ "$interval" -ge 60 ] || interval=21600
  last="$(state_get '.last_cleanup_ts // 0')"
  [ -n "$last" ] || last=0
  if [ "$last" -gt 0 ] && [ "$((now - last))" -lt "$interval" ]; then
    return 0
  fi
  run_temp_cleanup_once || true
  state_set ".last_cleanup_ts=${now}"
}

model_info() {
  if [ ! -f "$CONFIG_PATH" ]; then
    echo "primary=unknown subagent=unknown timeout=unknown concurrency=unknown"
    return 0
  fi
  local primary submodel timeout conc
  primary="$(jq -r '.agents.defaults.model.primary // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  submodel="$(jq -r '.agents.defaults.subagents.model // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  timeout="$(jq -r '.agents.defaults.subagents.runTimeoutSeconds // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  conc="$(jq -r '.agents.defaults.subagents.maxConcurrent // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo unknown)"
  echo "primary=${primary} subagent=${submodel} timeout=${timeout}s maxConcurrent=${conc}"
}

latest_runtime_log() {
  find "$RUNTIME_LOG_DIR" -maxdepth 1 -type f -name 'openclaw-*.log' 2>/dev/null | sort | tail -n1
}

detect_recent_subagent_failure() {
  local runtime_log
  runtime_log="$(latest_runtime_log)"
  python3 - "$runtime_log" "$GATEWAY_LOG_FILE" "$SCAN_LINES" "$SCAN_WINDOW_SECONDS" <<'PY' 2>/dev/null || echo '{"found":false}'
import collections
import datetime as dt
import hashlib
import json
import re
import sys

runtime_log, gateway_log, max_lines, window_sec = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
json_ts = re.compile(r'"time":"([^"]+)"')
iso_ts = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)')
fail_pat = re.compile(
    r'lane task error: .*subagent.*timed out|'
    r'lane task error: lane=subagent.*timed out|'
    r'FailoverError: LLM request timed out|'
    r'sessions_spawn.*(error|failed|fail)|'
    r'subagent.*(failed|timed out|did not report|no report|without report|loop)',
    re.I,
)
ignore_pat = re.compile(r'sessions_spawn tool start|sessions_spawn tool end|waiting for run end: .*timeoutMs=', re.I)
now = dt.datetime.now(dt.timezone.utc)

def tail_lines(path, n):
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return list(collections.deque(f, maxlen=n))
    except Exception:
        return []

def parse_ts(line):
    m = json_ts.search(line) or iso_ts.search(line)
    if not m:
        return None
    raw = m.group(1).replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(raw)
    except Exception:
        return None

latest = None
for path in (runtime_log, gateway_log):
    for line in tail_lines(path, max_lines):
        if ignore_pat.search(line):
            continue
        low = line.lower()
        if "iserror=false" in low:
            continue
        if not fail_pat.search(line):
            continue
        ts = parse_ts(line)
        if ts is not None and (now - ts).total_seconds() > window_sec:
            continue
        latest = (ts, line.strip(), path)

if latest is None:
    print(json.dumps({"found": False}, ensure_ascii=False))
    raise SystemExit

ts, line, path = latest
low = line.lower()
reason = "subagent-failed"
if "did not report" in low or "no report" in low or "without report" in low:
    reason = "subagent-no-report"
elif "loop" in low:
    reason = "subagent-loop"
elif "timed out" in low:
    reason = "subagent-timeout"
elif "sessions_spawn" in low and ("error" in low or "fail" in low):
    reason = "sessions-spawn-failed"
key = hashlib.sha1(f"{reason}|{line}".encode("utf-8", "ignore")).hexdigest()[:16]
print(json.dumps({
    "found": True,
    "reason": reason,
    "key": key,
    "excerpt": line[:220],
    "timestamp": ts.isoformat() if ts else "",
    "source": path,
}, ensure_ascii=False))
PY
}

maybe_alert_diag() {
  local diag found reason key excerpt ts source now last_key last_ts reason_text info
  diag="${1:-}"
  found="$(printf '%s' "$diag" | jq -r '.found // false' 2>/dev/null || echo false)"
  [ "$found" = "true" ] || return 0

  reason="$(printf '%s' "$diag" | jq -r '.reason // "subagent-failed"' 2>/dev/null || echo subagent-failed)"
  key="$(printf '%s' "$diag" | jq -r '.key // ""' 2>/dev/null || true)"
  excerpt="$(printf '%s' "$diag" | jq -r '.excerpt // ""' 2>/dev/null || true)"
  ts="$(printf '%s' "$diag" | jq -r '.timestamp // ""' 2>/dev/null || true)"
  source="$(printf '%s' "$diag" | jq -r '.source // ""' 2>/dev/null || true)"
  now="$(date +%s)"
  last_key="$(state_get '.last_alert_key // ""')"
  last_ts="$(state_get '.last_alert_ts // 0')"
  [ -n "$last_ts" ] || last_ts=0
  [ -n "$key" ] || key="no-key-$now"

  if [ "$key" = "$last_key" ] && [ "$((now - last_ts))" -lt "$ALERT_COOLDOWN_SECONDS" ]; then
    return 0
  fi
  if [ "$last_ts" -gt 0 ] && [ "$((now - last_ts))" -lt "$ALERT_COOLDOWN_SECONDS" ]; then
    log "alert throttled: reason=${reason}, key=${key}"
    return 0
  fi

  case "$reason" in
    subagent-timeout) reason_text="子代理執行逾時（超過時限）" ;;
    sessions-spawn-failed) reason_text="子代理建立失敗（sessions_spawn 失敗）" ;;
    subagent-no-report) reason_text="子代理未回報結果（no report）" ;;
    subagent-loop) reason_text="子代理疑似迴圈（loop）" ;;
    *) reason_text="子代理執行失敗" ;;
  esac

  info="$(model_info)"
  send_telegram "🚨 主系統子代理告警：${reason_text}
- ${info}
- 來源：${source:-unknown}
- 事件時間：${ts:-未知}
- 摘要：$(printf '%s' "$excerpt" | sed -E 's/[[:space:]]+/ /g' | cut -c1-220)"
  log "alert reason=${reason} key=${key} source=${source} line=$(printf '%s' "$excerpt" | cut -c1-220)"
  state_set ".last_alert_key=\"${key}\" | .last_alert_ts=${now} | .last_scan_ts=${now}"
}

monitor_loop() {
  local diag
  touch "$GATEWAY_LOG_FILE"
  while true; do
    diag="$(detect_recent_subagent_failure)"
    maybe_alert_diag "$diag"
    maybe_run_temp_cleanup
    sleep "$SCAN_INTERVAL_SECONDS"
  done
}

main() {
  state_init
  acquire_lock
  trap 'cleanup_lock' EXIT INT TERM HUP
  if [ "$STARTUP_NOTIFY" = "1" ]; then
    send_telegram "🧭 主系統子代理監控已啟動（單例模式）。"
  fi
  log "started, gateway_log=$GATEWAY_LOG_FILE, scan_interval=${SCAN_INTERVAL_SECONDS}s, cooldown=${ALERT_COOLDOWN_SECONDS}s"
  monitor_loop
}

main "$@"
