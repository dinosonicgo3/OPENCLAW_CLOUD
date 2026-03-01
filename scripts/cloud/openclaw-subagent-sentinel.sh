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
  "last_scan_ts": 0
}
EOF
  fi
  state_set '.last_alert_key=(.last_alert_key // "") | .last_alert_ts=(.last_alert_ts // 0) | .last_scan_ts=(.last_scan_ts // 0)'
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
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
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
