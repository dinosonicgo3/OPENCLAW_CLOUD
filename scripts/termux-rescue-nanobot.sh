#!/usr/bin/env bash
set -euo pipefail

NANOBOT_NAME="${NANOBOT_NAME:-runtianxie}"
NANOBOT_VERSION="1.3.0"

HOME_DIR="${HOME:-/home/ubuntu}"
REPO_DIR="${OPENCLAW_REPO_DIR:-${OPENCLAW_TERMUX_REPO_DIR:-$HOME_DIR/DINO_OPENCLAW}}"
STATE_DIR="${NANOBOT_STATE_DIR:-$HOME_DIR/.openclaw-nanobot}"
STATE_FILE="$STATE_DIR/state.json"
PID_FILE="$STATE_DIR/daemon.pid"
LOCK_DIR="$STATE_DIR/daemon.lock"
REPAIR_LOCK_DIR="$STATE_DIR/repair.lock"
ENV_FILE="${NANOBOT_ENV_FILE:-$HOME_DIR/.openclaw-nanobot.env}"
SHARED_ENV_FILE="${SHARED_ENV_FILE:-$HOME_DIR/.openclaw/openclaw.env}"
LOG_FILE="${NANOBOT_LOG_FILE:-$HOME_DIR/openclaw-logs/nanobot.log}"

CORE_GUARD_SCRIPT="${CORE_GUARD_SCRIPT:-}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-}"
OPENCLAW_REBUILD_SCRIPT="${OPENCLAW_REBUILD_SCRIPT:-}"
OPENCLAW_REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
OPENCLAW_SERVICE_NAME="${OPENCLAW_SERVICE_NAME:-openclaw.service}"
OPENCLAW_REBUILD_SERVICE="${OPENCLAW_REBUILD_SERVICE:-openclaw.service}"
NANOBOT_RUNTIME_ENV="${NANOBOT_RUNTIME_ENV:-auto}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
NANOBOT_MODEL="${NANOBOT_MODEL:-nvidia/z-ai/glm5}"
NANOBOT_BASE_URL="${NANOBOT_BASE_URL:-https://integrate.api.nvidia.com/v1}"
NANOBOT_ENABLED="${NANOBOT_ENABLED:-0}"
OPENCLAW_PORT="${OPENCLAW_PORT:-}"
NANOBOT_DIAG_LOG_LINES="${NANOBOT_DIAG_LOG_LINES:-60}"
NANOBOT_GITHUB_REPO="${NANOBOT_GITHUB_REPO:-openclaw/openclaw}"
OPENCLAW_OFFICIAL_GITHUB_URL="${OPENCLAW_OFFICIAL_GITHUB_URL:-https://github.com/openclaw/openclaw}"
HANDOFF_SCRIPT="${HANDOFF_SCRIPT:-$REPO_DIR/scripts/cloud/ai-handoff.sh}"
HANDOFF_ENABLED="${HANDOFF_ENABLED:-1}"

# Keep nanobot mostly dormant: only react to user messages by default.
AUTO_HEALTHCHECK_ENABLED="${AUTO_HEALTHCHECK_ENABLED:-0}"
AUTO_RESCUE_ON_UNHEALTHY="${AUTO_RESCUE_ON_UNHEALTHY:-0}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-1}"
TELEGRAM_LONGPOLL_TIMEOUT="${TELEGRAM_LONGPOLL_TIMEOUT:-25}"
HEALTHCHECK_INTERVAL_SECONDS="${HEALTHCHECK_INTERVAL_SECONDS:-600}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-35}"
OPENCLAW_REPLY_LAG_SECONDS="${OPENCLAW_REPLY_LAG_SECONDS:-300}"
OPENCLAW_STUCK_TASK_SECONDS="${OPENCLAW_STUCK_TASK_SECONDS:-180}"
OPENCLAW_HUNG_TASK_SECONDS="${OPENCLAW_HUNG_TASK_SECONDS:-900}"
OPENCLAW_HUNG_TASK_CPU_MAX="${OPENCLAW_HUNG_TASK_CPU_MAX:-1.0}"
OPENCLAW_TIMEOUT_STORM_LINES="${OPENCLAW_TIMEOUT_STORM_LINES:-1400}"
OPENCLAW_TIMEOUT_STORM_THRESHOLD="${OPENCLAW_TIMEOUT_STORM_THRESHOLD:-6}"
OPENCLAW_TIMEOUT_STORM_WINDOW_SECONDS="${OPENCLAW_TIMEOUT_STORM_WINDOW_SECONDS:-300}"
SUBAGENT_ALERT_CHECK_INTERVAL_SECONDS="${SUBAGENT_ALERT_CHECK_INTERVAL_SECONDS:-30}"
SUBAGENT_ALERT_WINDOW_SECONDS="${SUBAGENT_ALERT_WINDOW_SECONDS:-300}"
SUBAGENT_ALERT_LINES="${SUBAGENT_ALERT_LINES:-1800}"
GOOGLE_KEYPOOL_STATUS_URL="${GOOGLE_KEYPOOL_STATUS_URL:-http://127.0.0.1:18889/__keypool/status}"
GOOGLE_KEYPOOL_CHECK_INTERVAL_SECONDS="${GOOGLE_KEYPOOL_CHECK_INTERVAL_SECONDS:-86400}"
NANOBOT_GOOGLE_KEYPOOL_ALERT_ENABLED="${NANOBOT_GOOGLE_KEYPOOL_ALERT_ENABLED:-0}"
OPENCLAW_STALE_LOCK_SECONDS="${OPENCLAW_STALE_LOCK_SECONDS:-1800}"
NANOBOT_STARTUP_GRACE_SECONDS="${NANOBOT_STARTUP_GRACE_SECONDS:-900}"
NANOBOT_FAIL_THRESHOLD="${NANOBOT_FAIL_THRESHOLD:-2}"
NANOBOT_RESCUE_COOLDOWN_SECONDS="${NANOBOT_RESCUE_COOLDOWN_SECONDS:-1800}"
NANOBOT_STARTUP_NOTIFY="${NANOBOT_STARTUP_NOTIFY:-0}"
MAX_TELEGRAM_TEXT_BYTES="${MAX_TELEGRAM_TEXT_BYTES:-3500}"
NANOBOT_INCLUDE_UPSTREAM_CHECK="${NANOBOT_INCLUDE_UPSTREAM_CHECK:-0}"
INTENT_CLASS="chat"
INTENT_REASON="default"
OPENCLAW_LAST_HEALTH_REASON=""

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

if [ -f "$SHARED_ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$SHARED_ENV_FILE"
fi
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi
if [ "${NANOBOT_RUNTIME_ENV:-auto}" = "auto" ]; then
  case "$HOME_DIR" in
    /data/data/com.termux/files/home*) NANOBOT_RUNTIME_ENV="termux" ;;
    *) NANOBOT_RUNTIME_ENV="cloud" ;;
  esac
fi
if [ -z "${CORE_GUARD_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-coreguard.sh" ]; then
    CORE_GUARD_SCRIPT="$HOME_DIR/cloud/openclaw-coreguard.sh"
  else
    CORE_GUARD_SCRIPT="$REPO_DIR/scripts/termux-openclaw-core-guard.sh"
  fi
fi
if [ -z "${OPENCLAW_BOOT_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-launch.sh" ]; then
    OPENCLAW_BOOT_SCRIPT="$HOME_DIR/cloud/openclaw-launch.sh"
  else
    OPENCLAW_BOOT_SCRIPT="$HOME_DIR/.termux/boot/openclaw-launch.sh"
  fi
fi
if [ -z "${OPENCLAW_REBUILD_SCRIPT:-}" ]; then
  if [ "$NANOBOT_RUNTIME_ENV" = "cloud" ] && [ -f "$HOME_DIR/cloud/openclaw-rebuild.sh" ]; then
    OPENCLAW_REBUILD_SCRIPT="$HOME_DIR/cloud/openclaw-rebuild.sh"
  else
    OPENCLAW_REBUILD_SCRIPT="$REPO_DIR/scripts/termux-rebuild-openclaw.sh"
  fi
fi
if [ -z "${OPENCLAW_PORT:-}" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  OPENCLAW_PORT="$(jq -r '.gateway.port // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
OPENCLAW_BIN="${OPENCLAW_BIN:-$(command -v openclaw || true)}"
if [ -z "$OPENCLAW_BIN" ] && [ -x "$HOME_DIR/.npm-global/bin/openclaw" ]; then
  OPENCLAW_BIN="$HOME_DIR/.npm-global/bin/openclaw"
fi
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"

run_with_timeout() {
  local sec="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "${sec}s" "$@"
  else
    "$@"
  fi
}

env_upsert_var() {
  local file="$1" key="$2" value="$3" tmp
  [ -n "$file" ] || return 1
  [ -f "$file" ] || touch "$file"
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" '
    BEGIN { done=0 }
    {
      if ($0 ~ ("^" k "=")) {
        print k "=\"" v "\""
        done=1
      } else {
        print $0
      }
    }
    END {
      if (!done) print k "=\"" v "\""
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
}

nanobot_available_models() {
  local cfg="$HOME_DIR/.openclaw/openclaw.json"
  [ -f "$cfg" ] || return 1
  jq -r '
    .models.providers
    | to_entries[]
    | .key as $p
    | (.value.models // [])[]
    | select(.id != null and (.id|length)>0)
    | "\($p)/\(.id)"
  ' "$cfg" 2>/dev/null | sort -u
}

nanobot_model_exists() {
  local model="$1"
  nanobot_available_models | grep -Fxq "$model"
}

resolve_model_runtime_json() {
  local selected="$1" cfg="$HOME_DIR/.openclaw/openclaw.json"
  python3 - "$cfg" "$selected" <<'PY' 2>/dev/null || true
import json
import os
import sys

cfg_path = sys.argv[1]
selected = (sys.argv[2] or "").strip()
if not selected or not os.path.isfile(cfg_path):
    print("{}")
    raise SystemExit

cfg = json.load(open(cfg_path, "r", encoding="utf-8"))
providers = ((cfg.get("models") or {}).get("providers") or {})

provider = ""
model_id = selected
if "/" in selected:
    maybe_provider, rest = selected.split("/", 1)
    if maybe_provider in providers:
        provider = maybe_provider
        model_id = rest

if not provider:
    for p, pobj in providers.items():
        for m in (pobj.get("models") or []):
            if isinstance(m, dict) and str(m.get("id") or "") == selected:
                provider = p
                model_id = selected
                break
        if provider:
            break

if not provider or provider not in providers:
    print("{}")
    raise SystemExit

pobj = providers.get(provider) or {}
api_kind = str(pobj.get("api") or "openai-completions")
if api_kind != "openai-completions":
    print(json.dumps({"supported": False, "reason": f"provider-api-not-supported:{api_kind}"}, ensure_ascii=False))
    raise SystemExit

api_key = pobj.get("apiKey") or {}
key_id = str(api_key.get("id") or "").strip()
if not key_id:
    print(json.dumps({"supported": False, "reason": "provider-missing-apikey-id"}, ensure_ascii=False))
    raise SystemExit

base_url = str(pobj.get("baseUrl") or "").strip()
if not base_url:
    print(json.dumps({"supported": False, "reason": "provider-missing-baseurl"}, ensure_ascii=False))
    raise SystemExit

print(json.dumps({
    "supported": True,
    "provider": provider,
    "modelId": model_id,
    "selected": f"{provider}/{model_id}",
    "baseUrl": base_url.rstrip("/"),
    "apiKeyEnvId": key_id
}, ensure_ascii=False))
PY
}

nanobot_model_list_message() {
  local provider_filter="${1:-}" cfg="$HOME_DIR/.openclaw/openclaw.json"
  [ -f "$cfg" ] || { echo "目前沒有可讀取的模型清單。"; return 0; }
  jq -r --arg pf "$provider_filter" '
    .models.providers
    | to_entries
    | map(select($pf=="" or .key==$pf))
    | if length==0 then "找不到指定平台模型。"
      else
        "可選平台：" + (map(.key) | join(", ")) + "\n" +
        (map(
          "【" + .key + "】\n" +
          ((.value.models // [])
            | .[0:20]
            | map("- " + .id)
            | join("\n")
          )
        ) | join("\n"))
      end
  ' "$cfg" 2>/dev/null
}

set_nanobot_model() {
  local model="$1" runtime_json supported reason selected
  [ -n "$model" ] || return 1
  if ! nanobot_model_exists "$model"; then
    return 2
  fi
  runtime_json="$(resolve_model_runtime_json "$model")"
  supported="$(printf '%s' "$runtime_json" | jq -r '.supported // false' 2>/dev/null || echo false)"
  if [ "$supported" != "true" ]; then
    reason="$(printf '%s' "$runtime_json" | jq -r '.reason // "unknown"' 2>/dev/null || echo unknown)"
    echo "unsupported:${reason}"
    return 3
  fi
  selected="$(printf '%s' "$runtime_json" | jq -r '.selected // empty' 2>/dev/null || true)"
  [ -n "$selected" ] || return 4
  NANOBOT_MODEL="$selected"
  env_upsert_var "$ENV_FILE" "NANOBOT_MODEL" "$selected"
  return 0
}

latest_openclaw_runtime_log() {
  {
    find /tmp/openclaw -maxdepth 1 -type f -name 'openclaw-*.log' 2>/dev/null
    find "$HOME_DIR/tmp" -maxdepth 2 -type f -name 'openclaw-*.log' 2>/dev/null
  } | sort | tail -n1
}

recent_error_excerpt() {
  local src="$1"
  [ -f "$src" ] || return 0
  tail -n "$NANOBOT_DIAG_LOG_LINES" "$src" 2>/dev/null \
    | sanitize_issue_lines \
    | tail -n 6 || true
}

sanitize_issue_lines() {
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' \
    | sed -E 's/[[:space:]]+/ /g; s/^ +//; s/ +$//' \
    | grep -Eiv '(^\{)|(^\[)|("_meta")|(subsystem\\":)|(isError=false)|(memory embeddings: batch start)|(memory embeddings: query start)|(embedded run agent end)|(timeoutMs)|(noOutputTimeoutMs)|(maxOutputBytes)' \
    | grep -Ei 'error|failed|timeout|exception|panic|denied|forbidden|unhealthy|crash|invalid|refused|conflict|429|500|503' \
    | awk 'length($0)>0 { print substr($0,1,220) }' || true
}

truncate_telegram_text() {
  local msg="$1" bytes
  bytes="$(printf '%s' "$msg" | wc -c | tr -d ' ')"
  if [ "${bytes:-0}" -gt "$MAX_TELEGRAM_TEXT_BYTES" ]; then
    printf '%s\n%s' "$(printf '%s' "$msg" | head -c "$MAX_TELEGRAM_TEXT_BYTES")" "...(訊息過長，已截斷)"
  else
    printf '%s' "$msg"
  fi
}

detect_blocking_tasks() {
  local openclaw_roots
  openclaw_roots="$(pgrep -f 'openclaw-gateway|openclaw gateway|(^|[[:space:]])openclaw([[:space:]]|$)' 2>/dev/null | tr '\n' ' ' || true)"
  ps -eo pid,ppid,etimes,pcpu,cmd 2>/dev/null \
    | awk -v minKnown="$OPENCLAW_STUCK_TASK_SECONDS" -v minHung="$OPENCLAW_HUNG_TASK_SECONDS" -v cpuMax="$OPENCLAW_HUNG_TASK_CPU_MAX" -v roots="$openclaw_roots" '
      BEGIN {
        n=split(roots, arr, /[[:space:]]+/);
        for (i=1; i<=n; i++) if (arr[i] != "") root[arr[i]] = 1;
      }
      {
        pid=$1; ppid=$2; et=$3+0; cpu=$4+0;
        cmd="";
        for (i=5; i<=NF; i++) cmd = cmd (i==5 ? "" : " ") $i;

        known_stuck=(cmd ~ /^(@tobilu\/qmd\/dist\/qmd\.js embed|node-llama-cpp|cmake-js-llama|playwright|puppeteer|chromium[^\n]*--headless|npm (install|update|ci)|pnpm (install|update)|git (clone|fetch|pull)|sqlite3 [^\n]*VACUUM|embedding|indexer|reindex)/);
        openclaw_child=(root[ppid] == 1);
        generic_hung=(openclaw_child && et >= minHung && cpu <= cpuMax && cmd !~ /openclaw-gateway|openclaw gateway|termux-rescue-nanobot|webhook_skeleton/);

        if ((known_stuck && et >= minKnown) || generic_hung) print $0;
      }' || true
}

count_timeout_events() {
  local runtime_log="$1" gateway_log="$2"
  python - "$runtime_log" "$gateway_log" "$OPENCLAW_TIMEOUT_STORM_LINES" "$OPENCLAW_TIMEOUT_STORM_WINDOW_SECONDS" <<'PY' 2>/dev/null || echo 0
import collections
import datetime as dt
import re
import sys

runtime_log, gateway_log, max_lines, window_sec = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
pattern = re.compile(r'embedded run timeout|FailoverError: LLM request timed out|lane task error: .*timed out|tool.*timeout|timed out|timeout', re.I)
json_ts = re.compile(r'"time":"([^"]+)"')
iso_ts = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)')
now = dt.datetime.now(dt.timezone.utc)

def tail_lines(path, n):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return list(collections.deque(f, maxlen=n))
    except Exception:
        return []

def parse_ts(line):
    m = json_ts.search(line)
    if not m:
        m = iso_ts.search(line)
    if not m:
        return None
    raw = m.group(1).replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(raw)
    except Exception:
        return None

strict_timeout = re.compile(r'embedded run timeout|FailoverError: LLM request timed out|lane task error: .*timed out|ETIMEDOUT|ECONNRESET', re.I)
benign_timeout = re.compile(r'waiting for run end: .*timeoutMs=|getUpdates.*timed out|timeoutMs=', re.I)
count = 0
for path in (runtime_log, gateway_log):
    for line in tail_lines(path, max_lines):
        if benign_timeout.search(line):
            continue
        if not strict_timeout.search(line):
            continue
        ts = parse_ts(line)
        if ts is None:
            count += 1
            continue
        if (now - ts).total_seconds() <= window_sec:
            count += 1

print(count)
PY
}

get_primary_model_from_config() {
  if [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
    jq -r '.agents.defaults.model.primary // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null | head -n1
  fi
}

detect_stale_artifacts() {
  local stale_min stale_pid stale_locks
  stale_min=$(( OPENCLAW_STALE_LOCK_SECONDS / 60 ))
  [ "$stale_min" -lt 1 ] && stale_min=1

  stale_pid=""
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
      stale_pid="stale nanobot pid file: $PID_FILE=>$pid"
    fi
  fi

  stale_locks="$(find "$HOME_DIR/.openclaw" "$STATE_DIR" -maxdepth 4 -type f \
    \( -name '*gateway*.lock' -o -name '*update*.lock' -o -name '*maintenance*.lock' \) \
    -mmin +"$stale_min" 2>/dev/null | head -n 8 || true)"

  if [ -n "$stale_pid" ]; then
    printf '%s\n' "$stale_pid"
  fi
  if [ -n "$stale_locks" ]; then
    printf '%s\n' "$stale_locks"
  fi
}

humanize_reason() {
  local reason="${1:-}"
  case "$reason" in
    "") echo "" ;;
    process-not-running) echo "主服務程序未運行。" ;;
    gateway-port-unreachable:*) echo "主服務連接埠無法連線。" ;;
    channels-status-empty) echo "無法讀取通道狀態（回傳為空）。" ;;
    telegram-channel-not-running) echo "Telegram 通道目前未連線。" ;;
    reply-lag-exceeded:*) echo "收到訊息後超過預期時間仍未回覆。" ;;
    gateway-health-rpc-failed) echo "Gateway 健康檢查失敗。" ;;
    timeout-storm-warning:*) echo "近期逾時訊息偏多（警示，不一定代表當機）。" ;;
    blocking-task-detected) echo "偵測到阻塞任務（長任務卡住）。" ;;
    stale-artifacts-detected) echo "偵測到舊鎖檔或殘留檔案（可能是先前重啟遺留）。" ;;
    *) echo "系統回報異常：${reason}" ;;
  esac
}

humanize_issue_lines() {
  while IFS= read -r line; do
    case "$line" in
      *"edit failed: Could not find the exact text"*)
        echo "嘗試修改記憶檔時，找不到完全匹配的原文片段（屬於編輯失敗，非服務當機）。"
        ;;
      *"No API key found for provider"*)
        echo "模型金鑰未載入，暫時無法呼叫模型。"
        ;;
      *"gateway closed"*)
        echo "Gateway 連線中斷（通常是重啟瞬間或短暫斷線）。"
        ;;
      *)
        echo "$line"
        ;;
    esac
  done
}

remediate_stale_artifacts() {
  local artifacts removed pid
  artifacts="$(detect_stale_artifacts)"
  [ -n "$artifacts" ] || return 1
  removed=0

  if [ -f "$PID_FILE" ]; then
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$PID_FILE" >/dev/null 2>&1 || true
      removed=1
    fi
  fi

  while IFS= read -r file; do
    [ -n "$file" ] || continue
    [ -f "$file" ] || continue
    case "$file" in
      *".lock"|*".pid")
        rm -f "$file" >/dev/null 2>&1 || true
        removed=1
        ;;
    esac
  done <<EOF
$artifacts
EOF

  [ "$removed" -eq 1 ]
}

gateway_health_ok() {
  local health_json
  health_json="$(run_with_timeout "$HEALTH_TIMEOUT_SECONDS" "$OPENCLAW_BIN" health --json 2>/dev/null || true)"
  [ -n "$health_json" ] || return 1
  printf '%s' "$health_json" | jq -e '.ok == true or .healthy == true or .status == "ok"' >/dev/null 2>&1
}

enforce_stable_model_defaults() {
  local primary
  primary="$(get_primary_model_from_config)"
  primary="${primary:-nvidia/z-ai/glm5}"
  run_with_timeout 25 "$OPENCLAW_BIN" models set "$primary" --agent main >/dev/null 2>&1 || true
}

remediate_blocking_tasks() {
  local blockers
  blockers="$(detect_blocking_tasks)"
  [ -n "$blockers" ] || return 1
  log "blocking tasks detected: $(printf '%s' "$blockers" | tr '\n' '; ')"
  pkill -f "@tobilu/qmd/dist/qmd.js embed" >/dev/null 2>&1 || true
  pkill -f "node-llama-cpp" >/dev/null 2>&1 || true
  pkill -f "cmake-js-llama" >/dev/null 2>&1 || true
  pkill -f "playwright" >/dev/null 2>&1 || true
  pkill -f "puppeteer" >/dev/null 2>&1 || true
  pkill -f "chromium.*--headless" >/dev/null 2>&1 || true
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local pid
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    [ -n "$pid" ] || continue
    kill -TERM "$pid" >/dev/null 2>&1 || true
  done <<EOF
$blockers
EOF
  sleep 2
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local pid
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    [ -n "$pid" ] || continue
    kill -KILL "$pid" >/dev/null 2>&1 || true
  done <<EOF
$blockers
EOF
  sleep 2
  return 0
}

resolve_openclaw_repo_slug() {
  local slug url
  slug="${NANOBOT_GITHUB_REPO:-}"
  url="${OPENCLAW_OFFICIAL_GITHUB_URL:-}"
  if [ -z "$slug" ] && [ -n "$url" ]; then
    slug="$(printf '%s' "$url" | sed -E 's#^https?://github.com/##; s#\.git$##; s#/*$##')"
  fi
  [ -n "$slug" ] || slug="openclaw/openclaw"
  printf '%s' "$slug"
}

fetch_upstream_versions() {
  local npm_latest gh_tag gh_updated repo_slug
  repo_slug="$(resolve_openclaw_repo_slug)"
  npm_latest="$(run_with_timeout 10 npm view openclaw version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  gh_tag="$(curl -fsS --max-time 10 "https://api.github.com/repos/${repo_slug}/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' || true)"
  gh_updated="$(curl -fsS --max-time 10 "https://api.github.com/repos/${repo_slug}/releases/latest" 2>/dev/null | jq -r '.published_at // empty' || true)"
  jq -n --arg npm "$npm_latest" --arg gh "$gh_tag" --arg gh_updated "$gh_updated" --arg repo "$repo_slug" --arg official "$OPENCLAW_OFFICIAL_GITHUB_URL" \
    '{npm_latest:$npm, github_latest_tag:$gh, github_published_at:$gh_updated, github_repo:$repo, official_github_url:$official}'
}

collect_openclaw_snapshot_json() {
  local cfg gateway_port tmux_sessions openclaw_pid nanobot_pid healthy openclaw_ver git_head stable_tag runtime_log
  local gateway_err runtime_err upstream_json timeout_events stale_artifacts
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  gateway_port="$OPENCLAW_PORT"
  if [ -f "$cfg" ]; then
    gateway_port="$(jq -r '.gateway.port // empty' "$cfg" 2>/dev/null || true)"
    [ -n "$gateway_port" ] || gateway_port="$OPENCLAW_PORT"
  fi
  gateway_port="${gateway_port:-18789}"
  tmux_sessions="$({ tmux ls 2>/dev/null || true; } | awk -F: '{print $1}' | jq -Rsc 'split("\n") | map(select(length>0))' 2>/dev/null || true)"
  [ -n "$tmux_sessions" ] || tmux_sessions='[]'
  openclaw_pid="$(pgrep -f 'openclaw-gateway|openclaw gateway' | head -n1 || true)"
  nanobot_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  openclaw_ver="$("$OPENCLAW_BIN" --version 2>/dev/null | tr -d '\r' | tail -n1 || true)"
  git_head="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || true)"
  stable_tag="$(resolve_stable_tag)"
  runtime_log="$(latest_openclaw_runtime_log)"
  if openclaw_healthy; then
    healthy=true
  else
    healthy=false
  fi

  gateway_err="$(recent_error_excerpt "$HOME_DIR/openclaw-logs/gateway.log" | tail -n 6)"
  runtime_err="$(recent_error_excerpt "$runtime_log" | tail -n 6)"
  timeout_events="$(count_timeout_events "$runtime_log" "$HOME_DIR/openclaw-logs/gateway.log")"
  stale_artifacts="$(detect_stale_artifacts | tail -n 6 || true)"
  if [ "$NANOBOT_INCLUDE_UPSTREAM_CHECK" = "1" ]; then
    upstream_json="$(fetch_upstream_versions)"
  else
    upstream_json="$(jq -n --arg repo "$(resolve_openclaw_repo_slug)" --arg official "$OPENCLAW_OFFICIAL_GITHUB_URL" '{npm_latest:"", github_latest_tag:"", github_published_at:"", github_repo:$repo, official_github_url:$official}' )"
  fi

  jq -n \
    --argjson healthy "$healthy" \
    --arg openclaw_pid "$openclaw_pid" \
    --arg nanobot_pid "$nanobot_pid" \
    --arg gateway_port "$gateway_port" \
    --arg openclaw_ver "$openclaw_ver" \
    --arg git_head "$git_head" \
    --arg stable_tag "$stable_tag" \
    --arg runtime_log "${runtime_log:-}" \
    --arg gateway_err "$gateway_err" \
    --arg runtime_err "$runtime_err" \
    --arg unhealthy_reason "${OPENCLAW_LAST_HEALTH_REASON:-}" \
    --arg timeout_events "${timeout_events:-0}" \
    --arg stale_artifacts "$stale_artifacts" \
    --argjson tmux "$tmux_sessions" \
    --argjson upstream "$upstream_json" \
    '{
      healthy: $healthy,
      gateway_port: $gateway_port,
      openclaw_pid: $openclaw_pid,
      nanobot_pid: $nanobot_pid,
      openclaw_version: $openclaw_ver,
      git_head: $git_head,
      stable_tag: $stable_tag,
      runtime_log: $runtime_log,
      tmux_sessions: $tmux,
      recent_gateway_errors: $gateway_err,
      recent_runtime_errors: $runtime_err,
      unhealthy_reason: $unhealthy_reason,
      timeout_events: ($timeout_events | tonumber? // 0),
      stale_artifacts: $stale_artifacts,
      upstream: $upstream
    }'
}

build_status_report() {
  local snapshot healthy port opid npid ver head stable npm_latest gh_tag official_url repo_slug issues blockers reason reason_text timeout_events stale
  snapshot="$(collect_openclaw_snapshot_json)"
  healthy="$(printf '%s' "$snapshot" | jq -r '.healthy')"
  port="$(printf '%s' "$snapshot" | jq -r '.gateway_port')"
  opid="$(printf '%s' "$snapshot" | jq -r '.openclaw_pid // ""')"
  npid="$(printf '%s' "$snapshot" | jq -r '.nanobot_pid // ""')"
  ver="$(printf '%s' "$snapshot" | jq -r '.openclaw_version // ""')"
  head="$(printf '%s' "$snapshot" | jq -r '.git_head // ""')"
  stable="$(printf '%s' "$snapshot" | jq -r '.stable_tag // ""')"
  npm_latest="$(printf '%s' "$snapshot" | jq -r '.upstream.npm_latest // ""')"
  gh_tag="$(printf '%s' "$snapshot" | jq -r '.upstream.github_latest_tag // ""')"
  official_url="$(printf '%s' "$snapshot" | jq -r '.upstream.official_github_url // ""')"
  repo_slug="$(printf '%s' "$snapshot" | jq -r '.upstream.github_repo // ""')"
  reason="$(printf '%s' "$snapshot" | jq -r '.unhealthy_reason // ""')"
  reason_text="$(humanize_reason "$reason")"
  timeout_events="$(printf '%s' "$snapshot" | jq -r '.timeout_events // 0')"
  stale="$(printf '%s' "$snapshot" | jq -r '.stale_artifacts // ""')"
  issues="$(printf '%s' "$snapshot" \
    | jq -r '.recent_gateway_errors, .recent_runtime_errors' 2>/dev/null \
    | sed '/^null$/d;/^$/d' \
    | sanitize_issue_lines \
    | humanize_issue_lines \
    | tail -n 6 || true)"
  blockers="$(detect_blocking_tasks | head -n 3 || true)"

  printf '🦀 潤天蟹自動診斷報告\n'
  if [ "$healthy" = "true" ]; then
    printf -- '- OpenClaw: 正常（連接埠=%s, 程序=%s）\n' "$port" "${opid:-n/a}"
  else
    printf -- '- OpenClaw: 異常（連接埠=%s, 程序=%s）\n' "$port" "${opid:-n/a}"
  fi
  printf -- '- Nanobot: 在線（pid=%s）\n' "${npid:-n/a}"
  printf -- '- 環境: %s\n' "${NANOBOT_RUNTIME_ENV}"
  printf -- '- 版本: local=%s, git=%s, 穩定標籤=%s\n' "${ver:-unknown}" "${head:-unknown}" "${stable:-none}"
  printf -- '- 上游: npm=%s, github=%s\n' "${npm_latest:-unknown}" "${gh_tag:-unknown}"
  if [ -n "$official_url" ]; then
    printf -- '- 官方來源: %s (%s)\n' "$official_url" "${repo_slug:-openclaw/openclaw}"
  fi
  if [ -n "$issues" ]; then
    printf -- '- 最近異常摘要:\n%s\n' "$(printf '%s' "$issues" | tail -n 6)"
  fi
  if [ "$timeout_events" -ge "$OPENCLAW_TIMEOUT_STORM_THRESHOLD" ]; then
    printf -- '- 逾時風暴: %s（門檻=%s）\n' "$timeout_events" "$OPENCLAW_TIMEOUT_STORM_THRESHOLD"
  fi
  if [ -n "$blockers" ]; then
    printf -- '- 阻塞任務（known>%ss / generic>%ss）:\n%s\n' "$OPENCLAW_STUCK_TASK_SECONDS" "$OPENCLAW_HUNG_TASK_SECONDS" "$blockers"
  fi
  if [ -n "$stale" ]; then
    printf -- '- 陳舊鎖/殘留檔:\n%s\n' "$(printf '%s' "$stale" | tail -n 6)"
  fi
  if [ "$healthy" != "true" ] && [ -n "$reason" ]; then
    printf -- '- 判定原因: %s\n' "${reason_text:-$reason}"
  elif [ "$healthy" = "true" ] && [ -n "$reason" ]; then
    printf -- '- 風險提示: %s\n' "${reason_text:-$reason}"
  fi
}

build_brief_status_line() {
  local snapshot healthy port reason reason_text
  snapshot="$(collect_openclaw_snapshot_json)"
  healthy="$(printf '%s' "$snapshot" | jq -r '.healthy')"
  port="$(printf '%s' "$snapshot" | jq -r '.gateway_port // ""')"
  reason="$(printf '%s' "$snapshot" | jq -r '.unhealthy_reason // ""')"
  reason_text="$(humanize_reason "$reason")"
  if [ "$healthy" = "true" ]; then
    printf '目前 OpenClaw 正常運作（連接埠=%s）。' "${port:-unknown}"
  else
    printf '目前 OpenClaw 有異常（連接埠=%s）。原因：%s' "${port:-unknown}" "${reason_text:-系統暫時無法判定。}"
  fi
}

rescue_manual_brief() {
  cat <<'EOF'
🦀 潤天蟹救援手冊（摘要）
1) 先判斷是否「假健康」：
- openclaw channels status --json
- 檢查 telegram.running 必須為 true
- 檢查 lastInboundAt 與 lastOutboundAt 是否長時間失衡
2) 查阻塞任務（常見靜默根因）：
- 先查 known blockers：qmd embed / llama build / playwright / puppeteer / headless chromium
- 再查 generic blockers：OpenClaw 子進程低 CPU 長時間占用（hung）
3) 查逾時風暴與殘留鎖：
- runtime/gateway log 連續 timeout/FailoverError
- stale lock/pid/maintenance artifacts
4) 修復順序：
- terminate blockers + clear stale artifacts
- enforce stable model defaults
- coreguard --fix
- restart openclaw
- 還不行才 rebuild rescue
5) 回報要求：
- 修復前回報「原因+將執行步驟」
- 修復後回報「結果+是否恢復+下一步」
EOF
}

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [nanobot] %s\n' "$ts" "$*" >>"$LOG_FILE"
}

is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_update_id": 0,
  "last_healthcheck_ts": 0,
  "started_at": 0,
  "consecutive_health_failures": 0,
  "last_action_ts": 0,
  "last_action": "",
  "last_reason": "",
  "last_report": "",
  "repair_in_progress": false,
  "repair_started_at": 0,
  "repair_reason": "",
  "repair_step": "",
  "repair_updated_at": 0,
  "last_subagent_alert_key": "",
  "last_subagent_alert_ts": 0,
  "last_subagent_check_ts": 0,
  "last_google_keypool_check_ts": 0,
  "last_google_keypool_signature": "",
  "last_google_keypool_alert_ts": 0
}
EOF
  fi
  state_set '.last_subagent_alert_key = (.last_subagent_alert_key // "") | .last_subagent_alert_ts = (.last_subagent_alert_ts // 0) | .last_subagent_check_ts = (.last_subagent_check_ts // 0) | .last_google_keypool_check_ts = (.last_google_keypool_check_ts // 0) | .last_google_keypool_signature = (.last_google_keypool_signature // "") | .last_google_keypool_alert_ts = (.last_google_keypool_alert_ts // 0)'
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE"
}

state_set() {
  local expr="$1"
  local tmp
  tmp="$(mktemp)"
  jq "$expr" "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

repair_is_running() {
  [ -d "$REPAIR_LOCK_DIR" ]
}

repair_status_summary() {
  local in_progress started updated reason step now elapsed
  in_progress="$(state_get '.repair_in_progress // false')"
  started="$(state_get '.repair_started_at // 0')"
  updated="$(state_get '.repair_updated_at // 0')"
  reason="$(state_get '.repair_reason // ""')"
  step="$(state_get '.repair_step // ""')"
  now="$(date +%s)"
  if [ "$in_progress" = "true" ] || repair_is_running; then
    elapsed=$(( now - started ))
    [ "$elapsed" -lt 0 ] && elapsed=0
    printf '🛠️ 修復進行中（%ss）\n- 原因: %s\n- 目前步驟: %s\n- 最近更新: %ss 前' \
      "$elapsed" "${reason:-unknown}" "${step:-working}" "$(( now - updated ))"
  else
    printf '✅ 目前沒有進行中的修復流程。'
  fi
}

send_telegram() {
  local msg="$1"
  local msg_to_send
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0
  msg_to_send="$(truncate_telegram_text "$msg")"
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg_to_send}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

send_telegram_to_chat() {
  local chat_id="$1"
  local msg="$2"
  local msg_to_send
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$chat_id" ] || chat_id="$TELEGRAM_OWNER_ID"
  [ -n "$chat_id" ] || return 0
  msg_to_send="$(truncate_telegram_text "$msg")"
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${chat_id}" \
    --data-urlencode "text=${msg_to_send}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

start_typing_loop() {
  local chat_id="${1:-$TELEGRAM_OWNER_ID}"
  TYPING_PID=""
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$chat_id" ] || return 0
  (
    while true; do
      curl -fsS --max-time 10 \
        -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendChatAction" \
        -d "chat_id=${chat_id}" \
        -d "action=typing" >/dev/null 2>&1 || true
      sleep 3
    done
  ) &
  TYPING_PID="$!"
}

stop_typing_loop() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

openclaw_healthy() {
  OPENCLAW_LAST_HEALTH_REASON=""
  if ! pgrep -f "openclaw gateway" >/dev/null 2>&1 \
    && ! pgrep -f "openclaw-gateway" >/dev/null 2>&1 \
    && ! pgrep -x openclaw >/dev/null 2>&1; then
    OPENCLAW_LAST_HEALTH_REASON="process-not-running"
    return 1
  fi
  if ! python - "$OPENCLAW_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.5)
try:
    s.connect(("127.0.0.1", port))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
  then
    OPENCLAW_LAST_HEALTH_REASON="gateway-port-unreachable:$OPENCLAW_PORT"
    return 1
  fi
  local status_json running inbound outbound now lag tries
  status_json=""
  for tries in 1 2; do
    status_json="$($OPENCLAW_BIN channels status --json 2>/dev/null || true)"
    running="$(printf '%s' "$status_json" | jq -r '.channels.telegram.running // false' 2>/dev/null || echo false)"
    if [ "$running" = "true" ]; then
      break
    fi
    sleep 2
  done
  if [ -z "$status_json" ]; then
    OPENCLAW_LAST_HEALTH_REASON="channels-status-empty"
    return 1
  fi
  if [ "$running" != "true" ]; then
    OPENCLAW_LAST_HEALTH_REASON="telegram-channel-not-running"
    return 1
  fi

  inbound="$(printf '%s' "$status_json" | jq -r '.channelAccounts.telegram[]? | select(.accountId=="default") | (.lastInboundAt // 0)' 2>/dev/null | head -n1)"
  outbound="$(printf '%s' "$status_json" | jq -r '.channelAccounts.telegram[]? | select(.accountId=="default") | (.lastOutboundAt // 0)' 2>/dev/null | head -n1)"
  inbound="${inbound:-0}"
  outbound="${outbound:-0}"
  now="$(date +%s)"
  if [ "$inbound" -gt "$outbound" ] && [ "$inbound" -gt 0 ]; then
    lag=$(( now - (inbound / 1000) ))
    if [ "$lag" -gt "$OPENCLAW_REPLY_LAG_SECONDS" ]; then
      OPENCLAW_LAST_HEALTH_REASON="reply-lag-exceeded:${lag}s"
      return 1
    fi
  fi

  if ! gateway_health_ok; then
    OPENCLAW_LAST_HEALTH_REASON="gateway-health-rpc-failed"
    return 1
  fi

  local runtime_log timeout_events
  runtime_log="$(latest_openclaw_runtime_log)"
  timeout_events="$(count_timeout_events "$runtime_log" "$HOME_DIR/openclaw-logs/gateway.log")"
  if [ "${timeout_events:-0}" -ge "$OPENCLAW_TIMEOUT_STORM_THRESHOLD" ]; then
    # Timeout storm is treated as warning; not a hard-down signal by itself.
    OPENCLAW_LAST_HEALTH_REASON="timeout-storm-warning:${timeout_events}"
  fi

  if [ -n "$(detect_blocking_tasks)" ]; then
    OPENCLAW_LAST_HEALTH_REASON="blocking-task-detected"
    return 1
  fi
  if [ -n "$(detect_stale_artifacts)" ]; then
    OPENCLAW_LAST_HEALTH_REASON="stale-artifacts-detected"
    return 1
  fi
  OPENCLAW_LAST_HEALTH_REASON=""
}

restart_openclaw() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$OPENCLAW_SERVICE_NAME" >/dev/null 2>&1; then
    sudo systemctl restart "$OPENCLAW_SERVICE_NAME" >/dev/null 2>&1 || true
    sleep 10
    openclaw_healthy
    return $?
  fi

  if [ ! -f "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script missing: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    chmod +x "$OPENCLAW_BOOT_SCRIPT" >/dev/null 2>&1 || true
  fi
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script not executable: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t =openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$OPENCLAW_BOOT_SCRIPT"
  sleep 10
  openclaw_healthy
}

resolve_stable_tag() {
  [ -d "$REPO_DIR/.git" ] || return 0
  git -C "$REPO_DIR" tag -l '穩定版*' --sort=-creatordate | head -n1
}

rebuild_rescue() {
  local reason="$1" target ok i
  if [ ! -x "$OPENCLAW_REBUILD_SCRIPT" ]; then
    log "rebuild script missing: $OPENCLAW_REBUILD_SCRIPT"
    return 1
  fi
  target="$(resolve_stable_tag)"
  if [ -z "$target" ]; then
    target="origin/${OPENCLAW_REPO_BRANCH}"
  fi
  send_telegram "🦀 潤天蟹修復前回報：準備回滾重建 OpenClaw。原因：${reason}，目標：${target}"

  OPENCLAW_REBUILD_MODE="rescue" \
  OPENCLAW_REBUILD_PRESERVE_CONFIG=0 \
  OPENCLAW_REBUILD_PRESERVE_STATE=1 \
  OPENCLAW_REBUILD_SKIP_WATCHDOG=1 \
  OPENCLAW_REBUILD_SKIP_NANOBOT=1 \
  OPENCLAW_REBUILD_FORCE_STABLE_CONFIG=1 \
  OPENCLAW_ROLLBACK_TAG="$target" \
  OPENCLAW_BASELINE_PROFILE_PATH="$REPO_DIR/scripts/cloud/openclaw.stable.full.json" \
  OPENCLAW_DISALLOW_MINIMAL_TEMPLATE=1 \
  OPENCLAW_STACK_SERVICE="$OPENCLAW_REBUILD_SERVICE" \
  OPENCLAW_WATCHDOG_ENABLED=0 \
  NANOBOT_ENABLED=1 \
  NANOBOT_TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" \
  TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID" \
  NVIDIA_API_KEY="$NVIDIA_API_KEY" \
  OPENCLAW_PORT="$OPENCLAW_PORT" \
  bash "$OPENCLAW_REBUILD_SCRIPT" >>"$LOG_FILE" 2>&1 || return 1

  ok=0
  for i in 1 2 3; do
    sleep 8
    if openclaw_healthy; then
      ok=1
      break
    fi
  done

  if [ "$ok" = "1" ]; then
    send_telegram "✅ 潤天蟹修復後回報：回滾重建成功，OpenClaw 已恢復。原因：${reason}，目標：${target}"
    return 0
  fi

  send_telegram "❌ 潤天蟹修復後回報：回滾重建後仍不健康。原因：${reason}，目標：${target}"
  return 1
}

call_model_json() {
  local prompt="$1" schema_json="$2" out_var="$3"
  local payload resp response_content
  local runtime_json supported base_url model_id key_env_id key_value
  runtime_json="$(resolve_model_runtime_json "$NANOBOT_MODEL")"
  supported="$(printf '%s' "$runtime_json" | jq -r '.supported // false' 2>/dev/null || echo false)"
  if [ "$supported" != "true" ]; then
    printf -v "$out_var" '%s' ""
    return 1
  fi
  base_url="$(printf '%s' "$runtime_json" | jq -r '.baseUrl // empty' 2>/dev/null || true)"
  model_id="$(printf '%s' "$runtime_json" | jq -r '.modelId // empty' 2>/dev/null || true)"
  key_env_id="$(printf '%s' "$runtime_json" | jq -r '.apiKeyEnvId // empty' 2>/dev/null || true)"
  key_value="${!key_env_id:-}"
  if [ -z "$base_url" ] || [ -z "$model_id" ] || [ -z "$key_env_id" ] || [ -z "$key_value" ]; then
    printf -v "$out_var" '%s' ""
    return 1
  fi
  payload="$(jq -n \
    --arg model "$model_id" \
    --arg prompt "$prompt" \
    --argjson schema "$schema_json" '
    {
      model: $model,
      temperature: 0,
      messages: [
        { role: "system", content: "Output strict JSON only." },
        { role: "user", content: $prompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "nanobot_structured",
          strict: true,
          schema: $schema
        }
      }
    }')"
  resp="$(curl -fsS --max-time 30 \
    -X POST "${base_url}/chat/completions" \
    -H "Authorization: Bearer ${key_value}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"
  response_content="$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  printf -v "$out_var" '%s' "$response_content"
  [ -n "$response_content" ]
}

model_chat_reply() {
  local user_text="$1" payload resp content snapshot_json
  local runtime_json supported base_url model_id key_env_id key_value
  snapshot_json="$(collect_openclaw_snapshot_json)"
  runtime_json="$(resolve_model_runtime_json "$NANOBOT_MODEL")"
  supported="$(printf '%s' "$runtime_json" | jq -r '.supported // false' 2>/dev/null || echo false)"
  if [ "$supported" != "true" ]; then
    printf '%s\n%s\n%s\n' \
      "目前模型平台不支援潤天蟹直接對話，請先用 /model set nvidia/z-ai/glm5 或 /model set openrouter/<model>。" \
      "$(build_brief_status_line)" \
      "你也可以輸入 /model list 看可切換模型。"
    return 0
  fi
  base_url="$(printf '%s' "$runtime_json" | jq -r '.baseUrl // empty' 2>/dev/null || true)"
  model_id="$(printf '%s' "$runtime_json" | jq -r '.modelId // empty' 2>/dev/null || true)"
  key_env_id="$(printf '%s' "$runtime_json" | jq -r '.apiKeyEnvId // empty' 2>/dev/null || true)"
  key_value="${!key_env_id:-}"
  if [ -z "$key_value" ]; then
    printf '%s\n' "$(build_brief_status_line)"
    return 0
  fi
  payload="$(jq -n --arg model "$model_id" --arg text "$user_text" --arg snapshot "$snapshot_json" '
    {
      model: $model,
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content: "你是潤天蟹，OpenClaw 戰地醫護兵。部署環境是 Oracle Cloud Ubuntu（非手機 Termux）。請用繁體中文簡潔回覆。你必須根據系統診斷資訊回答，不要叫使用者輸入斜線指令。若可直接處理，直接處理；若需要修復，先做根因判斷，再清楚說明你將執行什麼。優先檢查：1) telegram channel 是否 running 2) inbound/outbound 是否失衡 3) 是否有 qmd embed / node-llama-cpp / cmake-js-llama 阻塞任務。"
        },
        {
          role: "system",
          content: ("系統診斷快照(JSON): " + $snapshot)
        },
        {
          role: "user",
          content: $text
        }
      ]
    }')"
  resp="$(curl -fsS --max-time 35 \
    -X POST "${base_url}/chat/completions" \
    -H "Authorization: Bearer ${key_value}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || true)"
  content="$(printf '%s' "$resp" | jq -r '.choices[0].message.content // empty' 2>/dev/null || true)"
  if [ -z "$content" ]; then
    printf '%s\n%s\n%s\n' \
      "我先直接回報現況：" \
      "$(build_brief_status_line)" \
      "你可直接說：要我做健康檢查、看最近錯誤，或執行修復。"
  else
    printf '%s\n' "$content"
  fi
}

classify_natural_intent() {
  local user_text="$1" text_norm schema content intent reason
  INTENT_CLASS="chat"
  INTENT_REASON="natural-chat"
  text_norm="$(printf '%s' "$user_text" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$text_norm" | grep -Eiq '修復完成|完成了嗎|進度|還在修|修好了嗎|修好了沒|done|progress'; then
    INTENT_CLASS="status"
    INTENT_REASON="keyword-repair-progress"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '狀態|健康|還在嗎|有沒有運作|運作嗎|在線|online|health|status'; then
    INTENT_CLASS="status"
    INTENT_REASON="keyword-status"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '日誌|log|後台|系統資訊|診斷|檢查|狀況|github|版本|更新|運行'; then
    INTENT_CLASS="diagnose"
    INTENT_REASON="keyword-diagnose"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '回滾|重建|rollback|rebuild'; then
    INTENT_CLASS="repair"
    INTENT_REASON="keyword-rollback"
    return 0
  fi
  if printf '%s' "$text_norm" | grep -Eiq '救援|修復|修好|修正|除錯|排錯|復原|掛了|當機|故障|失聯|沒反應|crash|broken|fix|repair|rescue'; then
    INTENT_CLASS="repair"
    INTENT_REASON="keyword-repair"
    return 0
  fi
  if [ -z "$NVIDIA_API_KEY" ]; then
    INTENT_CLASS="chat"
    INTENT_REASON="fallback-no-model"
    return 0
  fi

  schema='{
    "type":"object",
    "additionalProperties":false,
    "properties":{
      "intent":{"type":"string","enum":["repair","diagnose","status","chat"]},
      "reason":{"type":"string"}
    },
    "required":["intent","reason"]
  }'
  if call_model_json "Text: ${user_text}\nClassify intent into repair|diagnose|status|chat." "$schema" content; then
    intent="$(printf '%s' "$content" | jq -r 'try (fromjson.intent) catch .intent // "chat"' 2>/dev/null || echo chat)"
    reason="$(printf '%s' "$content" | jq -r 'try (fromjson.reason) catch .reason // "model-intent"' 2>/dev/null || echo model-intent)"
    case "$intent" in
      repair|diagnose|status|chat) ;;
      *) intent="chat"; reason="invalid-intent-fallback" ;;
    esac
    INTENT_CLASS="$intent"
    INTENT_REASON="$reason"
    return 0
  fi
  INTENT_CLASS="chat"
  INTENT_REASON="model-timeout"
}

is_nanobot_self_repair_request() {
  local text_norm
  text_norm="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$text_norm" | grep -Eiq '修復|修正|救援|回滾|rebuild|repair|fix'; then
    if printf '%s' "$text_norm" | grep -Eiq '潤天蟹|nanobot|你自己|自身|你的底層'; then
      return 0
    fi
  fi
  return 1
}

handoff_enqueue() {
  local from="$1" to="$2" type="$3" reason="$4" detail="${5:-}"
  [ -x "$HANDOFF_SCRIPT" ] || return 1
  "$HANDOFF_SCRIPT" enqueue \
    --from "$from" \
    --to "$to" \
    --type "$type" \
    --reason "$reason" \
    --detail "$detail"
}

delegate_nanobot_self_fix_to_openclaw() {
  local text="$1" task_json task_id task_file msg
  if ! is_true_flag "$HANDOFF_ENABLED"; then
    send_telegram "⚠️ 潤天蟹：目前未啟用跨代理交辦機制，無法轉交引天渡。"
    return 1
  fi
  if ! task_json="$(handoff_enqueue "nanobot" "openclaw" "nanobot-core-fix" "nanobot-self-fix-request" "$text" 2>/dev/null)"; then
    send_telegram "⚠️ 潤天蟹：建立交辦任務失敗，無法轉交引天渡。"
    return 1
  fi
  task_id="$(printf '%s' "$task_json" | jq -r '.id // empty' 2>/dev/null || true)"
  task_file="$(printf '%s' "$task_json" | jq -r '.file // empty' 2>/dev/null || true)"
  msg="【跨代理委派任務】請協助修復潤天蟹底層（禁止潤天蟹自修）。
任務ID：${task_id}
任務檔：${task_file}
需求：${text}
請完成後把任務標記 done/failed。"
  "$OPENCLAW_BIN" agent --message "$msg" --timeout 240 >/dev/null 2>&1 || true
  send_telegram "🧭 潤天蟹：你要求的是潤天蟹自我底層修正，已轉交引天渡處理（任務ID：${task_id}）。"
  return 0
}

is_internal_test_handoff() {
  local type="${1:-}" reason="${2:-}" detail="${3:-}" all
  all="$(printf '%s %s %s' "$type" "$reason" "$detail" | tr '[:upper:]' '[:lower:]')"
  if printf '%s' "$all" | grep -Eq '(^|[^a-z])(noop|verify|smoke|smoke-test|test)([^a-z]|$)'; then
    return 0
  fi
  return 1
}

maybe_process_openclaw_handoff() {
  local task id type reason detail result note
  if ! is_true_flag "$HANDOFF_ENABLED"; then
    return 0
  fi
  [ -x "$HANDOFF_SCRIPT" ] || return 0
  task="$("$HANDOFF_SCRIPT" claim --to nanobot --actor nanobot 2>/dev/null || true)"
  [ -n "$task" ] || return 0
  id="$(printf '%s' "$task" | jq -r '.id // empty' 2>/dev/null || true)"
  type="$(printf '%s' "$task" | jq -r '.type // empty' 2>/dev/null || true)"
  reason="$(printf '%s' "$task" | jq -r '.reason // empty' 2>/dev/null || true)"
  detail="$(printf '%s' "$task" | jq -r '.detail // empty' 2>/dev/null || true)"
  [ -n "$id" ] || return 0

  # Ignore internal smoke/verify/noop tasks quietly to avoid spamming user Telegram.
  if is_internal_test_handoff "$type" "$reason" "$detail"; then
    note="internal-test-ignored:${type}:${reason}"
    "$HANDOFF_SCRIPT" complete --id "$id" --status skipped --note "$note" --actor nanobot >/dev/null 2>&1 || true
    log "ignored internal test handoff: id=${id} type=${type} reason=${reason}"
    return 0
  fi

  case "$type" in
    openclaw-core-fix|openclaw-core-repair|openclaw-rescue)
      send_telegram "🤝 潤天蟹收到引天渡交辦：修復 OpenClaw（任務ID：${id}）。"
      if run_repair_playbook "handoff:${reason:-openclaw-handoff}"; then
        note="handled-by-nanobot:openclaw-repaired"
        "$HANDOFF_SCRIPT" complete --id "$id" --status done --note "$note" --actor nanobot >/dev/null 2>&1 || true
      else
        note="handled-by-nanobot:repair-failed"
        "$HANDOFF_SCRIPT" complete --id "$id" --status failed --note "$note" --actor nanobot >/dev/null 2>&1 || true
      fi
      ;;
    *)
      note="unsupported-task-type:${type}"
      "$HANDOFF_SCRIPT" complete --id "$id" --status skipped --note "$note" --actor nanobot >/dev/null 2>&1 || true
      send_telegram "⚠️ 潤天蟹：收到不支援的交辦類型（${type}），已標記跳過。"
      ;;
  esac
}

run_repair_playbook() {
  local reason="$1" now blockers timeout_events stale steps_msg allow_rebuild
  if repair_is_running; then
    send_telegram "⏳ 潤天蟹：已有修復流程在進行中，避免重複啟動。\n$(repair_status_summary)"
    return 0
  fi
  mkdir "$REPAIR_LOCK_DIR" >/dev/null 2>&1 || true
  trap 'rm -rf "$REPAIR_LOCK_DIR" >/dev/null 2>&1 || true' RETURN

  now="$(date +%s)"
  state_set ".repair_in_progress=true | .repair_started_at=${now} | .repair_reason=\"${reason}\" | .repair_step=\"init\" | .repair_updated_at=${now}"
  blockers="$(detect_blocking_tasks | head -n 6 || true)"
  timeout_events="$(count_timeout_events "$(latest_openclaw_runtime_log)" "$HOME_DIR/openclaw-logs/gateway.log")"
  stale="$(detect_stale_artifacts | head -n 6 || true)"
  steps_msg="1) terminate blockers 2) clear stale artifacts 3) enforce stable model 4) coreguard+restart 5) rebuild fallback"
  send_telegram "🦀 潤天蟹修復前回報：開始修復流程。原因：${reason}
診斷摘要：
- blockers=$([ -n "$blockers" ] && echo yes || echo no)
- timeout_events=${timeout_events}
- stale_artifacts=$([ -n "$stale" ] && echo yes || echo no)
執行步驟：${steps_msg}"
  log "repair playbook start: reason=${reason}"
  allow_rebuild=0
  case "$reason" in
    telegram-command|*keyword-rollback*|*force-rebuild*) allow_rebuild=1 ;;
  esac

  state_set ".repair_step=\"terminate_blockers\" | .repair_updated_at=$(date +%s)"
  if remediate_blocking_tasks; then
    send_telegram "🛠️ 潤天蟹：偵測到阻塞任務，已先中止阻塞任務。"
    if openclaw_healthy; then
      send_telegram "✅ 潤天蟹修復後回報：已解除阻塞，OpenClaw 恢復回應。原因：${reason}"
      state_set ".last_action_ts=${now} | .last_action=\"unstick_tasks\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0"
      return 0
    fi
  fi
  state_set ".repair_step=\"clear_stale_artifacts\" | .repair_updated_at=$(date +%s)"
  if remediate_stale_artifacts; then
    send_telegram "🧹 潤天蟹：已清理陳舊鎖檔/殘留 pid，準備再次健康檢查。"
    if openclaw_healthy; then
      send_telegram "✅ 潤天蟹修復後回報：清理殘留狀態後恢復正常。原因：${reason}"
      state_set ".last_action_ts=${now} | .last_action=\"clear_stale_artifacts\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0"
      return 0
    fi
  fi

  if [ "${timeout_events:-0}" -ge "$OPENCLAW_TIMEOUT_STORM_THRESHOLD" ]; then
    state_set ".repair_step=\"enforce_model_defaults\" | .repair_updated_at=$(date +%s)"
    enforce_stable_model_defaults
  fi

  state_set ".repair_step=\"coreguard\" | .repair_updated_at=$(date +%s)"
  if [ -f "$CORE_GUARD_SCRIPT" ]; then
    bash "$CORE_GUARD_SCRIPT" --fix >>"$LOG_FILE" 2>&1 || true
  fi

  state_set ".repair_step=\"restart_openclaw\" | .repair_updated_at=$(date +%s)"
  if restart_openclaw; then
    send_telegram "✅ 潤天蟹修復後回報：core-guard + restart 成功。原因：${reason}"
    state_set ".last_action_ts=${now} | .last_action=\"coreguard_restart\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0 | .repair_in_progress=false | .repair_step=\"done\" | .repair_updated_at=$(date +%s)"
    trap - RETURN
    rm -rf "$REPAIR_LOCK_DIR" >/dev/null 2>&1 || true
    return 0
  fi

  if [ "$allow_rebuild" -eq 1 ]; then
    state_set ".repair_step=\"rebuild_rescue\" | .repair_updated_at=$(date +%s)"
    if rebuild_rescue "$reason"; then
      state_set ".last_action_ts=${now} | .last_action=\"rebuild_rescue\" | .last_reason=\"${reason}\" | .last_report=\"ok\" | .consecutive_health_failures=0 | .repair_in_progress=false | .repair_step=\"done\" | .repair_updated_at=$(date +%s)"
      trap - RETURN
      rm -rf "$REPAIR_LOCK_DIR" >/dev/null 2>&1 || true
      return 0
    fi
  else
    send_telegram "⚠️ 潤天蟹：已完成非破壞修復，但仍未恢復。為避免誤操作，未自動執行回滾重建。若要回滾，請明確下達「強制回滾」或 /repair。"
  fi

  send_telegram "❌ 潤天蟹修復後回報：修復失敗，需要人工介入。原因：${reason}"
  state_set ".last_action_ts=${now} | .last_action=\"repair_failed\" | .last_reason=\"${reason}\" | .last_report=\"failed\" | .repair_in_progress=false | .repair_step=\"failed\" | .repair_updated_at=$(date +%s)"
  trap - RETURN
  rm -rf "$REPAIR_LOCK_DIR" >/dev/null 2>&1 || true
  return 1
}

handle_command() {
  local text="$1" chat_id="${2:-$TELEGRAM_OWNER_ID}" intent reason reply typing_pid rc
  rc=0
  start_typing_loop "$chat_id"
  typing_pid="${TYPING_PID:-}"
  trap 'stop_typing_loop "$typing_pid"' RETURN
  {
    case "$text" in
      "/status"|"/status@"*)
        send_telegram_to_chat "$chat_id" "$(build_status_report)
$(repair_status_summary)"
        ;;
      "/repair"|"/rescue"|"/fix"|"/repair@"*|"/rescue@"*|"/fix@"*)
        run_repair_playbook "telegram-command"
        ;;
      "/model"*|"/model@"*)
        # /model
        # /model list [provider]
        # /model set <provider/model>
        # /model <provider/model>
        local cmd_arg
        cmd_arg="$(printf '%s' "$text" | sed -E 's#^/model(@[^ ]+)?[ ]*##')"
        if [ -z "$cmd_arg" ]; then
          send_telegram_to_chat "$chat_id" "🦀 潤天蟹目前模型：${NANOBOT_MODEL}
可用指令：
- /model list
- /model list nvidia
- /model set nvidia/z-ai/glm5
- /model openrouter/openai/gpt-oss-120b"
        elif printf '%s' "$cmd_arg" | grep -Eiq '^list( |$)'; then
          local provider
          provider="$(printf '%s' "$cmd_arg" | awk '{print $2}')"
          send_telegram_to_chat "$chat_id" "$(nanobot_model_list_message "$provider")"
        else
          local target_model set_ret set_msg
          target_model="$(printf '%s' "$cmd_arg" | sed -E 's#^set[ ]+##')"
          set_msg="$(set_nanobot_model "$target_model" 2>&1 || true)"
          set_ret=$?
          if [ "$set_ret" -eq 0 ]; then
            send_telegram_to_chat "$chat_id" "✅ 潤天蟹模型已切換：${NANOBOT_MODEL}"
          elif [ "$set_ret" -eq 2 ]; then
            send_telegram_to_chat "$chat_id" "❌ 找不到模型：${target_model}
請先用 /model list 查看可選清單。"
          elif [ "$set_ret" -eq 3 ]; then
            send_telegram_to_chat "$chat_id" "⚠️ 目前不支援該平台直連：${target_model}
原因：${set_msg}
請改用 openai-completions 平台模型（如 nvidia/openrouter/groq/opencode）。"
          else
            send_telegram_to_chat "$chat_id" "❌ 模型切換失敗：${target_model}"
          fi
        fi
        ;;
      "/help"|"/help@"*)
        send_telegram_to_chat "$chat_id" "🦀 我會先自動診斷，再直接處理。你用自然語言描述需求即可。"
        ;;
      "/manual"|"/manual@"*)
        send_telegram_to_chat "$chat_id" "$(rescue_manual_brief)"
        ;;
      *)
        if is_nanobot_self_repair_request "$text"; then
          delegate_nanobot_self_fix_to_openclaw "$text"
        else
          classify_natural_intent "$text"
          intent="$INTENT_CLASS"
          reason="$INTENT_REASON"
          case "$intent" in
            repair)
              run_repair_playbook "natural:${reason}"
              ;;
            diagnose)
              send_telegram_to_chat "$chat_id" "$(build_status_report)
$(repair_status_summary)"
              ;;
            status)
              send_telegram_to_chat "$chat_id" "$(build_status_report)
$(repair_status_summary)"
              ;;
            chat|*)
              reply="$(model_chat_reply "$text")"
              send_telegram_to_chat "$chat_id" "$reply"
              ;;
          esac
        fi
        ;;
    esac
  } || rc=$?
  trap - RETURN
  stop_typing_loop "$typing_pid"
  return "$rc"
}

poll_telegram_updates() {
  local last_id offset resp_file ids id max_id chat_id text
  [ -n "$TELEGRAM_BOT_TOKEN" ] || return 0
  [ -n "$TELEGRAM_OWNER_ID" ] || return 0

  last_id="$(state_get '.last_update_id // 0')"
  offset="$((last_id + 1))"
  resp_file="$(mktemp)"
  if ! curl -fsS --max-time $((TELEGRAM_LONGPOLL_TIMEOUT + 10)) \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates?timeout=${TELEGRAM_LONGPOLL_TIMEOUT}&offset=${offset}" \
    -o "$resp_file" 2>/dev/null; then
    rm -f "$resp_file"
    return 0
  fi
  if [ "$(jq -r '.ok // false' "$resp_file" 2>/dev/null || echo false)" != "true" ]; then
    local desc
    desc="$(jq -r '.description // empty' "$resp_file" 2>/dev/null || true)"
    [ -n "$desc" ] && log "getUpdates not-ok: ${desc}"
    rm -f "$resp_file"
    return 0
  fi

  max_id="$last_id"
  ids="$(jq -r '.result[].update_id // empty' "$resp_file" 2>/dev/null || true)"
  for id in $ids; do
    [ "$id" -gt "$max_id" ] && max_id="$id"
    chat_id="$(jq -r ".result[] | select(.update_id==${id}) | (.message.chat.id // .edited_message.chat.id // empty)" "$resp_file" 2>/dev/null || true)"
    text="$(jq -r ".result[] | select(.update_id==${id}) | (.message.text // .edited_message.text // empty)" "$resp_file" 2>/dev/null || true)"
    [ -n "$chat_id" ] || continue
    [ -n "$text" ] || continue
    [ "$chat_id" = "$TELEGRAM_OWNER_ID" ] || continue
    handle_command "$text" "$chat_id"
  done

  rm -f "$resp_file"
  state_set ".last_update_id=${max_id}"
}

check_health_cycle() {
  local now last_hc started_at fail_count last_action_ts
  if ! is_true_flag "$AUTO_HEALTHCHECK_ENABLED"; then
    return 0
  fi

  now="$(date +%s)"
  last_hc="$(state_get '.last_healthcheck_ts // 0')"
  if [ "$((now - last_hc))" -lt "$HEALTHCHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_healthcheck_ts=${now}"

  started_at="$(state_get '.started_at // 0')"
  if [ "$started_at" -gt 0 ] && [ "$((now - started_at))" -lt "$NANOBOT_STARTUP_GRACE_SECONDS" ]; then
    log "startup grace active; skip auto health rescue"
    return 0
  fi

  if openclaw_healthy; then
    state_set '.consecutive_health_failures=0'
    return 0
  fi

  fail_count="$(state_get '.consecutive_health_failures // 0')"
  fail_count="$((fail_count + 1))"
  state_set ".consecutive_health_failures=${fail_count}"

  if [ "$fail_count" -lt "$NANOBOT_FAIL_THRESHOLD" ]; then
    log "health failed (${fail_count}/${NANOBOT_FAIL_THRESHOLD}); wait next cycle"
    return 0
  fi

  last_action_ts="$(state_get '.last_action_ts // 0')"
  if [ "$last_action_ts" -gt 0 ] && [ "$((now - last_action_ts))" -lt "$NANOBOT_RESCUE_COOLDOWN_SECONDS" ]; then
    log "rescue cooldown active; skip auto rescue"
    return 0
  fi

  if is_true_flag "$AUTO_RESCUE_ON_UNHEALTHY"; then
    run_repair_playbook "auto-healthcheck-failed"
  else
    send_telegram "🦀 潤天蟹提醒：偵測到 OpenClaw 不健康，但自動救援已關閉。"
  fi
}

detect_recent_subagent_failure() {
  local runtime_log gateway_log
  runtime_log="$(latest_openclaw_runtime_log)"
  gateway_log="$HOME_DIR/openclaw-logs/gateway.log"
  python - "$runtime_log" "$gateway_log" "$SUBAGENT_ALERT_LINES" "$SUBAGENT_ALERT_WINDOW_SECONDS" <<'PY' 2>/dev/null || echo '{"found":false}'
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
    r'embedded run tool error: .*tool=sessions_spawn|'
    r'sessions_spawn.*(error|failed|fail)|'
    r'subagent.*(failed|timed out)|'
    r'iserror=true',
    re.I
)
ignore_pat = re.compile(r'sessions_spawn tool start|sessions_spawn tool end|waiting for run end: .*timeoutMs=', re.I)
now = dt.datetime.now(dt.timezone.utc)

def tail_lines(path, n):
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
        # Ignore successful embedded/subagent completion logs.
        if "iserror=false" in low:
            continue
        if not fail_pat.search(line):
            continue
        ts = parse_ts(line)
        if ts is not None and (now - ts).total_seconds() > window_sec:
            continue
        latest = (ts, line.strip())

if latest is None:
    print(json.dumps({"found": False}, ensure_ascii=False))
    raise SystemExit

ts, line = latest
reason = "subagent-failure"
low = line.lower()
if "sessions_spawn" in low and ("error" in low or "fail" in low):
    reason = "sessions-spawn-failed"
elif "timed out" in low:
    reason = "subagent-timeout"
elif "unauthorized" in low or "token_mismatch" in low:
    reason = "subagent-auth-failed"
key_src = f"{ts.isoformat() if ts else 'no-ts'}|{line}"
key = hashlib.sha1(key_src.encode("utf-8", "ignore")).hexdigest()[:16]
print(json.dumps({
    "found": True,
    "reason": reason,
    "key": key,
    "excerpt": line[:220],
    "timestamp": ts.isoformat() if ts else ""
}, ensure_ascii=False))
PY
}

maybe_notify_subagent_failure() {
  local now last_check diag found key reason excerpt ts primary submodel last_key reason_text
  now="$(date +%s)"
  last_check="$(state_get '.last_subagent_check_ts // 0')"
  if [ "$last_check" -gt 0 ] && [ "$((now - last_check))" -lt "$SUBAGENT_ALERT_CHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_subagent_check_ts=${now}"

  diag="$(detect_recent_subagent_failure)"
  found="$(printf '%s' "$diag" | jq -r '.found // false' 2>/dev/null || echo false)"
  [ "$found" = "true" ] || return 0

  key="$(printf '%s' "$diag" | jq -r '.key // ""' 2>/dev/null || true)"
  reason="$(printf '%s' "$diag" | jq -r '.reason // "subagent-failure"' 2>/dev/null || echo subagent-failure)"
  excerpt="$(printf '%s' "$diag" | jq -r '.excerpt // ""' 2>/dev/null || true)"
  ts="$(printf '%s' "$diag" | jq -r '.timestamp // ""' 2>/dev/null || true)"
  last_key="$(state_get '.last_subagent_alert_key // ""')"
  [ -n "$key" ] || key="no-key-$now"
  if [ "$key" = "$last_key" ]; then
    return 0
  fi

  primary="$(get_primary_model_from_config)"
  submodel="$(jq -r '.agents.defaults.subagents.model // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
  case "$reason" in
    subagent-timeout)
      reason_text="子代理執行逾時（任務花太久，未在時限內完成）。"
      ;;
    sessions-spawn-failed)
      reason_text="子代理建立失敗（無法成功啟動子代理工作）。"
      ;;
    subagent-auth-failed)
      reason_text="子代理認證失敗（權杖或配對設定異常）。"
      ;;
    *)
      reason_text="子代理執行異常（請檢查最近一次子代理任務）。"
      ;;
  esac
  send_telegram "⚠️ 子代理異常告警
- 我判定壞掉的部分：${reason_text}
- 主模型：${primary:-unknown}
- 子代理模型：${submodel:-unknown}
- 事件時間：${ts:-未知}
（已即時回報，未自動改模型）"
  log "subagent failure alert: reason=${reason}, key=${key}, excerpt=${excerpt}"
  state_set ".last_subagent_alert_key=\"${key}\" | .last_subagent_alert_ts=${now}"
}

maybe_notify_google_keypool_issues() {
  local now last_check status_file parse_file sig blocked_count last_sig msg
  if ! is_true_flag "$NANOBOT_GOOGLE_KEYPOOL_ALERT_ENABLED"; then
    return 0
  fi
  now="$(date +%s)"
  last_check="$(state_get '.last_google_keypool_check_ts // 0')"
  if [ "$last_check" -gt 0 ] && [ "$((now - last_check))" -lt "$GOOGLE_KEYPOOL_CHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_google_keypool_check_ts=${now}"

  status_file="$(mktemp)"
  if ! curl -fsS --max-time 10 "$GOOGLE_KEYPOOL_STATUS_URL" -o "$status_file" 2>/dev/null; then
    rm -f "$status_file"
    return 0
  fi
  if [ "$(jq -r '.ok // false' "$status_file" 2>/dev/null || echo false)" != "true" ]; then
    rm -f "$status_file"
    return 0
  fi

  sig="$(jq -c '[.keys[] | {id,blocked,reason:(.last_error.reason // ""),status:(.last_error.status // 0),until:(.blocked_until // 0)}]' "$status_file" 2>/dev/null || echo '[]')"
  blocked_count="$(jq -r '[.keys[] | select(.blocked==true)] | length' "$status_file" 2>/dev/null || echo 0)"
  last_sig="$(state_get '.last_google_keypool_signature // ""')"

  if [ "$blocked_count" = "0" ]; then
    state_set ".last_google_keypool_signature=$(jq -Rn --arg v "$sig" '$v')"
    rm -f "$status_file"
    return 0
  fi

  if [ "$sig" = "$last_sig" ]; then
    rm -f "$status_file"
    return 0
  fi

  parse_file="$(mktemp)"
  if python3 - "$status_file" "$HOME_DIR/.openclaw/openclaw.env" >"$parse_file" <<'PY' 2>/dev/null
import datetime as dt
import hashlib
import json
import os
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
        user_label = ""
        m = re.match(r"GOOGLE_API_KEY_([A-Z])$", k)
        if m:
            idx = ord(m.group(1)) - ord("A") + 3
            user_label = f"GOOGLE_KEY_{idx}"
        id_map[kid] = {"env_name": k, "user_label": user_label}

blocked = [x for x in status.get("keys", []) if bool(x.get("blocked"))]
total = len(status.get("keys", []))
avail = max(total - len(blocked), 0)
lines = []
for item in blocked:
    kid = str(item.get("id") or "")
    meta = id_map.get(kid, {})
    env_name = meta.get("env_name") or "(未知環境變數)"
    user_label = meta.get("user_label") or "(未知序號)"
    reason = ((item.get("last_error") or {}).get("reason") or "unknown").strip()
    status_code = (item.get("last_error") or {}).get("status")
    until = int(item.get("blocked_until") or 0)
    if until > 0:
        t = dt.datetime.fromtimestamp(until, tz=dt.timezone.utc).astimezone(dt.timezone(dt.timedelta(hours=8)))
        until_text = t.strftime("%Y-%m-%d %H:%M:%S")
    else:
        until_text = "未知"
    if reason == "invalid-key":
        reason_text = "金鑰無效或已被平台標記風險"
    elif reason == "quota":
        reason_text = "額度用盡或流量限制"
    else:
        reason_text = "未知原因"
    lines.append(f"- {user_label}（{env_name}）: {reason_text}，HTTP {status_code}，解封時間 {until_text}")

print(f"⚠️ Google Key 輪換池告警\n- 目前可用：{avail}/{total}\n- 已封鎖：{len(blocked)} 把")
if lines:
    print("\n".join(lines))
PY
  then
    msg="$(cat "$parse_file")"
    [ -n "$msg" ] && send_telegram "$msg"
  fi
  rm -f "$parse_file"
  state_set ".last_google_keypool_signature=$(jq -Rn --arg v "$sig" '$v') | .last_google_keypool_alert_ts=${now}"
  rm -f "$status_file"
}

run_daemon() {
  local existing
  state_init
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
  trap 'pkill -P $$ >/dev/null 2>&1 || true; rm -f "$PID_FILE"; rm -rf "$LOCK_DIR"' EXIT
  trap 'exit 0' INT TERM HUP

  if ! is_true_flag "$NANOBOT_ENABLED"; then
    log "nanobot disabled; exit"
    exit 0
  fi
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    log "missing telegram credentials; exit"
    exit 1
  fi

  log "started v${NANOBOT_VERSION}, env=${NANOBOT_RUNTIME_ENV}, model=${NANOBOT_MODEL}, auto_healthcheck=${AUTO_HEALTHCHECK_ENABLED}, auto_rescue=${AUTO_RESCUE_ON_UNHEALTHY}"
  state_set ".started_at=$(date +%s) | .consecutive_health_failures=0"
  if is_true_flag "$NANOBOT_STARTUP_NOTIFY"; then
    send_telegram "🦀 潤天蟹已啟動（v${NANOBOT_VERSION}）。我會自動讀取引天渡狀態/日誌/版本並待命，你只要自然語言描述需求。"
  fi

  while true; do
    poll_telegram_updates
    maybe_process_openclaw_handoff
    maybe_notify_subagent_failure
    maybe_notify_google_keypool_issues
    check_health_cycle
    sleep "$POLL_INTERVAL_SECONDS"
  done
}

print_status() {
  state_init
  jq --arg version "$NANOBOT_VERSION" \
     --arg model "$NANOBOT_MODEL" \
     --arg auto_hc "$AUTO_HEALTHCHECK_ENABLED" \
     --arg auto_rescue "$AUTO_RESCUE_ON_UNHEALTHY" \
     '. + {version:$version, model:$model, auto_healthcheck:$auto_hc, auto_rescue:$auto_rescue}' \
     "$STATE_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  termux-rescue-nanobot.sh --daemon
  termux-rescue-nanobot.sh --once
  termux-rescue-nanobot.sh --status
  termux-rescue-nanobot.sh --diagnose
  termux-rescue-nanobot.sh --repair <reason>
  termux-rescue-nanobot.sh --simulate-text "<text>"
EOF
}

case "${1:---daemon}" in
  --daemon)
    run_daemon
    ;;
  --once)
    state_init
    poll_telegram_updates
    maybe_notify_subagent_failure
    check_health_cycle
    ;;
  --status)
    print_status
    ;;
  --diagnose)
    state_init
    build_status_report
    ;;
  --repair|--rescue)
    state_init
    run_repair_playbook "${2:-manual}"
    ;;
  --simulate-text)
    state_init
    handle_command "${2:-}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
