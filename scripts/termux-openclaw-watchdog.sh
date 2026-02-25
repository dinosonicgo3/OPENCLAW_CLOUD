#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

WATCHDOG_NAME="openclaw-watchdog"
WATCHDOG_VERSION="1.8.0"

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
STATE_DIR="${OPENCLAW_WATCHDOG_STATE_DIR:-$HOME_DIR/.openclaw-watchdog}"
STATE_FILE="$STATE_DIR/state.json"
HEARTBEAT_FILE="$STATE_DIR/openclaw-heartbeat.json"
MANIFEST_FILE="$STATE_DIR/critical-manifest.json"
LOG_FILE="${OPENCLAW_WATCHDOG_LOG:-$HOME_DIR/openclaw-logs/watchdog.log}"
ENV_FILE="${OPENCLAW_WATCHDOG_ENV:-$HOME_DIR/.openclaw-watchdog.env}"
PID_FILE="$STATE_DIR/daemon.pid"

REPO_DIR_DEFAULT="$HOME_DIR/DINO_OPENCLAW"
REPO_DIR="${OPENCLAW_REPO_DIR:-$REPO_DIR_DEFAULT}"
REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-core-guard.sh}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME_DIR/.termux/boot/openclaw-launch.sh}"

POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-180}"
MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-1800}"
MAINTENANCE_TIMEOUT_SECONDS="${MAINTENANCE_TIMEOUT_SECONDS:-1800}"
MAINTENANCE_AUTO_CLOSE_IF_HEALTHY="${MAINTENANCE_AUTO_CLOSE_IF_HEALTHY:-1}"
MAINTENANCE_AUTO_CLOSE_MIN_SECONDS="${MAINTENANCE_AUTO_CLOSE_MIN_SECONDS:-120}"
RESCUE_COOLDOWN_SECONDS="${RESCUE_COOLDOWN_SECONDS:-300}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-45}"
STARTUP_GRACE_SECONDS="${STARTUP_GRACE_SECONDS:-300}"
HEALTHCHECK_FAIL_THRESHOLD="${HEALTHCHECK_FAIL_THRESHOLD:-2}"
MODEL_COOLDOWN_SECONDS="${MODEL_COOLDOWN_SECONDS:-86400}"
MODEL_COOLDOWN_SOFT_THRESHOLD="${MODEL_COOLDOWN_SOFT_THRESHOLD:-3}"
MODEL_SCAN_FILE_COUNT="${MODEL_SCAN_FILE_COUNT:-30}"
MODEL_POLICY_RESTART_ON_CHANGE="${MODEL_POLICY_RESTART_ON_CHANGE:-0}"
DRIFT_AUTO_BASELINE_IF_HEALTHY="${DRIFT_AUTO_BASELINE_IF_HEALTHY:-1}"
SELFCHECK_INTERVAL_SECONDS="${SELFCHECK_INTERVAL_SECONDS:-1800}"
SELFCHECK_ALERT_COOLDOWN_SECONDS="${SELFCHECK_ALERT_COOLDOWN_SECONDS:-3600}"
SELFCHECK_MEMORY_INDEX_GRACE_SECONDS="${SELFCHECK_MEMORY_INDEX_GRACE_SECONDS:-21600}"
HANDSHAKE_INTERVAL_SECONDS="${HANDSHAKE_INTERVAL_SECONDS:-1800}"
HANDSHAKE_TIMEOUT_SECONDS="${HANDSHAKE_TIMEOUT_SECONDS:-45}"
HANDSHAKE_STALE_SECONDS="${HANDSHAKE_STALE_SECONDS:-900}"
HANDSHAKE_FAIL_THRESHOLD="${HANDSHAKE_FAIL_THRESHOLD:-1}"
SELF_CHECK_ENFORCE_LOCAL_MEMORY="${SELF_CHECK_ENFORCE_LOCAL_MEMORY:-1}"
OPENCLAW_MEMORY_EMBEDDING_MODEL="${OPENCLAW_MEMORY_EMBEDDING_MODEL:-}"
OPENCLAW_MEMORY_MODEL_CACHE_DIR="${OPENCLAW_MEMORY_MODEL_CACHE_DIR:-$HOME_DIR/.cache/openclaw/models}"
OPENCLAW_COMPACTION_RESERVE_TOKENS="${OPENCLAW_COMPACTION_RESERVE_TOKENS:-20000}"
OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS="${OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS:-4000}"
OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT="${OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT:-Write any lasting notes, rules, facts or preferences to memory/YYYY-MM-DD.md or MEMORY.md. Reply NO_REPLY if nothing to store.}"

OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
WATCHDOG_TELEGRAM_BOT_TOKEN="${WATCHDOG_TELEGRAM_BOT_TOKEN:-}"
WATCHDOG_TELEGRAM_POLL_ENABLED="${WATCHDOG_TELEGRAM_POLL_ENABLED:-0}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"

mkdir -p "$STATE_DIR" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

REPO_DIR="${OPENCLAW_REPO_DIR:-$REPO_DIR_DEFAULT}"
REPO_BRANCH="${OPENCLAW_REPO_BRANCH:-main}"
CORE_GUARD_SCRIPT="${OPENCLAW_CORE_GUARD_SCRIPT:-$REPO_DIR/scripts/termux-openclaw-core-guard.sh}"
OPENCLAW_BOOT_SCRIPT="${OPENCLAW_BOOT_SCRIPT:-$HOME_DIR/.termux/boot/openclaw-launch.sh}"

if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  TELEGRAM_BOT_TOKEN="$(jq -r '.channels.telegram.botToken // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
if [ -z "$TELEGRAM_OWNER_ID" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  TELEGRAM_OWNER_ID="$(jq -r '.channels.telegram.allowFrom[0] // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi
if [ -z "$NVIDIA_API_KEY" ] && [ -f "$HOME_DIR/.openclaw/openclaw.json" ]; then
  NVIDIA_API_KEY="$(jq -r '.models.providers.nvidia.apiKey // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
fi

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  mkdir -p "$(dirname "$LOG_FILE")"
  printf '[%s] [%s] %s\n' "$ts" "$WATCHDOG_NAME" "$*" >>"$LOG_FILE"
}

state_init() {
  if [ ! -f "$STATE_FILE" ]; then
    cat >"$STATE_FILE" <<'EOF'
{
  "last_update_id": 0,
  "last_monitor_ts": 0,
  "last_rescue_ts": 0,
  "last_rescue_reason": "",
  "consecutive_health_failures": 0,
  "started_at": 0,
  "maintenance": {
    "active": false,
    "reason": "",
    "started_at": 0,
    "deadline_at": 0
  },
  "model_guard": {
    "last_scan_ts": 0,
    "last_model_event_ts": "",
    "last_model_ref": "",
    "blocked_until": {},
    "blocked_reason": {}
  },
  "selfcheck": {
    "last_run_ts": 0,
    "last_alert_ts": 0,
    "last_alert_sig": ""
  },
  "handshake": {
    "last_attempt_ts": 0,
    "last_ok_ts": 0,
    "last_fail_ts": 0,
    "consecutive_failures": 0,
    "last_reason": ""
  }
}
EOF
  fi
  state_migrate
}

state_get() {
  local q="$1"
  jq -r "$q" "$STATE_FILE"
}

state_set() {
  local jq_expr="$1"
  local tmp
  tmp="$(mktemp)"
  jq "$jq_expr" "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

state_migrate() {
  local tmp
  tmp="$(mktemp)"
  jq '
    .last_update_id = (.last_update_id // 0) |
    .last_monitor_ts = (.last_monitor_ts // 0) |
    .last_rescue_ts = (.last_rescue_ts // 0) |
    .last_rescue_reason = (.last_rescue_reason // "") |
    .consecutive_health_failures = (.consecutive_health_failures // 0) |
    .started_at = (.started_at // 0) |
    .maintenance = (.maintenance // {}) |
    .maintenance.active = (.maintenance.active // false) |
    .maintenance.reason = (.maintenance.reason // "") |
    .maintenance.started_at = (.maintenance.started_at // 0) |
    .maintenance.deadline_at = (.maintenance.deadline_at // 0) |
    .model_guard = (.model_guard // {}) |
    .model_guard.last_scan_ts = (.model_guard.last_scan_ts // 0) |
    .model_guard.last_model_event_ts = (.model_guard.last_model_event_ts // "") |
    .model_guard.last_model_ref = (.model_guard.last_model_ref // "") |
    .model_guard.blocked_until = (.model_guard.blocked_until // {}) |
    .model_guard.blocked_reason = (.model_guard.blocked_reason // {}) |
    .selfcheck = (.selfcheck // {}) |
    .selfcheck.last_run_ts = (.selfcheck.last_run_ts // 0) |
    .selfcheck.last_alert_ts = (.selfcheck.last_alert_ts // 0) |
    .selfcheck.last_alert_sig = (.selfcheck.last_alert_sig // "") |
    .handshake = (.handshake // {}) |
    .handshake.last_attempt_ts = (.handshake.last_attempt_ts // 0) |
    .handshake.last_ok_ts = (.handshake.last_ok_ts // 0) |
    .handshake.last_fail_ts = (.handshake.last_fail_ts // 0) |
    .handshake.consecutive_failures = (.handshake.consecutive_failures // 0) |
    .handshake.last_reason = (.handshake.last_reason // "")
  ' "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

sha_path() {
  local file="$1"
  if [ ! -f "$file" ]; then
    printf 'missing'
    return 0
  fi
  sha256sum "$file" | awk '{print $1}'
}

critical_paths() {
  cat <<EOF
$REPO_DIR/scripts/termux-openclaw-core-guard.sh
$REPO_DIR/scripts/termux-openclaw-watchdog.sh
$REPO_DIR/scripts/termux-rebuild-openclaw.sh
$REPO_DIR/scripts/termux-main-system-update.sh
$OPENCLAW_BOOT_SCRIPT
$HOME_DIR/.termux/boot/openclaw-watchdog-launch.sh
$HOME_DIR/.termux/boot/start-openclaw.sh
EOF
}

refresh_critical_manifest() {
  local tmp tmp2 path sha now
  tmp="$(mktemp)"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n --arg now "$now" '{generated_at_utc:$now, entries:[]}' >"$tmp"
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    sha="$(sha_path "$path")"
    tmp2="$(mktemp)"
    jq --arg p "$path" --arg s "$sha" '.entries += [{"path":$p,"sha256":$s}]' "$tmp" >"$tmp2"
    mv "$tmp2" "$tmp"
  done < <(critical_paths)
  mv "$tmp" "$MANIFEST_FILE"
  chmod 600 "$MANIFEST_FILE"
  log "critical manifest refreshed: $MANIFEST_FILE"
}

critical_drift_detected() {
  local line path expected actual
  if [ ! -f "$MANIFEST_FILE" ]; then
    refresh_critical_manifest
    return 1
  fi

  while IFS=$'\t' read -r path expected; do
    [ -n "${path:-}" ] || continue
    actual="$(sha_path "$path")"
    if [ "$actual" != "$expected" ]; then
      log "critical drift: path=$path expected=$expected actual=$actual"
      printf '%s\n' "$path"
      return 0
    fi
  done < <(jq -r '.entries[]? | [.path, .sha256] | @tsv' "$MANIFEST_FILE" 2>/dev/null || true)

  return 1
}

send_telegram() {
  local msg="$1"
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    return 0
  fi
  curl -fsS --max-time 20 \
    -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_OWNER_ID}" \
    --data-urlencode "text=${msg}" \
    -d "disable_web_page_preview=true" >/dev/null 2>&1 || true
}

is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_local_memory_config() {
  local cfg tmp
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  [ -f "$cfg" ] || return 1
  tmp="$(mktemp)"
  if ! jq \
    --arg embeddingModel "$OPENCLAW_MEMORY_EMBEDDING_MODEL" \
    --arg embeddingCacheDir "$OPENCLAW_MEMORY_MODEL_CACHE_DIR" \
    --argjson compactionReserve "$OPENCLAW_COMPACTION_RESERVE_TOKENS" \
    --argjson compactionSoft "$OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS" \
    --arg compactionPrompt "$OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT" \
    '
    .agents = (.agents // {}) |
    .agents.defaults = (.agents.defaults // {}) |
    .agents.defaults.memorySearch = (.agents.defaults.memorySearch // {}) |
    .agents.defaults.memorySearch.provider = "local" |
    .agents.defaults.memorySearch.fallback = "none" |
    .agents.defaults.memorySearch.local = (.agents.defaults.memorySearch.local // {}) |
    if ($embeddingModel | length) > 0 then
      .agents.defaults.memorySearch.local.modelPath = $embeddingModel
    else
      del(.agents.defaults.memorySearch.local.modelPath)
    end |
    .agents.defaults.memorySearch.local.modelCacheDir = $embeddingCacheDir |
    .agents.defaults.memorySearch.store = (.agents.defaults.memorySearch.store // {}) |
    .agents.defaults.memorySearch.store.vector = (.agents.defaults.memorySearch.store.vector // {}) |
    .agents.defaults.memorySearch.store.vector.enabled = false |
    .agents.defaults.memorySearch.query = (.agents.defaults.memorySearch.query // {}) |
    .agents.defaults.memorySearch.query.hybrid = (.agents.defaults.memorySearch.query.hybrid // {}) |
    .agents.defaults.memorySearch.query.hybrid.enabled = true |
    .agents.defaults.memorySearch.query.hybrid.vectorWeight = 0 |
    .agents.defaults.memorySearch.query.hybrid.textWeight = 1 |
    .agents.defaults.compaction = (.agents.defaults.compaction // {}) |
    .agents.defaults.compaction.mode = "safeguard" |
    .agents.defaults.compaction.reserveTokensFloor = ((.agents.defaults.compaction.reserveTokensFloor | tonumber?) // $compactionReserve) |
    .agents.defaults.compaction.memoryFlush = (.agents.defaults.compaction.memoryFlush // {}) |
    .agents.defaults.compaction.memoryFlush.enabled = true |
    .agents.defaults.compaction.memoryFlush.softThresholdTokens = ((.agents.defaults.compaction.memoryFlush.softThresholdTokens | tonumber?) // $compactionSoft) |
    .agents.defaults.compaction.memoryFlush.prompt = (
      if ((.agents.defaults.compaction.memoryFlush.prompt // "") | length) > 0
      then .agents.defaults.compaction.memoryFlush.prompt
      else $compactionPrompt
      end
    ) |
    del(.agents.defaults.compaction.keepRecentTokens) |
    del(.agents.defaults.compaction.memoryFlush.hardThresholdTokens) |
    del(.channels.telegram.dmToken) |
    del(.agents.defaults.memorySearch.remote)
  ' "$cfg" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! cmp -s "$cfg" "$tmp"; then
    cp -f "$cfg" "$cfg.bak.selfcheck.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    mv "$tmp" "$cfg"
    chmod 600 "$cfg" >/dev/null 2>&1 || true
    log "selfcheck auto-fixed memorySearch to local/no-remote (Termux-safe settings)"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

ensure_gateway_controlui_config() {
  local cfg tmp
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  [ -f "$cfg" ] || return 1
  tmp="$(mktemp)"
  if ! jq '
    .gateway = (.gateway // {}) |
    if ((.gateway.bind // "lan") == "lan") then
      .gateway.controlUi = (.gateway.controlUi // {}) |
      .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true
    else
      .
    end
  ' "$cfg" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! cmp -s "$cfg" "$tmp"; then
    cp -f "$cfg" "$cfg.bak.selfcheck.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    mv "$tmp" "$cfg"
    chmod 600 "$cfg" >/dev/null 2>&1 || true
    log "selfcheck auto-fixed gateway.controlUi for lan bind"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

memory_index_warmup_active() {
  pgrep -f "openclaw-memory|openclaw memory index|cmake-js compile|node-llama-cpp|embeddinggemma" >/dev/null 2>&1
}

run_full_selfcheck() {
  local now notify_mode cfg cfg_port cfg_bind env_port provider_cfg workspace_path mem_files cfg_embed_model cfg_embed_cache cfg_controlui_fallback
  local mem_status_json mem_indexed mem_scanned mem_provider_runtime mem_model_runtime issues_text
  local started_at startup_age warmup_active
  local last_alert_sig last_alert_ts sig should_notify summary
  local -a issues
  issues=()
  now="${1:-$(date +%s)}"
  notify_mode="${2:-auto}"
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  env_port="${OPENCLAW_PORT:-}"

  if is_true_flag "$SELF_CHECK_ENFORCE_LOCAL_MEMORY"; then
    if ensure_local_memory_config; then
      issues+=("已自動修正 memorySearch 為 local/no-remote。")
    fi
  fi
  if ensure_gateway_controlui_config; then
    issues+=("已自動修正 gateway.controlUi（lan bind 啟動保護）。")
  fi

  if [ ! -f "$cfg" ]; then
    issues+=("缺少主配置檔：$cfg")
  else
    cfg_port="$(jq -r '.gateway.port // empty' "$cfg" 2>/dev/null || true)"
    cfg_bind="$(jq -r '.gateway.bind // "lan"' "$cfg" 2>/dev/null || echo lan)"
    if [ -n "$cfg_port" ] && [ -n "$env_port" ] && [ "$cfg_port" != "$env_port" ]; then
      issues+=("OpenClaw/Watchdog port 不一致（config=${cfg_port}, watchdog=${env_port}）。")
    fi
    cfg_controlui_fallback="$(jq -r '.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback // "unset"' "$cfg" 2>/dev/null || echo unset)"
    if [ "$cfg_bind" = "lan" ] && [ "$cfg_controlui_fallback" != "true" ]; then
      issues+=("gateway.controlUi 保護缺失（bind=lan 時需 fallback=true）。")
    fi

    provider_cfg="$(jq -r '.agents.defaults.memorySearch.provider // "unset"' "$cfg" 2>/dev/null || echo unset)"
    if [ "$provider_cfg" != "local" ]; then
      issues+=("memorySearch.provider 非 local（目前=${provider_cfg}）。")
    fi
    cfg_embed_model="$(jq -r '.agents.defaults.memorySearch.local.modelPath // empty' "$cfg" 2>/dev/null || true)"
    cfg_embed_cache="$(jq -r '.agents.defaults.memorySearch.local.modelCacheDir // empty' "$cfg" 2>/dev/null || true)"
    if [ -n "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ] && [ "$cfg_embed_model" != "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ]; then
      issues+=("記憶嵌入模型不符（config=${cfg_embed_model:-unset}, expected=${OPENCLAW_MEMORY_EMBEDDING_MODEL}）。")
    fi
    if [ -z "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ] && [ -n "$cfg_embed_model" ]; then
      issues+=("Termux 本地記憶應停用嵌入模型（目前 config modelPath=${cfg_embed_model}）。")
    fi
    if [ -n "$cfg_embed_cache" ] && [ "$cfg_embed_cache" != "$OPENCLAW_MEMORY_MODEL_CACHE_DIR" ]; then
      issues+=("記憶模型快取路徑不符（config=${cfg_embed_cache}, expected=${OPENCLAW_MEMORY_MODEL_CACHE_DIR}）。")
    fi
    if jq -e '.agents.defaults.memorySearch.remote.apiKey? | strings | length > 0' "$cfg" >/dev/null 2>&1; then
      issues+=("memorySearch.remote.apiKey 仍存在（應移除以避免雲端同步）。")
    fi
    if jq -e '.agents.defaults.compaction.memoryFlush.hardThresholdTokens? != null' "$cfg" >/dev/null 2>&1; then
      issues+=("compaction.memoryFlush.hardThresholdTokens 為無效欄位。")
    fi
    if jq -e '.agents.defaults.compaction.keepRecentTokens? != null' "$cfg" >/dev/null 2>&1; then
      issues+=("compaction.keepRecentTokens 為無效欄位。")
    fi
    if jq -e '.channels.telegram.dmToken? != null' "$cfg" >/dev/null 2>&1; then
      issues+=("channels.telegram.dmToken 為無效欄位。")
    fi
    if [ "$(jq -r '.agents.defaults.compaction.mode // "unset"' "$cfg" 2>/dev/null || echo unset)" != "safeguard" ]; then
      issues+=("compaction.mode 非 safeguard。")
    fi

    workspace_path="$(jq -r '.agents.defaults.workspace // empty' "$cfg" 2>/dev/null || true)"
    if [ -z "$workspace_path" ]; then
      workspace_path="$HOME_DIR/.openclaw/workspace"
    elif [ "${workspace_path#~/}" != "$workspace_path" ]; then
      workspace_path="$HOME_DIR/${workspace_path#~/}"
    fi
    if [ ! -e "$workspace_path" ] && [ ! -L "$workspace_path" ]; then
      issues+=("workspace 路徑不存在：${workspace_path}")
    fi

    mem_files="$(find -L "${workspace_path}/memory" -type f -name '*.md' 2>/dev/null | wc -l | tr -d '[:space:]' || echo 0)"
    if ! printf '%s' "$mem_files" | grep -Eq '^[0-9]+$'; then
      mem_files=0
    fi
  fi

  for p in \
    "$REPO_DIR/scripts/termux-openclaw-watchdog.sh" \
    "$REPO_DIR/scripts/termux-openclaw-core-guard.sh" \
    "$REPO_DIR/scripts/termux-rebuild-openclaw.sh" \
    "$REPO_DIR/scripts/termux-main-system-update.sh" \
    "$HOME_DIR/.termux/boot/openclaw-launch.sh" \
    "$HOME_DIR/.termux/boot/openclaw-watchdog-launch.sh" \
    "$HOME_DIR/.termux/boot/start-openclaw.sh"; do
    if [ ! -x "$p" ]; then
      issues+=("腳本不可執行：$p")
    fi
  done

  started_at="$(state_get '.started_at // 0')"
  if ! printf '%s' "$started_at" | grep -Eq '^[0-9]+$'; then
    started_at=0
  fi
  startup_age=0
  if [ "$started_at" -gt 0 ] && [ "$now" -ge "$started_at" ]; then
    startup_age="$((now - started_at))"
  fi
  warmup_active=0
  if memory_index_warmup_active; then
    warmup_active=1
  fi

  mem_status_json=""
  if command -v timeout >/dev/null 2>&1; then
    mem_status_json="$(timeout 25 openclaw memory status --json 2>/dev/null || true)"
  else
    mem_status_json="$(openclaw memory status --json 2>/dev/null || true)"
  fi
  if [ -z "$mem_status_json" ]; then
    sleep 2
    if command -v timeout >/dev/null 2>&1; then
      mem_status_json="$(timeout 25 openclaw memory status --json 2>/dev/null || true)"
    else
      mem_status_json="$(openclaw memory status --json 2>/dev/null || true)"
    fi
  fi
  if [ -n "$mem_status_json" ]; then
    mem_indexed="$(printf '%s' "$mem_status_json" | jq -r '.[0].status.files // 0' 2>/dev/null || echo 0)"
    mem_scanned="$(printf '%s' "$mem_status_json" | jq -r '.[0].scan.totalFiles // 0' 2>/dev/null || echo 0)"
    mem_provider_runtime="$(printf '%s' "$mem_status_json" | jq -r '.[0].status.provider // "unknown"' 2>/dev/null || echo unknown)"
    mem_model_runtime="$(printf '%s' "$mem_status_json" | jq -r '.[0].status.model // empty' 2>/dev/null || true)"
    if ! printf '%s' "$mem_indexed" | grep -Eq '^[0-9]+$'; then mem_indexed=0; fi
    if ! printf '%s' "$mem_scanned" | grep -Eq '^[0-9]+$'; then mem_scanned=0; fi
    if [ -n "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ] && [ "$mem_provider_runtime" = "local" ] && [ -n "$mem_model_runtime" ] && [ "$mem_model_runtime" != "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ]; then
      issues+=("記憶運行模型不符（runtime=${mem_model_runtime}, expected=${OPENCLAW_MEMORY_EMBEDDING_MODEL}）。")
    fi
    if [ -n "$OPENCLAW_MEMORY_EMBEDDING_MODEL" ] && [ "$mem_scanned" -gt 0 ] && [ "$mem_indexed" -eq 0 ]; then
      if [ "$warmup_active" -eq 1 ]; then
        log "memory index warmup in progress; suppressing indexed=0 alert"
      elif [ "$startup_age" -lt "$SELFCHECK_MEMORY_INDEX_GRACE_SECONDS" ]; then
        log "memory index grace window active (${startup_age}s < ${SELFCHECK_MEMORY_INDEX_GRACE_SECONDS}s); suppressing indexed=0 alert"
      else
        issues+=("記憶索引異常：indexed=${mem_indexed}/${mem_scanned}（provider=${mem_provider_runtime}）。")
        if [ "${mem_files:-0}" -gt 0 ]; then
          issues+=("記憶檔存在(${mem_files})但索引為 0，memory_search 會回空。")
        fi
      fi
    fi
  else
    if [ "$warmup_active" -eq 1 ]; then
      log "memory status unavailable during warmup; suppressing alert"
    elif [ "$startup_age" -lt "$SELFCHECK_MEMORY_INDEX_GRACE_SECONDS" ]; then
      log "memory status unavailable during startup grace (${startup_age}s < ${SELFCHECK_MEMORY_INDEX_GRACE_SECONDS}s); suppressing alert"
    elif ! openclaw_healthy; then
      log "memory status unavailable while openclaw unhealthy; suppressing alert"
    else
      issues+=("無法取得 memory status（openclaw memory status --json）。")
    fi
  fi

  if [ "${#issues[@]}" -gt 0 ]; then
    issues_text="$(printf '%s\n' "${issues[@]}")"
    sig="$(printf '%s' "$issues_text" | sha256sum | awk '{print $1}')"
    last_alert_sig="$(state_get '.selfcheck.last_alert_sig // ""')"
    last_alert_ts="$(state_get '.selfcheck.last_alert_ts // 0')"
    should_notify=0
    if [ "$notify_mode" = "force" ]; then
      should_notify=1
    elif [ "$sig" != "$last_alert_sig" ]; then
      should_notify=1
    elif [ "$((now - last_alert_ts))" -ge "$SELFCHECK_ALERT_COOLDOWN_SECONDS" ]; then
      should_notify=1
    fi

    summary="$(printf '%s\n' "${issues[@]}" | head -n 12)"
    log "full self-check issues: $(printf '%s' "$summary" | tr '\n' '; ')"
    if [ "$should_notify" -eq 1 ]; then
      send_telegram "🩺 Watchdog 全功能自檢發現問題：
${summary}
（已啟用主動提醒）"
      state_set ".selfcheck.last_alert_ts=${now} | .selfcheck.last_alert_sig=\"${sig}\""
    fi
    printf 'issues\n'
    return 1
  fi

  last_alert_sig="$(state_get '.selfcheck.last_alert_sig // ""')"
  if [ -n "$last_alert_sig" ] || [ "$notify_mode" = "force" ]; then
    send_telegram "✅ Watchdog 全功能自檢通過：核心檔案/記憶/skills/Obsidian 檢查正常。"
    state_set ".selfcheck.last_alert_ts=${now} | .selfcheck.last_alert_sig=\"\""
  fi
  log "full self-check passed"
  printf 'ok\n'
  return 0
}

maybe_run_full_selfcheck() {
  local now last_run
  now="${1:-$(date +%s)}"
  last_run="$(state_get '.selfcheck.last_run_ts // 0')"
  if [ "$((now - last_run))" -lt "$SELFCHECK_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".selfcheck.last_run_ts=${now}"
  run_full_selfcheck "$now" "auto" >/dev/null 2>&1 || true
}

disallowed_model_ref() {
  local ref normalized
  ref="${1:-}"
  normalized="$(printf '%s' "$ref" | tr '[:upper:]' '[:lower:]')"
  case "$normalized" in
    */zai-org/glm-5|*/z-ai/glm5|zai/glm-5|zai/glm5)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

drift_auto_heal_allowed_path() {
  local path
  path="${1:-}"
  case "$path" in
    "$REPO_DIR/scripts/termux-openclaw-watchdog.sh"|\
    "$REPO_DIR/scripts/termux-rebuild-openclaw.sh"|\
    "$REPO_DIR/scripts/termux-main-system-update.sh"|\
    "$REPO_DIR/scripts/termux-openclaw-core-guard.sh")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

model_error_hard_unusable() {
  local err
  err="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "$err" == *"prompt tokens limit exceeded"* ]] && return 0
  [[ "$err" == *"creditserror"* ]] && return 0
  [[ "$err" == *"no payment method"* ]] && return 0
  [[ "$err" == *"does not yet include access"* ]] && return 0
  [[ "$err" == *"cannot read properties of undefined (reading 'prompt_tokens')"* ]] && return 0
  [[ "$err" == *"model not found"* ]] && return 0
  [[ "$err" == *"unsupported model"* ]] && return 0
  return 1
}

model_error_soft_unusable() {
  local err
  err="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "$err" == *"too many requests"* ]] && return 0
  [[ "$err" == *"error decoding response body"* ]] && return 0
  [[ "$err" == *"request was aborted"* ]] && return 0
  [[ "$err" == *"llm request timed out"* ]] && return 0
  [[ "$err" == *"timed out"* ]] && return 0
  return 1
}

block_model_for_cooldown() {
  local ref reason now expiry current tmp msg
  ref="${1:-}"
  reason="${2:-unknown}"
  [ -n "$ref" ] || return 0
  now="$(date +%s)"
  expiry="$((now + MODEL_COOLDOWN_SECONDS))"
  current="$(jq -r --arg ref "$ref" '.model_guard.blocked_until[$ref] // 0' "$STATE_FILE" 2>/dev/null || echo 0)"
  if [ "${current:-0}" -ge "$expiry" ]; then
    return 0
  fi
  tmp="$(mktemp)"
  jq --arg ref "$ref" --arg reason "$reason" --argjson expiry "$expiry" \
    '.model_guard.blocked_until[$ref] = $expiry | .model_guard.blocked_reason[$ref] = $reason' \
    "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
  log "model cooldown set: ref=${ref}, until=${expiry}, reason=${reason}"
  msg="⛔ 模型暫停使用：${ref}
原因：${reason}
已標記 24 小時內不再調用此平台模型。"
  send_telegram "$msg"
}

prune_expired_model_cooldowns() {
  local now tmp
  now="$(date +%s)"
  tmp="$(mktemp)"
  jq --argjson now "$now" '
    (.model_guard.blocked_until // {}) as $blocked |
    .model_guard.blocked_until = ($blocked | with_entries(select(.value > $now))) |
    (.model_guard.blocked_until // {}) as $active |
    .model_guard.blocked_reason = ((.model_guard.blocked_reason // {}) | with_entries(select(.key as $k | ($active[$k] // 0) > $now)))
  ' "$STATE_FILE" >"$tmp"
  mv "$tmp" "$STATE_FILE"
}

scan_model_failures() {
  local session_dir files last_scan now f
  session_dir="$HOME_DIR/.openclaw/agents/main/sessions"
  [ -d "$session_dir" ] || return 0
  last_scan="$(state_get '.model_guard.last_scan_ts // 0')"
  now="$(date +%s)"
  files="$(ls -1t "$session_dir"/*.jsonl 2>/dev/null | head -n "$MODEL_SCAN_FILE_COUNT" || true)"
  [ -n "$files" ] || {
    state_set ".model_guard.last_scan_ts=${now}"
    return 0
  }

  declare -A soft_count
  declare -A soft_reason
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    while IFS=$'\t' read -r epoch provider model err; do
      local ref err_clean threshold
      [ -n "${epoch:-}" ] || continue
      [ "${epoch:-0}" -gt "${last_scan:-0}" ] || continue
      [ -n "${provider:-}" ] || continue
      [ -n "${model:-}" ] || continue
      if [ "${model#${provider}/}" != "$model" ]; then
        ref="$model"
      else
        ref="${provider}/${model}"
      fi
      err_clean="$(printf '%s' "${err:-unknown}" | tr '\n' ' ' | tr -s ' ')"
      if model_error_hard_unusable "$err_clean"; then
        block_model_for_cooldown "$ref" "$err_clean"
        continue
      fi
      if model_error_soft_unusable "$err_clean"; then
        soft_count["$ref"]="$(( ${soft_count["$ref"]:-0} + 1 ))"
        soft_reason["$ref"]="$err_clean"
      fi
    done < <(
      jq -r '
        if .type=="message" and .message.role=="assistant" and ((.message.stopReason=="error") or (.message.stopReason=="aborted")) then
          [(.timestamp|fromdateiso8601? // 0), (.message.provider // ""), (.message.model // ""), (.message.errorMessage // .message.stopReason // "error")] | @tsv
        elif .type=="custom" and .customType=="openclaw:prompt-error" then
          [((.data.timestamp // 0) / 1000 | floor), (.data.provider // ""), (.data.model // ""), (.data.error // "error")] | @tsv
        else
          empty
        end
      ' "$f" 2>/dev/null || true
    )
  done <<< "$files"

  threshold="${MODEL_COOLDOWN_SOFT_THRESHOLD:-3}"
  for ref in "${!soft_count[@]}"; do
    if [ "${soft_count[$ref]:-0}" -ge "$threshold" ]; then
      block_model_for_cooldown "$ref" "${soft_reason[$ref]}"
    fi
  done
  state_set ".model_guard.last_scan_ts=${now}"
}

apply_model_policy() {
  local cfg now before_primary before_fallbacks after_primary after_fallbacks tmp msg
  cfg="$HOME_DIR/.openclaw/openclaw.json"
  [ -f "$cfg" ] || return 0
  now="$(date +%s)"
  prune_expired_model_cooldowns

  before_primary="$(jq -r '.agents.defaults.model.primary // empty' "$cfg" 2>/dev/null || true)"
  before_fallbacks="$(jq -r '(.agents.defaults.model.fallbacks // []) | join(",")' "$cfg" 2>/dev/null || true)"

  tmp="$(mktemp)"
  jq --argjson now "$now" --slurpfile st "$STATE_FILE" '
    .agents = (.agents // {}) |
    .agents.defaults = (.agents.defaults // {}) |
    .agents.defaults.model = (.agents.defaults.model // {}) |
    ($st[0].model_guard.blocked_until // {}) as $blocked |
    def blocked($r): (($blocked[$r] // 0) > $now);
    def disallowed($r): (($r | ascii_downcase) | test("(^|.*/)(zai-org/glm-5|z-ai/glm5)$"));
    (.agents.defaults.model.primary // "") as $primary |
    (.agents.defaults.model.fallbacks // []) as $fallbacks |
    ($fallbacks | map(select((blocked(.) | not) and (disallowed(.) | not))) | unique) as $allowedFallbacks |
    if ($primary | length) == 0 then
      .agents.defaults.model.fallbacks = $allowedFallbacks
    elif blocked($primary) or disallowed($primary) then
      if ($allowedFallbacks | length) > 0 then
        .agents.defaults.model.primary = $allowedFallbacks[0] |
        .agents.defaults.model.fallbacks = ($allowedFallbacks | .[1:])
      else
        .agents.defaults.model.fallbacks = []
      end
    else
      .agents.defaults.model.fallbacks = $allowedFallbacks
    end
  ' "$cfg" >"$tmp"

  if ! cmp -s "$cfg" "$tmp"; then
    mv "$tmp" "$cfg"
    after_primary="$(jq -r '.agents.defaults.model.primary // empty' "$cfg" 2>/dev/null || true)"
    after_fallbacks="$(jq -r '(.agents.defaults.model.fallbacks // []) | join(",")' "$cfg" 2>/dev/null || true)"
    msg="🛠️ Watchdog: 模型路由策略已更新
primary: ${before_primary} -> ${after_primary}
fallbacks: ${before_fallbacks}
=> ${after_fallbacks}"
    log "model policy updated: primary ${before_primary} -> ${after_primary}"
    send_telegram "$msg"
    if is_true_flag "$MODEL_POLICY_RESTART_ON_CHANGE"; then
      if restart_openclaw_after_guard; then
        send_telegram "✅ Watchdog: 已重啟 OpenClaw 套用新的模型策略。"
      else
        send_telegram "⚠️ Watchdog: 模型策略已更新，但重啟 OpenClaw 失敗，請手動執行 ocr。"
      fi
    fi
  else
    rm -f "$tmp"
  fi
}

notify_fallback_switch() {
  local session_dir files f latest_epoch latest_ts latest_provider latest_model line
  local last_ts primary ref
  session_dir="$HOME_DIR/.openclaw/agents/main/sessions"
  [ -d "$session_dir" ] || return 0
  files="$(ls -1t "$session_dir"/*.jsonl 2>/dev/null | head -n "$MODEL_SCAN_FILE_COUNT" || true)"
  [ -n "$files" ] || return 0

  latest_epoch=0
  latest_ts=""
  latest_provider=""
  latest_model=""
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    while IFS=$'\t' read -r epoch ts provider model; do
      [ -n "${epoch:-}" ] || continue
      if [ "${epoch:-0}" -ge "$latest_epoch" ]; then
        latest_epoch="${epoch:-0}"
        latest_ts="${ts:-}"
        latest_provider="${provider:-}"
        latest_model="${model:-}"
      fi
    done < <(
      jq -r 'select(.type=="model_change") | [(.timestamp|fromdateiso8601? // 0), (.timestamp // ""), (.provider // ""), (.modelId // "")] | @tsv' "$f" 2>/dev/null || true
    )
  done <<< "$files"

  [ -n "$latest_ts" ] || return 0
  last_ts="$(state_get '.model_guard.last_model_event_ts // ""')"
  [ "$latest_ts" = "$last_ts" ] && return 0

  if [ "${latest_model#${latest_provider}/}" != "$latest_model" ]; then
    ref="$latest_model"
  else
    ref="${latest_provider}/${latest_model}"
  fi

  line="$(mktemp)"
  jq --arg ts "$latest_ts" --arg ref "$ref" \
    '.model_guard.last_model_event_ts = $ts | .model_guard.last_model_ref = $ref' \
    "$STATE_FILE" >"$line"
  mv "$line" "$STATE_FILE"

  primary="$(jq -r '.agents.defaults.model.primary // empty' "$HOME_DIR/.openclaw/openclaw.json" 2>/dev/null || true)"
  if [ -n "$ref" ] && [ "$ref" != "$primary" ] && jq -e --arg ref "$ref" '.agents.defaults.model.fallbacks // [] | index($ref) != null' "$HOME_DIR/.openclaw/openclaw.json" >/dev/null 2>&1; then
    log "fallback model active: ${ref} (primary=${primary})"
    send_telegram "ℹ️ 模型切換通知：已切到備援模型 ${ref}（主模型：${primary}）。"
  fi
}

enforce_model_guard() {
  scan_model_failures
  apply_model_policy
  notify_fallback_switch
}

run_core_guard() {
  if [ ! -x "$CORE_GUARD_SCRIPT" ]; then
    log "core guard script missing: $CORE_GUARD_SCRIPT"
    printf 'missing\n'
    return 1
  fi

  local out rc
  out="$("$CORE_GUARD_SCRIPT" --fix 2>/dev/null)" || rc=$?
  rc="${rc:-0}"
  case "$rc:$out" in
    0:changed)
      log "core guard healed unsafe config"
      printf 'changed\n'
      return 0
      ;;
    0:unchanged)
      printf 'unchanged\n'
      return 0
      ;;
    *)
      log "core guard failed: rc=${rc}"
      printf 'error\n'
      return 1
      ;;
  esac
}

restart_openclaw_after_guard() {
  if [ ! -x "$OPENCLAW_BOOT_SCRIPT" ]; then
    log "boot script missing for guarded restart: $OPENCLAW_BOOT_SCRIPT"
    return 1
  fi
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$OPENCLAW_BOOT_SCRIPT"
  sleep 10
  openclaw_healthy
}

enter_maintenance() {
  local reason="$1"
  local now deadline
  now="$(date +%s)"
  deadline="$((now + MAINTENANCE_TIMEOUT_SECONDS))"
  state_set ".maintenance.active=true | .maintenance.reason=\"${reason}\" | .maintenance.started_at=${now} | .maintenance.deadline_at=${deadline}"
  log "maintenance start: ${reason}, deadline=${deadline}"
  send_telegram "🛠️ Watchdog: 進入更新握手模式（${reason}），${MAINTENANCE_TIMEOUT_SECONDS} 秒內允許 OpenClaw 失聯。"
}

finish_maintenance() {
  local reason="${1:-manual}"
  local guard_result
  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    log "maintenance finish: config healed, restarting openclaw before ack"
    restart_openclaw_after_guard || true
  fi
  if ! openclaw_healthy; then
    log "maintenance finish rejected: openclaw unhealthy"
    send_telegram "❌ Watchdog: 更新成功握手被拒絕，OpenClaw 健康檢查未通過，啟動救援回滾。"
    state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
    trigger_rescue "maintenance-finish-unhealthy"
    return 1
  fi
  refresh_critical_manifest
  state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
  log "maintenance finished: ${reason}"
  send_telegram "✅ Watchdog: 收到更新成功握手（${reason}），恢復正常監控。"
}

openclaw_healthy() {
  if ! pgrep -f "openclaw gateway" >/dev/null 2>&1 \
    && ! pgrep -f "openclaw-gateway" >/dev/null 2>&1 \
    && ! pgrep -x openclaw >/dev/null 2>&1; then
    return 1
  fi
  python - "$OPENCLAW_PORT" <<'PY'
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
  [ $? -eq 0 ] || return 1
  return 0
}

heartbeat_fresh() {
  local now hb_ts
  [ -f "$HEARTBEAT_FILE" ] || return 1
  hb_ts="$(jq -r '.ts // 0' "$HEARTBEAT_FILE" 2>/dev/null || echo 0)"
  if ! printf '%s' "$hb_ts" | grep -Eq '^[0-9]+$'; then
    return 1
  fi
  now="$(date +%s)"
  [ "$((now - hb_ts))" -le "$HANDSHAKE_STALE_SECONDS" ]
}

perform_watchdog_handshake() {
  local now resp ok fail_count reason
  now="$(date +%s)"
  state_set ".handshake.last_attempt_ts=${now}"

  if ! heartbeat_fresh; then
    reason="heartbeat-stale"
    fail_count="$(state_get '.handshake.consecutive_failures // 0')"
    fail_count="$((fail_count + 1))"
    state_set ".handshake.last_fail_ts=${now} | .handshake.consecutive_failures=${fail_count} | .handshake.last_reason=\"${reason}\""
    log "watchdog handshake failed: ${reason} (${fail_count}/${HANDSHAKE_FAIL_THRESHOLD})"
    return 1
  fi

  if command -v timeout >/dev/null 2>&1; then
    resp="$(timeout "$HANDSHAKE_TIMEOUT_SECONDS" openclaw health --json --timeout 12000 2>/dev/null || true)"
  else
    resp="$(openclaw health --json --timeout 12000 2>/dev/null || true)"
  fi
  ok="$(printf '%s' "$resp" | jq -r '.ok // false' 2>/dev/null || echo false)"
  if [ "$ok" != "true" ]; then
    reason="gateway-health-failed"
    fail_count="$(state_get '.handshake.consecutive_failures // 0')"
    fail_count="$((fail_count + 1))"
    state_set ".handshake.last_fail_ts=${now} | .handshake.consecutive_failures=${fail_count} | .handshake.last_reason=\"${reason}\""
    log "watchdog handshake failed: ${reason} (${fail_count}/${HANDSHAKE_FAIL_THRESHOLD})"
    return 1
  fi

  state_set ".handshake.last_ok_ts=${now} | .handshake.consecutive_failures=0 | .handshake.last_reason=\"\""
  return 0
}

resolve_stable_tag() {
  git -C "$REPO_DIR" fetch --all --tags --prune >/dev/null 2>&1 || true
  git -C "$REPO_DIR" tag -l '穩定版*' --sort=-creatordate | head -n1
}

config_looks_complete() {
  local cfg="$1"
  [ -f "$cfg" ] || return 1
  jq -e '
    ((keys | length) >= 6)
    and ((.gateway.port | tonumber?) != null)
    and ((.channels.telegram.enabled // false) == true)
    and (((.channels.telegram.allowFrom // []) | length) > 0)
    and ((.agents.defaults.model.primary // "") | length > 0)
    and ((.models.providers | type) == "object")
    and ((.models.providers | keys | length) > 0)
  ' "$cfg" >/dev/null 2>&1
}

rollback_and_rebuild() {
  local reason="$1"
  local stable_tag target cfg_path rescue_cfg_backup
  stable_tag="$(resolve_stable_tag)"
  target="${stable_tag:-origin/${REPO_BRANCH}}"
  cfg_path="$HOME_DIR/.openclaw/openclaw.json"
  rescue_cfg_backup=""

  log "rescue start: reason=${reason}, target=${target}"
  send_telegram "🚨 Watchdog 救援啟動：${reason}\n目標版本：${target}"

  if [ -f "$cfg_path" ]; then
    rescue_cfg_backup="$STATE_DIR/openclaw.json.pre-rescue.$(date +%Y%m%d-%H%M%S)"
    cp -f "$cfg_path" "$rescue_cfg_backup" >/dev/null 2>&1 || rescue_cfg_backup=""
  fi

  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux kill-session -t openclaw >/dev/null 2>&1 || true

  if [ ! -d "$REPO_DIR/.git" ]; then
    log "repo not found: $REPO_DIR"
    send_telegram "❌ Watchdog 救援失敗：找不到 repo ${REPO_DIR}"
    return 1
  fi

  git -C "$REPO_DIR" checkout "$REPO_BRANCH" >/dev/null 2>&1 || git -C "$REPO_DIR" checkout -B "$REPO_BRANCH" "origin/${REPO_BRANCH}" >/dev/null 2>&1
  git -C "$REPO_DIR" reset --hard "$target" >/dev/null 2>&1

  TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN" \
  TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID" \
  NVIDIA_API_KEY="$NVIDIA_API_KEY" \
  OPENCLAW_PORT="$OPENCLAW_PORT" \
  OPENCLAW_REBUILD_MODE="rescue" \
  OPENCLAW_REBUILD_PRESERVE_CONFIG=1 \
  OPENCLAW_REBUILD_PRESERVE_STATE=1 \
  OPENCLAW_REBUILD_SKIP_WATCHDOG=1 \
  bash "$REPO_DIR/scripts/termux-rebuild-openclaw.sh" >>"$LOG_FILE" 2>&1 || {
    log "rescue failed: rebuild script exited non-zero"
    send_telegram "❌ Watchdog 救援失敗：重建腳本執行失敗（${target}）"
    return 1
  }
  run_core_guard >/dev/null 2>&1 || true

  if ! config_looks_complete "$cfg_path"; then
    if [ -n "$rescue_cfg_backup" ] && [ -f "$rescue_cfg_backup" ] && jq -e . "$rescue_cfg_backup" >/dev/null 2>&1; then
      log "rescue detected oversimplified config; restoring pre-rescue config backup"
      cp -f "$rescue_cfg_backup" "$cfg_path"
      chmod 600 "$cfg_path" >/dev/null 2>&1 || true
      run_core_guard >/dev/null 2>&1 || true
      send_telegram "🛠️ Watchdog: 救援後偵測到精簡配置，已自動還原完整配置並套用安全修復。"
    else
      log "rescue detected oversimplified config but no valid backup"
      send_telegram "⚠️ Watchdog: 救援後配置疑似被精簡，且無可用備份，請人工檢查。"
    fi
  fi

  sleep 8
  if openclaw_healthy; then
    refresh_critical_manifest || true
    log "rescue success: ${target}"
    send_telegram "✅ Watchdog 救援成功：已回滾並重建到 ${target}"
    return 0
  fi

  log "rescue failed after rebuild: ${target}"
  send_telegram "❌ Watchdog 救援失敗：回滾重建後仍無法恢復（${target}）"
  return 1
}

trigger_rescue() {
  local reason="$1"
  local now last
  now="$(date +%s)"
  last="$(state_get '.last_rescue_ts // 0')"
  if [ "$((now - last))" -lt "$RESCUE_COOLDOWN_SECONDS" ]; then
    log "rescue skipped due to cooldown: ${reason}"
    return 0
  fi
  state_set ".last_rescue_ts=${now} | .last_rescue_reason=\"${reason}\""
  rollback_and_rebuild "$reason" || true
}

handle_command() {
  local text="$1"
  local normalized
  normalized="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    "/helpdog"|"/helpdog@"*)
      log "telegram command detected: /helpdog"
      trigger_rescue "telegram:/helpdog"
      ;;
    *"更新主系統"*|"/update_system"|"/updatesystem")
      log "telegram command detected: update-start"
      enter_maintenance "telegram:更新主系統"
      ;;
    *"更新成功"*|*"更新完成"*|"/update_ok"|"/update_done")
      log "telegram command detected: update-success"
      finish_maintenance "telegram:update-success"
      ;;
    "/dogstatus")
      local active reason deadline
      active="$(state_get '.maintenance.active')"
      reason="$(state_get '.maintenance.reason')"
      deadline="$(state_get '.maintenance.deadline_at')"
      send_telegram "🐶 Watchdog 狀態\nactive=${active}\nmaintenance_reason=${reason}\ndeadline=${deadline}"
      ;;
    *)
      ;;
  esac
}

poll_telegram_updates() {
  local poll_flag
  poll_flag="$(printf '%s' "$WATCHDOG_TELEGRAM_POLL_ENABLED" | tr '[:upper:]' '[:lower:]')"
  case "$poll_flag" in
    1|true|yes|on)
      ;;
    *)
      return 0
      ;;
  esac

  if [ -z "$WATCHDOG_TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_OWNER_ID" ]; then
    log "telegram polling disabled: missing WATCHDOG_TELEGRAM_BOT_TOKEN or TELEGRAM_OWNER_ID"
    WATCHDOG_TELEGRAM_POLL_ENABLED="0"
    return 0
  fi
  if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ "$WATCHDOG_TELEGRAM_BOT_TOKEN" = "$TELEGRAM_BOT_TOKEN" ]; then
    log "telegram polling disabled: watchdog token matches primary bot token"
    WATCHDOG_TELEGRAM_POLL_ENABLED="0"
    return 0
  fi

  local last_id offset resp ids id max_id
  last_id="$(state_get '.last_update_id // 0')"
  offset="$((last_id + 1))"
  resp="$(curl -fsS --max-time 40 "https://api.telegram.org/bot${WATCHDOG_TELEGRAM_BOT_TOKEN}/getUpdates?timeout=25&offset=${offset}" 2>/dev/null || true)"
  [ -z "$resp" ] && return 0
  if [ "$(printf '%s' "$resp" | jq -r '.ok // false')" != "true" ]; then
    return 0
  fi

  max_id="$last_id"
  ids="$(printf '%s' "$resp" | jq -r '.result[].update_id // empty')"
  for id in $ids; do
    [ "$id" -gt "$max_id" ] && max_id="$id"
    local chat_id text
    chat_id="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.chat.id // .edited_message.chat.id // empty)")"
    text="$(printf '%s' "$resp" | jq -r ".result[] | select(.update_id==${id}) | (.message.text // .edited_message.text // empty)")"
    [ -z "$chat_id" ] && continue
    [ -z "$text" ] && continue
    [ "$chat_id" != "$TELEGRAM_OWNER_ID" ] && continue
    handle_command "$text"
  done
  state_set ".last_update_id=${max_id}"
}

monitor_once() {
  local now active deadline last_monitor guard_result drift_path fail_count maintenance_started auto_close
  local last_handshake hs_fail_count hs_reason
  now="$(date +%s)"
  poll_telegram_updates

  active="$(state_get '.maintenance.active')"
  deadline="$(state_get '.maintenance.deadline_at // 0')"

  if [ "$active" = "true" ]; then
    maintenance_started="$(state_get '.maintenance.started_at // 0')"
    auto_close="$(printf '%s' "$MAINTENANCE_AUTO_CLOSE_IF_HEALTHY" | tr '[:upper:]' '[:lower:]')"
    case "$auto_close" in
      1|true|yes|on)
        if [ "$((now - maintenance_started))" -ge "$MAINTENANCE_AUTO_CLOSE_MIN_SECONDS" ] && openclaw_healthy; then
          log "maintenance auto-finish: openclaw healthy after ${MAINTENANCE_AUTO_CLOSE_MIN_SECONDS}s"
          finish_maintenance "auto-healthy"
          return 0
        fi
        ;;
      *) ;;
    esac

    if [ "$now" -gt "$deadline" ]; then
      if openclaw_healthy; then
        log "maintenance timeout reached but openclaw healthy; auto-finishing"
        finish_maintenance "timeout-healthy"
        return 0
      fi
      log "maintenance timeout reached"
      send_telegram "⚠️ Watchdog: 更新握手逾時，啟動自動回滾救援。"
      state_set '.maintenance.active=false | .maintenance.reason="" | .maintenance.started_at=0 | .maintenance.deadline_at=0'
      trigger_rescue "maintenance-timeout"
    fi
    return 0
  fi

  last_handshake="$(state_get '.handshake.last_attempt_ts // 0')"
  if [ "$((now - last_handshake))" -ge "$HANDSHAKE_INTERVAL_SECONDS" ]; then
    if perform_watchdog_handshake; then
      log "watchdog handshake ok"
    else
      hs_fail_count="$(state_get '.handshake.consecutive_failures // 0')"
      hs_reason="$(state_get '.handshake.last_reason // "unknown"')"
      send_telegram "⚠️ Watchdog 握手失敗：${hs_reason}（${hs_fail_count}/${HANDSHAKE_FAIL_THRESHOLD}）"
      if [ "$hs_fail_count" -ge "$HANDSHAKE_FAIL_THRESHOLD" ]; then
        send_telegram "🚨 Watchdog 握手連續失敗，啟動救援回滾。"
        trigger_rescue "handshake-failed"
        return 0
      fi
    fi
  fi

  maybe_run_full_selfcheck "$now"
  enforce_model_guard

  drift_path="$(critical_drift_detected 2>/dev/null || true)"
  if [ -n "$drift_path" ]; then
    if is_true_flag "$DRIFT_AUTO_BASELINE_IF_HEALTHY" && drift_auto_heal_allowed_path "$drift_path" && openclaw_healthy; then
      log "critical drift auto-baseline: ${drift_path}"
      refresh_critical_manifest || true
      send_telegram "🩹 Watchdog: 偵測到受控腳本更新（${drift_path}），OpenClaw 健康，已自動更新 baseline，不回滾。"
      return 0
    fi
    send_telegram "🚨 Watchdog: 偵測到底層檔案漂移（${drift_path}），啟動救援回滾。"
    trigger_rescue "critical-drift"
    return 0
  fi

  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    send_telegram "🩹 Watchdog: 偵測到危險配置已自動修復，先進入觀察模式，不立即回滾。"
    state_set ".started_at=${now} | .last_monitor_ts=${now} | .consecutive_health_failures=0"
    log "guard-heal observed; grace window reset without forced restart"
    return 0
  fi

  last_monitor="$(state_get '.last_monitor_ts // 0')"
  local started_at
  started_at="$(state_get '.started_at // 0')"
  if [ "$((now - started_at))" -lt "$STARTUP_GRACE_SECONDS" ]; then
    return 0
  fi
  if [ "$((now - last_monitor))" -lt "$MONITOR_INTERVAL_SECONDS" ]; then
    return 0
  fi
  state_set ".last_monitor_ts=${now}"

  if ! openclaw_healthy; then
    fail_count="$(state_get '.consecutive_health_failures // 0')"
    fail_count="$((fail_count + 1))"
    state_set ".consecutive_health_failures=${fail_count}"
    log "health check failed (consecutive=${fail_count}/${HEALTHCHECK_FAIL_THRESHOLD})"
    if [ "$fail_count" -lt "$HEALTHCHECK_FAIL_THRESHOLD" ]; then
      send_telegram "⚠️ Watchdog: 健康檢查失敗（${fail_count}/${HEALTHCHECK_FAIL_THRESHOLD}），先嘗試重啟，不立即回滾。"
      if restart_openclaw_after_guard; then
        now="$(date +%s)"
        state_set ".started_at=${now} | .last_monitor_ts=${now} | .consecutive_health_failures=0"
        log "health self-restart success; grace reset"
      else
        log "health self-restart failed; awaiting next monitor before rescue"
      fi
    else
      trigger_rescue "healthcheck-failed"
      state_set '.consecutive_health_failures=0'
    fi
  else
    state_set '.consecutive_health_failures=0'
    log "health check ok"
  fi
}

run_daemon() {
  local existing now poll_mode guard_result
  state_init
  if [ -f "$PID_FILE" ]; then
    existing="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing" ] && kill -0 "$existing" >/dev/null 2>&1; then
      log "already running (pid=${existing})"
      exit 0
    fi
  fi
  echo "$$" >"$PID_FILE"
  trap 'rm -f "$PID_FILE"' EXIT

  now="$(date +%s)"
  state_set ".started_at=${now} | .last_monitor_ts=${now} | .consecutive_health_failures=0 | .handshake.last_attempt_ts=${now} | .handshake.consecutive_failures=0 | .handshake.last_reason=\"\""
  guard_result="$(run_core_guard 2>/dev/null || true)"
  if [ "$guard_result" = "changed" ]; then
    send_telegram "🩹 Watchdog: 開機時修復了 OpenClaw 危險配置。"
  fi
  run_full_selfcheck "$now" "auto" >/dev/null 2>&1 || true
  enforce_model_guard
  refresh_critical_manifest || true
  poll_mode="disabled"
  case "$(printf '%s' "$WATCHDOG_TELEGRAM_POLL_ENABLED" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) poll_mode="enabled" ;;
  esac
  log "started v${WATCHDOG_VERSION}, poll=${POLL_INTERVAL_SECONDS}s, monitor=${MONITOR_INTERVAL_SECONDS}s, telegram_command_poll=${poll_mode}"
  send_telegram "🐶 Watchdog 已啟動（v${WATCHDOG_VERSION}）"
  while true; do
    monitor_once
    sleep "$POLL_INTERVAL_SECONDS"
  done
}

print_status() {
  state_init
  jq . "$STATE_FILE"
}

usage() {
  cat <<'EOF'
Usage:
  termux-openclaw-watchdog.sh --daemon
  termux-openclaw-watchdog.sh --once
  termux-openclaw-watchdog.sh --status
  termux-openclaw-watchdog.sh --baseline-refresh
  termux-openclaw-watchdog.sh --selfcheck
  termux-openclaw-watchdog.sh --rescue <reason>
  termux-openclaw-watchdog.sh --maintenance-start <reason>
  termux-openclaw-watchdog.sh --maintenance-ok <reason>
EOF
}

case "${1:---daemon}" in
  --daemon)
    run_daemon
    ;;
  --once)
    state_init
    monitor_once
    ;;
  --status)
    print_status
    ;;
  --baseline-refresh)
    refresh_critical_manifest
    ;;
  --selfcheck)
    state_init
    run_full_selfcheck "$(date +%s)" "force" || true
    ;;
  --rescue)
    state_init
    trigger_rescue "${2:-manual-rescue}"
    ;;
  --maintenance-start)
    state_init
    enter_maintenance "${2:-manual-start}"
    ;;
  --maintenance-ok)
    state_init
    finish_maintenance "${2:-manual-ok}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
