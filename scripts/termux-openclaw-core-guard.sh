#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
CFG_FILE="${OPENCLAW_CONFIG_PATH:-$HOME_DIR/.openclaw/openclaw.json}"
LOG_FILE="${OPENCLAW_CORE_GUARD_LOG:-$HOME_DIR/openclaw-logs/core-guard.log}"
EMBEDDING_MODEL_REF="${OPENCLAW_MEMORY_EMBEDDING_MODEL:-hf:ggml-org/embeddinggemma-300m-qat-q8_0-GGUF/embeddinggemma-300m-qat-Q8_0.gguf}"
EMBEDDING_MODEL_CACHE_DIR="${OPENCLAW_MEMORY_MODEL_CACHE_DIR:-$HOME_DIR/.cache/openclaw/models}"

mkdir -p "$(dirname "$CFG_FILE")" "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [openclaw-core-guard] %s\n' "$ts" "$*" >>"$LOG_FILE"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing command: $1"
    exit 1
  }
}

random_token() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

json_sha() {
  if [ ! -f "$CFG_FILE" ]; then
    printf 'missing'
    return 0
  fi
  sha256sum "$CFG_FILE" | awk '{print $1}'
}

tmp_sha() {
  local file="$1"
  sha256sum "$file" | awk '{print $1}'
}

is_safe() {
  [ -f "$CFG_FILE" ] || return 1
  jq -e '
    (.gateway // {} | .bind // "lan") as $bind
    | (.gateway // {} | .auth // {} | .mode // "none") as $mode
    | (.gateway // {} | .auth // {} | .token // "") as $token
    | (.gateway // {} | .auth // {} | .password // "") as $password
    | (.gateway // {} | .controlUi // {} | .dangerouslyAllowHostHeaderOriginFallback // false) as $uiFallback
    | (.gateway // {} | .port) as $port
    | (.agents // {} | .defaults // {} | .memorySearch // {} | .provider // "") as $memProvider
    | (.agents // {} | .defaults // {} | .memorySearch // {} | .local // {} | .modelPath // "") as $memModelPath
    | (.agents // {} | .defaults // {} | .memorySearch // {} | .local // {} | .modelCacheDir // "") as $memModelCacheDir
    | (($port | tonumber?) != null)
    and (
      ($bind != "lan")
      or (
        ($uiFallback == true)
        and (
          ($mode == "token" and ($token | length) > 0)
          or ($mode == "password" and ($password | length) > 0)
        )
      )
    )
    and ($memProvider == "local")
    and (($memModelPath | length) > 0)
    and (($memModelCacheDir | length) > 0)
  ' "$CFG_FILE" >/dev/null 2>&1
}

fix_config() {
  local before after token fallback_port backup tmp
  if is_safe; then
    log "config checked; no changes required"
    printf 'unchanged\n'
    return 0
  fi

  before="$(json_sha)"
  fallback_port="${OPENCLAW_PORT:-18789}"
  token="${OPENCLAW_GATEWAY_TOKEN:-}"
  if [ -z "$token" ] && [ -f "$CFG_FILE" ]; then
    token="$(jq -r '.gateway.auth.token // empty' "$CFG_FILE" 2>/dev/null || true)"
  fi
  if [ -z "$token" ]; then
    token="$(random_token)"
  fi

  tmp="$(mktemp)"
  jq \
    --arg token "$token" \
    --argjson fallbackPort "$fallback_port" \
    --arg embeddingModel "$EMBEDDING_MODEL_REF" \
    --arg embeddingCacheDir "$EMBEDDING_MODEL_CACHE_DIR" \
    '
      .gateway = (.gateway // {}) |
      .gateway.mode = (.gateway.mode // "local") |
      .gateway.bind = (.gateway.bind // "lan") |
      .gateway.port = ((.gateway.port | tonumber?) // $fallbackPort) |
      .gateway.auth = (.gateway.auth // {}) |
      .gateway.controlUi = (.gateway.controlUi // {}) |
      if .gateway.bind == "lan" then
        .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true |
        if ((.gateway.auth.mode // "none") == "none") or ((.gateway.auth.mode // "") == "") then
          .gateway.auth.mode = "token" |
          .gateway.auth.token = $token
        elif ((.gateway.auth.mode // "") == "token") and ((.gateway.auth.token // "") == "") then
          .gateway.auth.token = $token
        elif ((.gateway.auth.mode // "") == "password") and ((.gateway.auth.password // "") == "") then
          .gateway.auth.mode = "token" |
          .gateway.auth.token = $token
        else
          .
        end
      else
        .
      end |
      .agents = (.agents // {}) |
      .agents.defaults = (.agents.defaults // {}) |
      .agents.defaults.memorySearch = (.agents.defaults.memorySearch // {}) |
      .agents.defaults.memorySearch.provider = "local" |
      .agents.defaults.memorySearch.fallback = "none" |
      .agents.defaults.memorySearch.local = (.agents.defaults.memorySearch.local // {}) |
      .agents.defaults.memorySearch.local.modelPath = $embeddingModel |
      .agents.defaults.memorySearch.local.modelCacheDir = $embeddingCacheDir |
      del(.agents.defaults.memorySearch.remote)
    ' "$CFG_FILE" >"$tmp"
  after="$(tmp_sha "$tmp")"
  if [ "$before" != "$after" ]; then
    backup="$CFG_FILE.bak.core-guard.$(date +%Y%m%d-%H%M%S)"
    cp -f "$CFG_FILE" "$backup" 2>/dev/null || true
    mv "$tmp" "$CFG_FILE"
    chmod 600 "$CFG_FILE"
    log "config healed (sha ${before} -> ${after}, backup=$(basename "$backup"))"
    printf 'changed\n'
    return 0
  fi
  rm -f "$tmp"
  log "config checked; no changes required"
  printf 'unchanged\n'
  return 0
}

usage() {
  cat <<'EOF'
Usage:
  termux-openclaw-core-guard.sh --check
  termux-openclaw-core-guard.sh --fix
EOF
}

main() {
  require_cmd jq
  case "${1:---check}" in
    --check)
      if is_safe; then
        log "safety check: ok"
        printf 'safe\n'
        exit 0
      fi
      log "safety check: failed"
      printf 'unsafe\n'
      exit 1
      ;;
    --fix)
      if ! [ -f "$CFG_FILE" ]; then
        log "config file missing: $CFG_FILE"
        exit 1
      fi
      fix_config
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
