#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

log() {
  printf "[termux-rebuild] %s\n" "$*"
}

is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing command: $1"
    exit 1
  }
}

cleanup_block() {
  local file="$1"
  local begin="$2"
  local end="$3"
  [ -f "$file" ] || return 0
  sed -i "/${begin}/,/${end}/d" "$file"
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

if [ "${PREFIX:-}" != "/data/data/com.termux/files/usr" ]; then
  log "this script must run inside Termux"
  exit 1
fi

require_cmd pkg

export DEBIAN_FRONTEND=noninteractive
export TMPDIR="${TMPDIR:-$HOME/tmp}"
mkdir -p "$TMPDIR"
SKIP_WATCHDOG="${OPENCLAW_REBUILD_SKIP_WATCHDOG:-0}"
OPENCLAW_WATCHDOG_ENABLED="${OPENCLAW_WATCHDOG_ENABLED:-0}"
if ! is_true_flag "$OPENCLAW_WATCHDOG_ENABLED"; then
  SKIP_WATCHDOG="1"
fi
SKIP_NANOBOT="${OPENCLAW_REBUILD_SKIP_NANOBOT:-1}"
REBUILD_MODE="${OPENCLAW_REBUILD_MODE:-standard}"
PRESERVE_CONFIG="${OPENCLAW_REBUILD_PRESERVE_CONFIG:-1}"
PRESERVE_STATE="${OPENCLAW_REBUILD_PRESERVE_STATE:-1}"
REBUILD_BACKUP_DIR="$HOME/.openclaw-rebuild-backup"
PREV_CFG_PATH="$HOME/.openclaw/openclaw.json"
PREV_ENV_PATH="$HOME/.openclaw-watchdog.env"
PREV_CFG_BACKUP=""
PREV_ENV_BACKUP=""
EMBEDDING_MODEL_REF="${OPENCLAW_MEMORY_EMBEDDING_MODEL:-}"
EMBEDDING_MODEL_CACHE_DIR="${OPENCLAW_MEMORY_MODEL_CACHE_DIR:-$HOME/.cache/openclaw/models}"
EMBEDDING_WARMUP_ON_REBUILD="${EMBEDDING_WARMUP_ON_REBUILD:-1}"
OPENCLAW_COMPACTION_RESERVE_TOKENS="${OPENCLAW_COMPACTION_RESERVE_TOKENS:-20000}"
OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS="${OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS:-4000}"
OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT="${OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT:-Write any lasting notes, rules, facts or preferences to memory/YYYY-MM-DD.md or MEMORY.md. Reply NO_REPLY if nothing to store.}"
OPENCLAW_NPM_TARGET="${OPENCLAW_NPM_TARGET:-latest}"
OPENCLAW_ALLOW_DEV="${OPENCLAW_ALLOW_DEV:-0}"

log "stopping old claw processes"
pkill -9 -x zeroclaw >/dev/null 2>&1 || true
pkill -9 -f "zeroclaw daemon" >/dev/null 2>&1 || true
pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
if [ "$SKIP_NANOBOT" != "1" ]; then
  pkill -9 -f "termux-rescue-nanobot.sh" >/dev/null 2>&1 || true
fi
pkill -9 -f "termux-openclaw-watchdog.sh" >/dev/null 2>&1 || true
pkill -9 -x openclaw >/dev/null 2>&1 || true
tmux kill-session -t openclaw >/dev/null 2>&1 || true
if [ "$SKIP_NANOBOT" != "1" ]; then
  tmux kill-session -t openclaw-nanobot >/dev/null 2>&1 || true
fi
tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true

mkdir -p "$REBUILD_BACKUP_DIR"
if [ -f "$PREV_CFG_PATH" ]; then
  PREV_CFG_BACKUP="$REBUILD_BACKUP_DIR/openclaw.json.pre-rebuild.$(date +%Y%m%d-%H%M%S)"
  cp -f "$PREV_CFG_PATH" "$PREV_CFG_BACKUP" >/dev/null 2>&1 || PREV_CFG_BACKUP=""
fi
if [ -f "$PREV_ENV_PATH" ]; then
  PREV_ENV_BACKUP="$REBUILD_BACKUP_DIR/openclaw-watchdog.env.pre-rebuild.$(date +%Y%m%d-%H%M%S)"
  cp -f "$PREV_ENV_PATH" "$PREV_ENV_BACKUP" >/dev/null 2>&1 || PREV_ENV_BACKUP=""
fi

log "removing zeroclaw and old openclaw data (mode=$REBUILD_MODE preserve_config=$PRESERVE_CONFIG preserve_state=$PRESERVE_STATE)"
rm -f "$PREFIX/bin/zeroclaw" "$HOME/.cargo/bin/zeroclaw" >/dev/null 2>&1 || true
rm -rf \
  "$HOME/.zeroclaw" \
  "$HOME/zeroclaw" \
  "$HOME/openclaw" \
  "$HOME/openclaw-install.sh" \
  "$HOME/.zeroclaw_daemon.log" \
  "$HOME/.openclaw_daemon.log"
if is_true_flag "$PRESERVE_STATE"; then
  mkdir -p "$HOME/.openclaw" "$HOME/openclaw-logs"
else
  rm -rf "$HOME/.openclaw" "$HOME/openclaw-logs"
fi
if [ "$SKIP_WATCHDOG" != "1" ]; then
  if ! is_true_flag "$PRESERVE_STATE"; then
    rm -rf "$HOME/.openclaw-watchdog"
  fi
else
  rm -f "$HOME/.openclaw-watchdog.env" >/dev/null 2>&1 || true
fi

mkdir -p "$HOME/.termux/boot"
find "$HOME/.termux/boot" -maxdepth 1 -type f \( -iname "*zeroclaw*" -o -iname "*openclaw*" -o -iname "*claw*" \) -delete 2>/dev/null || true

if [ -f "$HOME/.termux/crontab" ]; then
  grep -Eiv "zeroclaw|openclaw|DINO_OPENCLAW|claw" "$HOME/.termux/crontab" >"$HOME/.termux/crontab.clean" || true
  mv "$HOME/.termux/crontab.clean" "$HOME/.termux/crontab"
fi

cleanup_block "$HOME/.bashrc" "# --- OpenClaw Start ---" "# --- OpenClaw End ---"
cleanup_block "$HOME/.bashrc" "# --- OPENCLAW_TERMUX_RUNTIME_BEGIN ---" "# --- OPENCLAW_TERMUX_RUNTIME_END ---"
cleanup_block "$HOME/.zshrc" "# --- OPENCLAW_TERMUX_RUNTIME_BEGIN ---" "# --- OPENCLAW_TERMUX_RUNTIME_END ---"
sed -i "/zeroclaw/d" "$HOME/.bashrc" "$HOME/.zshrc" 2>/dev/null || true

log "installing/updating dependencies"
pkg update -y
pkg upgrade -y
pkg install -y nodejs-lts git curl jq tmux openssh termux-api

mkdir -p "$HOME/.npm-global/bin"
npm config set prefix "$HOME/.npm-global" >/dev/null 2>&1 || true
export PATH="$HOME/.npm-global/bin:$PATH"

log "installing openclaw target build"
if [ "$OPENCLAW_NPM_TARGET" != "latest" ]; then
  npm install -g "openclaw@${OPENCLAW_NPM_TARGET}" --ignore-scripts --no-audit --no-fund
  OPENCLAW_CHANNEL="$OPENCLAW_NPM_TARGET"
elif is_true_flag "$OPENCLAW_ALLOW_DEV"; then
  if npm view openclaw@dev version >/dev/null 2>&1 && npm install -g openclaw@dev --ignore-scripts --no-audit --no-fund; then
    OPENCLAW_CHANNEL="dev"
  else
    log "openclaw@dev install failed; fallback to latest stable"
    npm install -g openclaw@latest --ignore-scripts --no-audit --no-fund
    OPENCLAW_CHANNEL="latest"
  fi
else
  npm install -g openclaw@latest --ignore-scripts --no-audit --no-fund
  OPENCLAW_CHANNEL="latest"
fi

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-}"
OPENCLAW_PORT="${OPENCLAW_PORT:-}"
OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-}"
NANOBOT_TELEGRAM_BOT_TOKEN="${NANOBOT_TELEGRAM_BOT_TOKEN:-}"
NANOBOT_MODEL="${NANOBOT_MODEL:-z-ai/glm4.7}"
NANOBOT_ENABLED="${NANOBOT_ENABLED:-0}"
OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$REPO_DIR}"
CORE_GUARD_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh"
OBSIDIAN_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-obsidian-integrate.sh"
UPDATE_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-main-system-update.sh"

if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ]; then
  TELEGRAM_BOT_TOKEN="$(jq -r '.channels.telegram.botToken // empty' "$PREV_CFG_BACKUP" 2>/dev/null || true)"
fi
if [ -z "$NVIDIA_API_KEY" ] && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ]; then
  NVIDIA_API_KEY="$(jq -r '.models.providers.nvidia.apiKey // empty' "$PREV_CFG_BACKUP" 2>/dev/null || true)"
fi
if [ -z "${TELEGRAM_OWNER_ID:-}" ] && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ]; then
  TELEGRAM_OWNER_ID="$(jq -r '.channels.telegram.allowFrom[0] // empty' "$PREV_CFG_BACKUP" 2>/dev/null || true)"
fi
if [ -z "${OPENCLAW_PORT:-}" ] && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ]; then
  OPENCLAW_PORT="$(jq -r '.gateway.port // empty' "$PREV_CFG_BACKUP" 2>/dev/null || true)"
fi
if [ -z "${OPENCLAW_GATEWAY_TOKEN:-}" ] && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ]; then
  OPENCLAW_GATEWAY_TOKEN="$(jq -r '.gateway.auth.token // empty' "$PREV_CFG_BACKUP" 2>/dev/null || true)"
fi
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-6002298888}"
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-$(date +%s | sha256sum | cut -c1-24)}"
if [ -n "$NANOBOT_TELEGRAM_BOT_TOKEN" ]; then
  NANOBOT_ENABLED="1"
fi

if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
  log "TELEGRAM_BOT_TOKEN is required"
  exit 1
fi
if [ -z "$NVIDIA_API_KEY" ]; then
  log "NVIDIA_API_KEY is required"
  exit 1
fi
if ! echo "$OPENCLAW_PORT" | grep -Eq "^[0-9]+$"; then
  log "OPENCLAW_PORT must be a number"
  exit 1
fi

mkdir -p "$HOME/.openclaw" "$HOME/openclaw-logs"

log "writing ~/.openclaw/openclaw.json (full restore mode)"
BASE_CFG_TMP="$(mktemp)"
FINAL_CFG_TMP="$(mktemp)"
jq -n \
  --arg gatewayToken "$OPENCLAW_GATEWAY_TOKEN" \
  --argjson gatewayPort "$OPENCLAW_PORT" \
  --arg telegramToken "$TELEGRAM_BOT_TOKEN" \
  --arg telegramOwner "$TELEGRAM_OWNER_ID" \
  --arg nvidiaKey "$NVIDIA_API_KEY" \
  --arg embeddingModel "$EMBEDDING_MODEL_REF" \
  --arg embeddingCacheDir "$EMBEDDING_MODEL_CACHE_DIR" \
  --argjson compactionReserve "$OPENCLAW_COMPACTION_RESERVE_TOKENS" \
  --argjson compactionSoft "$OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS" \
  --arg compactionPrompt "$OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT" \
  '{
    gateway: {
      mode: "local",
      bind: "lan",
      port: $gatewayPort,
      auth: { mode: "token", token: $gatewayToken },
      controlUi: {
        dangerouslyAllowHostHeaderOriginFallback: true
      }
    },
    models: {
      providers: {
        nvidia: {
          baseUrl: "https://integrate.api.nvidia.com/v1",
          api: "openai-completions",
          apiKey: $nvidiaKey,
          models: [
            {
              id: "z-ai/glm4.7",
              name: "GLM 4.7 (NVIDIA)",
              reasoning: false,
              input: ["text"],
              contextWindow: 131072,
              maxTokens: 8192
            },
            {
              id: "moonshotai/kimi-k2.5",
              name: "Kimi K2.5 (NVIDIA)",
              reasoning: false,
              input: ["text"],
              contextWindow: 131072,
              maxTokens: 8192
            },
            {
              id: "openai/gpt-oss-120b",
              name: "GPT-OSS 120B (NVIDIA)",
              reasoning: false,
              input: ["text"],
              contextWindow: 131072,
              maxTokens: 8192
            },
            {
              id: "nvidia/llama-3.1-nemotron-70b-instruct",
              name: "NVIDIA Llama 3.1 Nemotron 70B Instruct",
              reasoning: false,
              input: ["text"],
              contextWindow: 131072,
              maxTokens: 4096
            }
          ]
        }
      }
    },
    agents: {
      defaults: {
        model: {
          primary: "nvidia/z-ai/glm4.7",
          fallbacks: [
            "nvidia/moonshotai/kimi-k2.5",
            "nvidia/openai/gpt-oss-120b",
            "nvidia/nvidia/llama-3.1-nemotron-70b-instruct"
          ]
        },
        memorySearch: {
          provider: "local",
          fallback: "none",
          store: {
            vector: {
              enabled: false
            }
          },
          query: {
            hybrid: {
              enabled: true,
              vectorWeight: 0,
              textWeight: 1
            }
          },
          local: {
            modelCacheDir: $embeddingCacheDir
          }
        },
        compaction: {
          mode: "safeguard",
          reserveTokensFloor: $compactionReserve,
          memoryFlush: {
            enabled: true,
            softThresholdTokens: $compactionSoft,
            prompt: $compactionPrompt
          }
        }
      }
    },
    channels: {
      telegram: {
        enabled: true,
        botToken: $telegramToken,
        dmPolicy: "allowlist",
        allowFrom: [$telegramOwner],
        groupPolicy: "disabled",
        groups: {}
      }
    }
  }' >"$BASE_CFG_TMP"

if is_true_flag "$PRESERVE_CONFIG" && [ -n "$PREV_CFG_BACKUP" ] && [ -f "$PREV_CFG_BACKUP" ] && jq -e . "$PREV_CFG_BACKUP" >/dev/null 2>&1; then
  log "merging preserved runtime config into rebuilt base config"
  jq -s \
    --arg gatewayToken "$OPENCLAW_GATEWAY_TOKEN" \
    --argjson gatewayPort "$OPENCLAW_PORT" \
    --arg telegramToken "$TELEGRAM_BOT_TOKEN" \
    --arg telegramOwner "$TELEGRAM_OWNER_ID" \
    --arg nvidiaKey "$NVIDIA_API_KEY" \
    --arg embeddingModel "$EMBEDDING_MODEL_REF" \
    --arg embeddingCacheDir "$EMBEDDING_MODEL_CACHE_DIR" \
    --argjson compactionReserve "$OPENCLAW_COMPACTION_RESERVE_TOKENS" \
    --argjson compactionSoft "$OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS" \
    --arg compactionPrompt "$OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT" \
    '
      .[0] * .[1]
      | .gateway = (.gateway // {})
      | .gateway.mode = (.gateway.mode // "local")
      | .gateway.bind = (.gateway.bind // "lan")
      | .gateway.port = $gatewayPort
      | .gateway.auth = (.gateway.auth // {})
      | .gateway.controlUi = (.gateway.controlUi // {})
      | .gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true
      | if ((.gateway.auth.mode // "none") == "none") or ((.gateway.auth.mode // "") == "") then
          .gateway.auth.mode = "token" | .gateway.auth.token = $gatewayToken
        elif (.gateway.auth.mode == "token") and ((.gateway.auth.token // "") == "") then
          .gateway.auth.token = $gatewayToken
        else
          .
        end
      | .channels = (.channels // {})
      | .channels.telegram = (.channels.telegram // {})
      | .channels.telegram.enabled = true
      | .channels.telegram.botToken = (if ($telegramToken | length) > 0 then $telegramToken else (.channels.telegram.botToken // "") end)
      | .channels.telegram.dmPolicy = "allowlist"
      | .channels.telegram.allowFrom = [$telegramOwner]
      | .channels.telegram.groupPolicy = "disabled"
      | .channels.telegram.groups = (.channels.telegram.groups // {})
      | .plugins = (.plugins // {})
      | .plugins.entries = (.plugins.entries // {})
      | .plugins.entries.telegram = (.plugins.entries.telegram // {})
      | .plugins.entries.telegram.enabled = true
      | .models = (.models // {})
      | .models.providers = (.models.providers // {})
      | .models.providers.nvidia = (.models.providers.nvidia // {})
      | .models.providers.nvidia.api = (.models.providers.nvidia.api // "openai-completions")
      | .models.providers.nvidia.baseUrl = (.models.providers.nvidia.baseUrl // "https://integrate.api.nvidia.com/v1")
      | if ($nvidiaKey | length) > 0 then .models.providers.nvidia.apiKey = $nvidiaKey else . end
      | .agents = (.agents // {})
      | .agents.defaults = (.agents.defaults // {})
      | .agents.defaults.model = (.agents.defaults.model // {})
      | if ((.agents.defaults.model.primary // "") | length) == 0 then
          .agents.defaults.model.primary = "nvidia/z-ai/glm4.7"
        else
          .
        end
      | if ((.agents.defaults.model.fallbacks // []) | length) == 0 then
          .agents.defaults.model.fallbacks = [
            "nvidia/moonshotai/kimi-k2.5",
            "nvidia/openai/gpt-oss-120b",
            "nvidia/nvidia/llama-3.1-nemotron-70b-instruct"
          ]
        else
          .
        end
      | .agents.defaults.memorySearch = (.agents.defaults.memorySearch // {})
      | .agents.defaults.memorySearch.provider = "local"
      | .agents.defaults.memorySearch.fallback = "none"
      | .agents.defaults.memorySearch.local = (.agents.defaults.memorySearch.local // {})
      | if ($embeddingModel | length) > 0 then
          .agents.defaults.memorySearch.local.modelPath = $embeddingModel
        else
          del(.agents.defaults.memorySearch.local.modelPath)
        end
      | .agents.defaults.memorySearch.local.modelCacheDir = $embeddingCacheDir
      | .agents.defaults.memorySearch.store = (.agents.defaults.memorySearch.store // {})
      | .agents.defaults.memorySearch.store.vector = (.agents.defaults.memorySearch.store.vector // {})
      | .agents.defaults.memorySearch.store.vector.enabled = false
      | .agents.defaults.memorySearch.query = (.agents.defaults.memorySearch.query // {})
      | .agents.defaults.memorySearch.query.hybrid = (.agents.defaults.memorySearch.query.hybrid // {})
      | .agents.defaults.memorySearch.query.hybrid.enabled = true
      | .agents.defaults.memorySearch.query.hybrid.vectorWeight = 0
      | .agents.defaults.memorySearch.query.hybrid.textWeight = 1
      | .agents.defaults.compaction = (.agents.defaults.compaction // {})
      | .agents.defaults.compaction.mode = "safeguard"
      | .agents.defaults.compaction.reserveTokensFloor = ((.agents.defaults.compaction.reserveTokensFloor | tonumber?) // $compactionReserve)
      | .agents.defaults.compaction.memoryFlush = (.agents.defaults.compaction.memoryFlush // {})
      | .agents.defaults.compaction.memoryFlush.enabled = true
      | .agents.defaults.compaction.memoryFlush.softThresholdTokens = ((.agents.defaults.compaction.memoryFlush.softThresholdTokens | tonumber?) // $compactionSoft)
      | .agents.defaults.compaction.memoryFlush.prompt = (
          if ((.agents.defaults.compaction.memoryFlush.prompt // "") | length) > 0
          then .agents.defaults.compaction.memoryFlush.prompt
          else $compactionPrompt
          end
        )
      | del(.agents.defaults.compaction.keepRecentTokens)
      | del(.agents.defaults.compaction.memoryFlush.hardThresholdTokens)
      | del(.channels.telegram.dmToken)
      | del(.models.providers.google.api)
      | del(.agents.defaults.memorySearch.remote)
    ' "$BASE_CFG_TMP" "$PREV_CFG_BACKUP" >"$FINAL_CFG_TMP"
else
  cp -f "$BASE_CFG_TMP" "$FINAL_CFG_TMP"
fi

if [ -n "$EMBEDDING_MODEL_REF" ]; then
  jq --arg embeddingModel "$EMBEDDING_MODEL_REF" '
    .agents.defaults.memorySearch.local = (.agents.defaults.memorySearch.local // {}) |
    .agents.defaults.memorySearch.local.modelPath = $embeddingModel
  ' "$FINAL_CFG_TMP" >"$FINAL_CFG_TMP.with-model"
  mv "$FINAL_CFG_TMP.with-model" "$FINAL_CFG_TMP"
fi

jq --argjson compactionReserve "$OPENCLAW_COMPACTION_RESERVE_TOKENS" \
   --argjson compactionSoft "$OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS" \
   --arg compactionPrompt "$OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT" '
  .agents = (.agents // {}) |
  .agents.defaults = (.agents.defaults // {}) |
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
  del(.models.providers.google.api)
' "$FINAL_CFG_TMP" >"$FINAL_CFG_TMP.clean"
mv "$FINAL_CFG_TMP.clean" "$FINAL_CFG_TMP"

if [ -f "$HOME/.openclaw/openclaw.json" ]; then
  cp -f "$HOME/.openclaw/openclaw.json" "$HOME/.openclaw/openclaw.json.bak.rebuild.$(date +%Y%m%d-%H%M%S)" >/dev/null 2>&1 || true
fi
mv "$FINAL_CFG_TMP" "$HOME/.openclaw/openclaw.json"
chmod 600 "$HOME/.openclaw/openclaw.json"
rm -f "$BASE_CFG_TMP"

if [ "$OPENCLAW_TERMUX_REPO_DIR" != "$HOME/DINO_OPENCLAW" ]; then
  ln -sfn "$OPENCLAW_TERMUX_REPO_DIR" "$HOME/DINO_OPENCLAW"
fi

cleanup_block "$HOME/.bashrc" "# --- OPENCLAW_TERMUX_RUNTIME_BEGIN ---" "# --- OPENCLAW_TERMUX_RUNTIME_END ---"
cat >>"$HOME/.bashrc" <<'EOF'
# --- OPENCLAW_TERMUX_RUNTIME_BEGIN ---
export PATH="$HOME/.npm-global/bin:$PATH"
export TMPDIR="$HOME/tmp"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
alias ocr='pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true; pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true; pkill -x openclaw >/dev/null 2>&1 || true; tmux kill-session -t openclaw >/dev/null 2>&1 || true; tmux new -d -s openclaw "$HOME/.termux/boot/openclaw-launch.sh"'
alias oclog='tmux attach -t openclaw'
alias ockill='pkill -9 -f "openclaw" >/dev/null 2>&1 || true; tmux kill-session -t openclaw >/dev/null 2>&1 || true'
alias obsidian_status='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-obsidian-integrate.sh" --status'
alias obsidian_link='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-obsidian-integrate.sh" --link'
alias doglog='tmux attach -t openclaw-watchdog'
alias dogstatus='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-watchdog.sh" --status'
alias dogbaseline='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-watchdog.sh" --baseline-refresh'
alias dogrescue='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-watchdog.sh" --rescue manual'
alias dogmaint_start='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-watchdog.sh" --maintenance-start manual'
alias dogmaint_ok='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-watchdog.sh" --maintenance-ok manual'
alias nanolog='tmux attach -t openclaw-nanobot'
alias nanostatus='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-rescue-nanobot.sh" --status'
alias nanorescue='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-rescue-nanobot.sh" --rescue manual'
alias coreguard='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-core-guard.sh" --fix'
alias occfg='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-safe-config-edit.sh"'
alias ocupdate='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-main-system-update.sh"'
alias ocupdate_force='FORCE_NPM_UPDATE=1 bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-main-system-update.sh"'
# --- OPENCLAW_TERMUX_RUNTIME_END ---
EOF

log "writing Termux boot auto-start scripts"
mkdir -p "$HOME/.termux/boot"
cat >"$HOME/.termux/boot/openclaw-launch.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -eu
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
export TMPDIR="$HOME/tmp"
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp" "$HOME/.openclaw-watchdog"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
if [ -x "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh" ]; then
  "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh" --fix >>"$HOME/openclaw-logs/core-guard.log" 2>&1 || true
fi
heartbeat_file="$HOME/.openclaw-watchdog/openclaw-heartbeat.json"

openclaw gateway --allow-unconfigured >>"$HOME/openclaw-logs/gateway.log" 2>&1 &
gateway_pid="$!"

while kill -0 "$gateway_pid" >/dev/null 2>&1; do
  ts="$(date +%s)"
  tmp="${heartbeat_file}.tmp"
  printf '{"ts":%s,"pid":%s,"source":"openclaw-launch"}\n' "$ts" "$gateway_pid" >"$tmp" 2>/dev/null || true
  mv -f "$tmp" "$heartbeat_file" 2>/dev/null || true
  sleep 30
done

wait "$gateway_pid"
EOF
if [ "$SKIP_WATCHDOG" != "1" ]; then
cat >"$HOME/.termux/boot/openclaw-watchdog-launch.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -eu
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
export TMPDIR="$HOME/tmp"
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp"
export OPENCLAW_WATCHDOG_ENV="$HOME/.openclaw-watchdog.env"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
exec "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-watchdog.sh" --daemon >>"$HOME/openclaw-logs/watchdog.log" 2>&1
EOF
else
  rm -f "$HOME/.termux/boot/openclaw-watchdog-launch.sh" >/dev/null 2>&1 || true
fi
cat >"$HOME/.termux/boot/openclaw-nanobot-launch.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -eu
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
export TMPDIR="$HOME/tmp"
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
exec "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-rescue-nanobot.sh" --daemon >>"$HOME/openclaw-logs/nanobot.log" 2>&1
EOF
cat >"$HOME/.termux/boot/start-openclaw.sh" <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
set -eu
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
export TMPDIR="$HOME/tmp"
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
termux-wake-lock >/dev/null 2>&1 || true
sleep 8
OPENCLAW_PORT="${OPENCLAW_PORT:-$(jq -r '.gateway.port // 18789' "$HOME/.openclaw/openclaw.json" 2>/dev/null || echo 18789)}"
OPENCLAW_WATCHDOG_ENABLED="${OPENCLAW_WATCHDOG_ENABLED:-0}"
NANOBOT_ENABLED="${NANOBOT_ENABLED:-0}"
is_true_flag() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}
if [ -f "$HOME/.openclaw-nanobot.env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.openclaw-nanobot.env"
fi
gateway_running() {
  pgrep -f "openclaw gateway" >/dev/null 2>&1 || pgrep -f "openclaw-gateway" >/dev/null 2>&1
}
if ! gateway_running; then
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$HOME/.termux/boot/openclaw-launch.sh"
  sleep 4
  if ! gateway_running; then
    printf '[%s] [start-openclaw] gateway start failed on port %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$OPENCLAW_PORT" >>"$HOME/openclaw-logs/start-openclaw.log"
  fi
fi
if is_true_flag "$OPENCLAW_WATCHDOG_ENABLED"; then
  # singleton watchdog: clear stale/orphan daemons then start one managed tmux session
  for pid in $(pgrep -f 'termux-openclaw-watchdog.sh --daemon' 2>/dev/null || true); do
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
  tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true
  tmux new -d -s openclaw-watchdog "$HOME/.termux/boot/openclaw-watchdog-launch.sh"
else
  for pid in $(pgrep -f 'termux-openclaw-watchdog.sh --daemon' 2>/dev/null || true); do
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
  tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true
fi
if is_true_flag "$NANOBOT_ENABLED"; then
  # singleton nanobot: clear stale/orphan daemons then start one managed tmux session
  for pid in $(pgrep -f 'termux-rescue-nanobot.sh --daemon' 2>/dev/null || true); do
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
  rm -f "$HOME/.openclaw-nanobot/daemon.pid" >/dev/null 2>&1 || true
  rm -rf "$HOME/.openclaw-nanobot/daemon.lock" >/dev/null 2>&1 || true
  tmux kill-session -t openclaw-nanobot >/dev/null 2>&1 || true
  tmux new -d -s openclaw-nanobot "$HOME/.termux/boot/openclaw-nanobot-launch.sh"
fi
EOF
chmod 700 "$HOME/.termux/boot/openclaw-launch.sh" "$HOME/.termux/boot/openclaw-nanobot-launch.sh" "$HOME/.termux/boot/start-openclaw.sh"
if [ -f "$HOME/.termux/boot/openclaw-watchdog-launch.sh" ]; then
  chmod 700 "$HOME/.termux/boot/openclaw-watchdog-launch.sh"
fi
if [ -f "$CORE_GUARD_SCRIPT" ]; then
  chmod 700 "$CORE_GUARD_SCRIPT"
fi
if [ -f "$OBSIDIAN_SCRIPT" ]; then
  chmod 700 "$OBSIDIAN_SCRIPT"
fi
if [ -f "$UPDATE_SCRIPT" ]; then
  chmod 700 "$UPDATE_SCRIPT"
fi
if [ -f "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-rescue-nanobot.sh" ]; then
  chmod 700 "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-rescue-nanobot.sh"
fi
if [ -f "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-safe-config-edit.sh" ]; then
  chmod 700 "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-safe-config-edit.sh"
fi

if [ "$SKIP_WATCHDOG" != "1" ]; then
log "writing watchdog env"
cat >"$HOME/.openclaw-watchdog.env" <<EOF
OPENCLAW_REPO_DIR="$OPENCLAW_TERMUX_REPO_DIR"
OPENCLAW_REPO_BRANCH="main"
OPENCLAW_PORT="$OPENCLAW_PORT"
TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN"
TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID"
WATCHDOG_TELEGRAM_POLL_ENABLED="0"
WATCHDOG_TELEGRAM_BOT_TOKEN=""
NVIDIA_API_KEY="$NVIDIA_API_KEY"
POLL_INTERVAL_SECONDS="180"
MONITOR_INTERVAL_SECONDS="1800"
MAINTENANCE_TIMEOUT_SECONDS="1800"
RESCUE_COOLDOWN_SECONDS="300"
STARTUP_GRACE_SECONDS="300"
HANDSHAKE_INTERVAL_SECONDS="1800"
HANDSHAKE_TIMEOUT_SECONDS="45"
HANDSHAKE_STALE_SECONDS="900"
HANDSHAKE_FAIL_THRESHOLD="1"
MODEL_POLICY_RESTART_ON_CHANGE="0"
DRIFT_AUTO_BASELINE_IF_HEALTHY="1"
SELF_CHECK_ENFORCE_LOCAL_MEMORY="1"
SELFCHECK_INTERVAL_SECONDS="1800"
SELFCHECK_ALERT_COOLDOWN_SECONDS="3600"
SELFCHECK_MEMORY_INDEX_GRACE_SECONDS="21600"
OPENCLAW_MEMORY_EMBEDDING_MODEL="$EMBEDDING_MODEL_REF"
OPENCLAW_MEMORY_MODEL_CACHE_DIR="$EMBEDDING_MODEL_CACHE_DIR"
OPENCLAW_COMPACTION_RESERVE_TOKENS="$OPENCLAW_COMPACTION_RESERVE_TOKENS"
OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS="$OPENCLAW_COMPACTION_MEMORY_FLUSH_SOFT_TOKENS"
OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT="$OPENCLAW_COMPACTION_MEMORY_FLUSH_PROMPT"
EOF
chmod 600 "$HOME/.openclaw-watchdog.env"
fi

log "writing nanobot env"
cat >"$HOME/.openclaw-nanobot.env" <<EOF
NANOBOT_ENABLED="$NANOBOT_ENABLED"
OPENCLAW_WATCHDOG_ENABLED="$OPENCLAW_WATCHDOG_ENABLED"
OPENCLAW_TERMUX_REPO_DIR="$OPENCLAW_TERMUX_REPO_DIR"
CORE_GUARD_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh"
OPENCLAW_BOOT_SCRIPT="$HOME/.termux/boot/openclaw-launch.sh"
TELEGRAM_BOT_TOKEN="$NANOBOT_TELEGRAM_BOT_TOKEN"
TELEGRAM_OWNER_ID="$TELEGRAM_OWNER_ID"
NVIDIA_API_KEY="$NVIDIA_API_KEY"
NANOBOT_MODEL="$NANOBOT_MODEL"
POLL_INTERVAL_SECONDS="15"
HEALTHCHECK_INTERVAL_SECONDS="300"
HEALTH_TIMEOUT_SECONDS="35"
AUTO_RESCUE_ON_UNHEALTHY="1"
NANOBOT_STARTUP_GRACE_SECONDS="900"
NANOBOT_FAIL_THRESHOLD="3"
NANOBOT_RESCUE_COOLDOWN_SECONDS="1800"
EOF
chmod 600 "$HOME/.openclaw-nanobot.env"

if [ -x "$OBSIDIAN_SCRIPT" ] && pm list packages 2>/dev/null | grep -q '^package:md\.obsidian$'; then
  log "obsidian detected; linking vault"
  OPENCLAW_OBSIDIAN_RESTART=0 bash "$OBSIDIAN_SCRIPT" --link >>"$HOME/openclaw-logs/obsidian-integration.log" 2>&1 || true
fi

log "starting OpenClaw gateway in tmux"
termux-wake-lock >/dev/null 2>&1 || true
tmux kill-session -t openclaw >/dev/null 2>&1 || true
tmux new -d -s openclaw "$HOME/.termux/boot/openclaw-launch.sh"
if [ "$SKIP_WATCHDOG" != "1" ]; then
  tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true
  tmux new -d -s openclaw-watchdog "$HOME/.termux/boot/openclaw-watchdog-launch.sh"
else
  tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true
fi
if [ "$NANOBOT_ENABLED" = "1" ]; then
  if [ "$SKIP_NANOBOT" != "1" ]; then
    rm -f "$HOME/.openclaw-nanobot/daemon.pid" >/dev/null 2>&1 || true
    rm -rf "$HOME/.openclaw-nanobot/daemon.lock" >/dev/null 2>&1 || true
    tmux kill-session -t openclaw-nanobot >/dev/null 2>&1 || true
    tmux new -d -s openclaw-nanobot "$HOME/.termux/boot/openclaw-nanobot-launch.sh"
  fi
fi
sleep 3

if is_true_flag "$EMBEDDING_WARMUP_ON_REBUILD" && [ -n "$EMBEDDING_MODEL_REF" ]; then
  if ! pgrep -f "openclaw-memory|openclaw memory index" >/dev/null 2>&1; then
    log "warming local memory index with embedding model"
    nohup bash -lc 'export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"; export TMPDIR="${TMPDIR:-$HOME/tmp}"; openclaw memory index --force --verbose' >>"$HOME/openclaw-logs/memory-index.log" 2>&1 &
  else
    log "memory warmup already running; skip"
  fi
fi

log "openclaw version: $(openclaw --version 2>/dev/null || echo unavailable)"
log "channel: $OPENCLAW_CHANNEL"
log "done"
log "gateway token: $OPENCLAW_GATEWAY_TOKEN"
log "auto-start script: ~/.termux/boot/start-openclaw.sh"
if [ "$SKIP_WATCHDOG" != "1" ]; then
  log "watchdog env: ~/.openclaw-watchdog.env"
fi
log "next: use 'oclog' to watch logs"
