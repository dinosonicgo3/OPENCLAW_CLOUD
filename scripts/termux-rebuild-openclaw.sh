#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

log() {
  printf "[termux-rebuild] %s\n" "$*"
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

log "stopping old claw processes"
pkill -9 -x zeroclaw >/dev/null 2>&1 || true
pkill -9 -f "zeroclaw daemon" >/dev/null 2>&1 || true
pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
if [ "$SKIP_WATCHDOG" != "1" ]; then
  pkill -9 -f "termux-openclaw-watchdog.sh" >/dev/null 2>&1 || true
fi
pkill -9 -x openclaw >/dev/null 2>&1 || true
tmux kill-session -t openclaw >/dev/null 2>&1 || true
if [ "$SKIP_WATCHDOG" != "1" ]; then
  tmux kill-session -t openclaw-watchdog >/dev/null 2>&1 || true
fi

log "removing zeroclaw and old openclaw data"
rm -f "$PREFIX/bin/zeroclaw" "$HOME/.cargo/bin/zeroclaw" >/dev/null 2>&1 || true
rm -rf \
  "$HOME/.zeroclaw" \
  "$HOME/zeroclaw" \
  "$HOME/.openclaw" \
  "$HOME/openclaw" \
  "$HOME/openclaw-logs" \
  "$HOME/openclaw-install.sh" \
  "$HOME/.zeroclaw_daemon.log" \
  "$HOME/.openclaw_daemon.log"
if [ "$SKIP_WATCHDOG" != "1" ]; then
  rm -rf "$HOME/.openclaw-watchdog"
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

log "installing openclaw latest non-stable build"
if npm view openclaw@dev version >/dev/null 2>&1; then
  npm install -g openclaw@dev
  OPENCLAW_CHANNEL="dev"
else
  npm install -g openclaw@latest
  OPENCLAW_CHANNEL="latest"
fi

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
TELEGRAM_OWNER_ID="${TELEGRAM_OWNER_ID:-6002298888}"
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-$(date +%s | sha256sum | cut -c1-24)}"
OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$REPO_DIR}"
CORE_GUARD_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh"
OBSIDIAN_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-obsidian-integrate.sh"
UPDATE_SCRIPT="$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-main-system-update.sh"

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

log "writing ~/.openclaw/openclaw.json"
jq -n \
  --arg gatewayToken "$OPENCLAW_GATEWAY_TOKEN" \
  --argjson gatewayPort "$OPENCLAW_PORT" \
  --arg telegramToken "$TELEGRAM_BOT_TOKEN" \
  --arg telegramOwner "$TELEGRAM_OWNER_ID" \
  --arg nvidiaKey "$NVIDIA_API_KEY" \
  '{
    gateway: {
      mode: "local",
      bind: "lan",
      port: $gatewayPort,
      auth: { mode: "token", token: $gatewayToken }
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
              reasoning: true,
              input: ["text"],
              contextWindow: 131072,
              maxTokens: 8192
            },
            {
              id: "moonshotai/kimi-k2.5",
              name: "Kimi K2.5 (NVIDIA)",
              reasoning: true,
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
  }' >"$HOME/.openclaw/openclaw.json"

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
alias coreguard='bash "${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}/scripts/termux-openclaw-core-guard.sh" --fix'
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
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp"
export OPENCLAW_TERMUX_REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME/DINO_OPENCLAW}"
if [ -x "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh" ]; then
  "$OPENCLAW_TERMUX_REPO_DIR/scripts/termux-openclaw-core-guard.sh" --fix >>"$HOME/openclaw-logs/core-guard.log" 2>&1 || true
fi
exec openclaw gateway --allow-unconfigured >>"$HOME/openclaw-logs/gateway.log" 2>&1
EOF
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
if ! ss -ltn 2>/dev/null | grep -q ":${OPENCLAW_PORT} "; then
  if ! pgrep -f "openclaw gateway" >/dev/null 2>&1 && ! pgrep -f "openclaw-gateway" >/dev/null 2>&1; then
    if ! tmux has-session -t openclaw 2>/dev/null; then
      tmux new -d -s openclaw "$HOME/.termux/boot/openclaw-launch.sh"
    fi
  fi
fi
tmux has-session -t openclaw-watchdog 2>/dev/null || tmux new -d -s openclaw-watchdog "$HOME/.termux/boot/openclaw-watchdog-launch.sh"
EOF
chmod 700 "$HOME/.termux/boot/openclaw-launch.sh" "$HOME/.termux/boot/openclaw-watchdog-launch.sh" "$HOME/.termux/boot/start-openclaw.sh"
if [ -f "$CORE_GUARD_SCRIPT" ]; then
  chmod 700 "$CORE_GUARD_SCRIPT"
fi
if [ -f "$OBSIDIAN_SCRIPT" ]; then
  chmod 700 "$OBSIDIAN_SCRIPT"
fi
if [ -f "$UPDATE_SCRIPT" ]; then
  chmod 700 "$UPDATE_SCRIPT"
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
MODEL_POLICY_RESTART_ON_CHANGE="0"
DRIFT_AUTO_BASELINE_IF_HEALTHY="1"
EOF
chmod 600 "$HOME/.openclaw-watchdog.env"
fi

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
fi
sleep 3

log "openclaw version: $(openclaw --version 2>/dev/null || echo unavailable)"
log "channel: $OPENCLAW_CHANNEL"
log "done"
log "gateway token: $OPENCLAW_GATEWAY_TOKEN"
log "auto-start script: ~/.termux/boot/start-openclaw.sh"
if [ "$SKIP_WATCHDOG" != "1" ]; then
  log "watchdog env: ~/.openclaw-watchdog.env"
fi
log "next: use 'oclog' to watch logs"
