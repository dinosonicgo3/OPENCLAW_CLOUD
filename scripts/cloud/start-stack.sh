#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export TZ="${TZ:-Asia/Taipei}"
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
mkdir -p "$HOME/openclaw-logs" "$HOME/tmp" "$HOME/.openclaw-nanobot"

start_openclaw() {
  if ! tmux has-session -t =openclaw 2>/dev/null; then
    tmux new -d -s openclaw "$HOME/cloud/openclaw-launch.sh"
  fi
}

start_nanobot() {
  if ! tmux has-session -t =openclaw-nanobot 2>/dev/null; then
    tmux new -d -s openclaw-nanobot "bash $HOME/DINO_OPENCLAW/scripts/termux-rescue-nanobot.sh --daemon >>$HOME/openclaw-logs/nanobot.log 2>&1"
  fi
}

start_webhook() {
  if [ ! -f "$HOME/cloud/webhook_skeleton.py" ]; then
    return 0
  fi
  if ! pgrep -f "python3 .*cloud/webhook_skeleton.py" >/dev/null 2>&1; then
    nohup python3 "$HOME/cloud/webhook_skeleton.py" >>"$HOME/openclaw-logs/webhook.log" 2>&1 < /dev/null &
  fi
}

while true; do
  start_openclaw
  start_nanobot
  start_webhook
  sleep 10
done
