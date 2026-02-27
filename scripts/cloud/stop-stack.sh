#!/usr/bin/env bash
set -euo pipefail
for s in openclaw openclaw-nanobot openclaw-watchdog; do tmux kill-session -t "=$s" >/dev/null 2>&1 || true; done
pkill -9 -f "openclaw-gateway|openclaw gateway|termux-rescue-nanobot.sh --daemon|termux-openclaw-watchdog.sh --daemon" >/dev/null 2>&1 || true
