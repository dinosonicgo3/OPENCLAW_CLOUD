# Termux Main System Update Policy (Stable V1)

This policy defines a safe, repeatable update process for the phone-side Termux environment after OpenClaw is deployed.

## Scope

- Device: Android + Termux runtime
- Service: OpenClaw gateway running in `tmux`
- Channel: Telegram
- Default model: `nvidia/z-ai/glm4.7`

## Change control

- Update window: one controlled maintenance window at a time
- Rule: no config edits during package update/upgrade
- Rule: keep one known-good backup before every update

## Pre-update checklist

Run all checks before update:

```bash
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
tmux ls
openclaw --version
jq -r '.agents.defaults.model.primary,.channels.telegram.enabled' ~/.openclaw/openclaw.json
```

Create backup:

```bash
mkdir -p ~/backups
ts="$(date +%Y%m%d-%H%M%S)"
tar -czf ~/backups/openclaw-state-"$ts".tar.gz ~/.openclaw ~/.bashrc ~/.termux
```

## Standard update procedure

### 1) Stop runtime cleanly

```bash
pkill -f "openclaw gateway" || true
tmux kill-session -t openclaw || true
```

### 2) Update Termux base packages

```bash
pkg update -y
pkg upgrade -y
pkg install -y nodejs-lts git curl jq tmux openssh termux-api
```

### 3) Update OpenClaw runtime

```bash
export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"
npm config set prefix "$HOME/.npm-global"
npm install -g openclaw@latest
```

### 4) Validate required config

```bash
jq -r '.agents.defaults.model.primary,.agents.defaults.model.fallbacks[0],.channels.telegram.enabled,.channels.telegram.allowFrom[0]' ~/.openclaw/openclaw.json
```

Expected values:

- primary model: `nvidia/z-ai/glm4.7`
- fallback model: `nvidia/nvidia/llama-3.1-nemotron-70b-instruct`
- telegram enabled: `true`

### 5) Start runtime

```bash
tmux new -d -s openclaw
tmux send-keys -t openclaw 'export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"; openclaw gateway --allow-unconfigured 2>&1 | tee -a "$HOME/openclaw-logs/gateway.log"' C-m
```

### 6) Post-update verification

```bash
tail -n 60 ~/openclaw-logs/gateway.log
```

Check for:

- `listening on ws://0.0.0.0:18789`
- `agent model: nvidia/z-ai/glm4.7`
- `telegram ... starting provider`

## Rollback procedure

If update fails:

```bash
pkill -f "openclaw gateway" || true
tmux kill-session -t openclaw || true
tar -xzf ~/backups/openclaw-state-<timestamp>.tar.gz -C ~
tmux new -d -s openclaw
tmux send-keys -t openclaw 'export PATH="$HOME/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"; openclaw gateway --allow-unconfigured 2>&1 | tee -a "$HOME/openclaw-logs/gateway.log"' C-m
```

## Mandatory stability rules

- Never run `pkg upgrade` without creating a backup tarball first.
- Never change provider/model and package versions in the same maintenance window.
- Always confirm Telegram + model logs after restart.
- Keep `~/.openclaw/openclaw.json` under versioned backup snapshots.
- Keep boot scripts present: `~/.termux/boot/start-openclaw.sh` and `~/.termux/boot/openclaw-launch.sh`.
- Keep Termux:Boot (`com.termux.boot`) installed so OpenClaw can auto-start after reboot.
- Keep watchdog running (`tmux` session: `openclaw-watchdog`) with valid `~/.openclaw-watchdog.env`.
- Before system update, send Telegram command `更新主系統`; after success, send `更新成功` (handshake complete).

## Version label

Policy baseline tag: `穩定版V1`.
