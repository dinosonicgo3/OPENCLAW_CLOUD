# Termux Full Rebuild (ZeroClaw -> OpenClaw)

This workflow fully removes old `zeroclaw` and old OpenClaw runtime state, then installs OpenClaw on Termux with:

- Telegram enabled
- default model set to `nvidia/z-ai/glm4.7`
- fallback models:
  - `nvidia/zai-org/GLM-5`
  - `nvidia/moonshotai/kimi-k2.5`
  - `nvidia/openai/gpt-oss-120b`
  - `nvidia/nvidia/llama-3.1-nemotron-70b-instruct`

## 1) Clone repository on phone

```bash
git clone https://github.com/dinosonicgo3/DINO_OPENCLAW.git
cd DINO_OPENCLAW
```

## 2) Export required secrets

```bash
export TELEGRAM_BOT_TOKEN='your-bot-token'
export NVIDIA_API_KEY='nvapi-...'
```

Optional:

```bash
export TELEGRAM_OWNER_ID='6002298888'
export OPENCLAW_GATEWAY_TOKEN='your_gateway_token'
export OPENCLAW_PORT='18789'
```

## 3) Run one command

```bash
bash scripts/termux-rebuild-openclaw.sh
```

## 4) Daily commands

```bash
oclog   # attach gateway logs
ocr     # restart OpenClaw gateway in tmux
ockill  # stop OpenClaw
coreguard # enforce safe gateway auth config
obsidian_status # show Obsidian integration status
obsidian_link   # link OpenClaw workspace to Obsidian vault
dogbaseline # refresh watchdog critical-file baseline
```

## 5) Boot auto-start

The rebuild script writes:

- `~/.termux/boot/start-openclaw.sh`
- `~/.termux/boot/openclaw-launch.sh`
- `~/.termux/boot/openclaw-watchdog-launch.sh`
- `~/.openclaw-watchdog.env`
- `scripts/termux-openclaw-core-guard.sh` (used by launcher/watchdog)

Verify:

```bash
ls -la ~/.termux/boot
```

Required app:

- Install **Termux:Boot** (`com.termux.boot`)
- After phone reboot, open Termux once and confirm:

```bash
tmux ls
openclaw health
```

Watchdog details:

- `docs/termux-watchdog.md`

## 6) Obsidian integration

If Obsidian Android app (`md.obsidian`) is installed, rebuild auto-links workspace into a shared vault.

- Integration script: `scripts/termux-obsidian-integrate.sh`
- Default vault path: `~/storage/shared/Documents/OpenClawVault`
- Manual commands:

```bash
obsidian_status
obsidian_link
```

Details:

- `docs/termux-obsidian.md`

## 7) Main system update policy

Follow the maintenance policy after deployment:

- `docs/termux-main-system-update-policy.md`
