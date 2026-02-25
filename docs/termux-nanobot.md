# Termux Rescue Nanobot (`潤天蟹`)

Independent rescue bot for phone-side OpenClaw recovery.

## Purpose

- Run as a separate process from OpenClaw gateway.
- Listen on a dedicated Telegram bot token.
- Detect unhealthy OpenClaw and trigger safe recovery.
- Use NVIDIA `z-ai/glm4.7` for structured rescue decision only.

## Safety boundary

Nanobot only allows these actions:

1. `none`
2. `coreguard_restart`
3. `watchdog_rescue`

No free-form shell command from LLM output is executed.

## Runtime files

- Script: `scripts/termux-rescue-nanobot.sh`
- Env: `~/.openclaw-nanobot.env`
- State: `~/.openclaw-nanobot/state.json`
- Log: `~/openclaw-logs/nanobot.log`
- Boot launcher: `~/.termux/boot/openclaw-nanobot-launch.sh`

## Enable in rebuild

```bash
export NANOBOT_TELEGRAM_BOT_TOKEN='<dedicated-nanobot-token>'
export TELEGRAM_OWNER_ID='6002298888'
export NVIDIA_API_KEY='nvapi-...'
export NANOBOT_MODEL='z-ai/glm4.7'
bash scripts/termux-rebuild-openclaw.sh
```

If `NANOBOT_TELEGRAM_BOT_TOKEN` is empty, nanobot is written but disabled.

## Telegram commands (owner only)

- `/status` - health status
- `/rescue` or `/helpdog` - immediate rescue
- `/fix` or `/repair` - fix/restart path
- `/model` - current nanobot model

## Local commands

- `nanolog` - attach nanobot tmux session
- `nanostatus` - print nanobot state
- `nanorescue` - force rescue now

