# OpenClaw Cloud Operations (OCI)

## Runtime Topology
- `openclaw-stack.service`: systemd supervisor (always running)
- tmux session `openclaw`: OpenClaw gateway runtime
- tmux session `openclaw-nanobot`: Nanobot Telegram medical bot
- webhook skeleton: `python3 ~/cloud/webhook_skeleton.py` on port `38080`

## Cloud-Native Scripts
- `~/cloud/openclaw-coreguard.sh`: validate/fix `~/.openclaw/openclaw.json`
- `~/cloud/openclaw-rebuild.sh`: safe rebuild + restart + health verify
- `~/cloud/openclaw-update.sh`: update OpenClaw to latest and verify

## Daily Commands
- Status:
```bash
systemctl status openclaw-stack.service --no-pager
bash ~/DINO_OPENCLAW/scripts/termux-rescue-nanobot.sh --diagnose
```
- Update:
```bash
bash ~/cloud/openclaw-update.sh
```
- Rebuild rescue:
```bash
bash ~/cloud/openclaw-rebuild.sh
```

## Safety Rules
- Do not run Termux `pkg` commands on OCI.
- Keep Watchdog disabled in cloud mode.
- Use `tmux` exact session names (`=openclaw`, `=openclaw-nanobot`).
- Always run `openclaw-coreguard.sh --fix` before/after config changes.
