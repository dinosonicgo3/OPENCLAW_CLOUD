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

## Model Canonicalization (NVIDIA GLM-5)
- Canonical model id is z-ai/glm5 (not zai-org/GLM-5).
- Repair command: bash ~/cloud/openclaw-coreguard.sh --fix
- Restart after repair: systemctl restart openclaw-stack.service
- Verify primary/fallback: jq -r '.agents.defaults.model' ~/.openclaw/openclaw.json
- Verify allowlist includes GLM5/GLM4.7: jq -r '.agents.defaults.models | keys[]' ~/.openclaw/openclaw.json | grep -E 'nvidia/z-ai/glm5|nvidia/z-ai/glm4.7'
- Query NVIDIA official model ids (internal command): bash ~/DINO_OPENCLAW/scripts/cloud/nvidia-model-catalog.sh

## Coding Standard (AI編程規範)
- Source of truth: ~/OpenClawVault/AI編程規範.txt
- Repo copy for sync: docs/AI編程規範.txt
- Any coding/self-repair task must read this standard before editing core files.
