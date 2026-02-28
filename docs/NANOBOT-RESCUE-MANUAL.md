# Nanobot Rescue Manual (Cloud)

## Scope
This manual is for OCI cloud OpenClaw (`ubuntu@158.178.238.13`) where Watchdog is disabled and Nanobot is primary medic.

## Fast Triage
1. Check stack process health:
- `systemctl status openclaw-stack.service --no-pager`
- `tmux ls`

2. Check Telegram channel runtime (not just PID/port):
- `~/.npm-global/bin/openclaw channels status --json`
- Required: `.channels.telegram.running == true`

3. Check OpenClaw session drift:
- `~/.npm-global/bin/openclaw status --json`
- Verify `sessions.recent[].model` does not drift to unstable fallback unintentionally.

## Silent-But-Alive Root Cause Pattern
Common symptom: OpenClaw process exists, port open, but Telegram stops replying.

Primary causes:
- Telegram provider not running (`running=false`)
- Inbound/Outbound lag imbalance (`lastInboundAt` newer than `lastOutboundAt` for too long)
- Long blocking task inside agent lane (QMD embed / node-llama-cpp / cmake-js-llama)

## Blocking Task Detection
- `ps -eo pid,ppid,etimes,cmd | egrep 'qmd.js embed|node-llama-cpp|cmake-js-llama'`
- If elapsed time is high and Telegram no response, treat as blocking.

## Repair Order (Strict)
1. Stop blocking tasks only:
- `pkill -f '@tobilu/qmd/dist/qmd.js embed'`
- `pkill -f 'node-llama-cpp'`
- `pkill -f 'cmake-js-llama'`

2. Core guard normalize config:
- `bash ~/cloud/openclaw-coreguard.sh --fix`

3. Restart OpenClaw stack:
- `sudo systemctl restart openclaw-stack.service`

4. Re-check channel and session:
- `~/.npm-global/bin/openclaw channels status --json`
- `~/.npm-global/bin/openclaw status --json`

5. Only if still unhealthy, run rebuild rescue:
- `bash ~/cloud/openclaw-rebuild.sh`

## Model Stability Rule
- Default model for cloud Telegram session should remain `nvidia/z-ai/glm4.7`.
- If session model drifts to heavy fallback and causes repeated timeout, reset session model metadata and restart stack.

## Reporting Rule
Nanobot must report both:
- Before repair: cause + planned steps
- After repair: result + health state + next action
