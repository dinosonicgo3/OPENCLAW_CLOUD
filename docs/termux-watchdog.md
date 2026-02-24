# Termux Watchdog (Auto Rescue)

This watchdog runs independently from OpenClaw and is started with phone boot.

## What it does

- Optional Telegram command polling every 3 minutes (disabled by default to avoid bot conflicts with main OpenClaw service).
- Runs OpenClaw health checks every 30 minutes.
- Runs `termux-openclaw-core-guard.sh --fix` before health checks to auto-heal dangerous gateway auth drift.
- Enforces model policy:
  - removes forbidden fallback `zai/glm-5` family refs,
  - sends Telegram notice when runtime switches to a fallback model,
  - marks confirmed unusable `provider/model` for 24 hours (cooldown) to avoid repeated wasted retries.
- Tracks hash baseline for critical low-level files. If drift is detected outside maintenance handshake, watchdog auto-rolls back.
- Auto-rolls back to latest git tag matching `穩定版*` when rescue is needed.
- Sends rescue and status messages back to Telegram owner.

## Why this guard is required

One observed crash pattern was:

- `gateway.bind=lan`
- `gateway.auth.mode=none`

OpenClaw correctly refuses this startup state (`Refusing to bind gateway to lan without auth`).  
`core-guard` now prevents this by auto-enforcing token/password auth when LAN binding is enabled.

## Default no-conflict mode

- `WATCHDOG_TELEGRAM_POLL_ENABLED=0` by default.
- Use local commands for handshake/rescue so watchdog does not call `getUpdates`.
- Local commands:
  - `dogrescue`
  - `dogmaint_start`
  - `dogmaint_ok`

## Optional Telegram commands (dedicated watchdog bot token required)

- `/helpdog`  
  Immediate rescue rollback + rebuild.
- `更新主系統` (or `/update_system`)  
  Start maintenance handshake (expected disconnect allowed).
- `更新成功` / `更新完成` (or `/update_ok`)  
  Finish maintenance handshake.
- `/dogstatus`  
  Return watchdog state.

Enable only with a dedicated token that is different from the main OpenClaw bot:

```bash
WATCHDOG_TELEGRAM_POLL_ENABLED="1"
WATCHDOG_TELEGRAM_BOT_TOKEN="<dedicated_watchdog_bot_token>"
```

## Handshake behavior

1. Before system update starts, run `dogmaint_start` (or send `更新主系統` only when dedicated watchdog bot polling is enabled).
2. Watchdog enters maintenance mode for 30 minutes.
3. During maintenance, OpenClaw disconnection is treated as expected.
4. After update completes, run `dogmaint_ok` (or send `更新成功` only when dedicated watchdog bot polling is enabled).
5. `dogmaint_ok` now includes a health gate: OpenClaw must be healthy, otherwise watchdog rejects success and triggers rescue rollback.
6. On successful maintenance finish, watchdog refreshes the critical hash baseline.
7. If maintenance success is not received within 30 minutes, watchdog triggers rescue rollback automatically.
8. Safety enhancement: if OpenClaw stays healthy during maintenance, watchdog auto-finishes maintenance instead of waiting for timeout.

## Runtime files

- Watchdog script: `scripts/termux-openclaw-watchdog.sh`
- Core guard script: `scripts/termux-openclaw-core-guard.sh`
- Main update script: `scripts/termux-main-system-update.sh`
- Env config: `~/.openclaw-watchdog.env`
- State file: `~/.openclaw-watchdog/state.json`
- Log file: `~/openclaw-logs/watchdog.log`
- Boot launchers:
  - `~/.termux/boot/openclaw-watchdog-launch.sh`
  - `~/.termux/boot/start-openclaw.sh`

## Local control commands

```bash
doglog         # attach watchdog tmux session
dogstatus      # print watchdog state json
dogbaseline    # refresh critical file hash baseline
dogrescue      # force rescue rollback now
dogmaint_start # manual maintenance-start handshake
dogmaint_ok    # manual maintenance-success handshake
```
