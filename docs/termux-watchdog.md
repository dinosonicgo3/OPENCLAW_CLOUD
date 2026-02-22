# Termux Watchdog (Auto Rescue)

This watchdog runs independently from OpenClaw and is started with phone boot.

## What it does

- Polls Telegram every 3 minutes for owner commands.
- Runs OpenClaw health checks every 30 minutes.
- Auto-rolls back to latest git tag matching `穩定版*` when rescue is needed.
- Sends rescue and status messages back to Telegram owner.

## Telegram commands

- `/helpdog`  
  Immediate rescue rollback + rebuild.
- `更新主系統` (or `/update_system`)  
  Start maintenance handshake (expected disconnect allowed).
- `更新成功` / `更新完成` (or `/update_ok`)  
  Finish maintenance handshake.
- `/dogstatus`  
  Return watchdog state.

## Handshake behavior

1. Send `更新主系統` before system update starts.
2. Watchdog enters maintenance mode for 30 minutes.
3. During maintenance, OpenClaw disconnection is treated as expected.
4. If `更新成功` is not received within 30 minutes, watchdog triggers rescue rollback automatically.

## Runtime files

- Watchdog script: `scripts/termux-openclaw-watchdog.sh`
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
dogrescue      # force rescue rollback now
dogmaint_start # manual maintenance-start handshake
dogmaint_ok    # manual maintenance-success handshake
```
