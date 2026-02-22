# Termux Obsidian Integration

This guide links OpenClaw workspace to an Obsidian vault on Android shared storage.

## Goal

- OpenClaw and Obsidian read/write the same Markdown files.
- Keep phone-side notes editable from both CLI and Obsidian app.

## Script

- `scripts/termux-obsidian-integrate.sh`

## Commands

```bash
obsidian_status
obsidian_link
```

Direct script usage:

```bash
bash scripts/termux-obsidian-integrate.sh --status
bash scripts/termux-obsidian-integrate.sh --link
```

## Behavior

- Verifies Obsidian app package `md.obsidian` exists.
- Detects existing vault by finding `.obsidian` under `~/storage/shared`.
- If no vault exists, creates default vault:
  - `~/storage/shared/Documents/OpenClawVault`
- Backs up old workspace to:
  - `~/.openclaw/backups/workspace-pre-obsidian-<timestamp>`
- Links workspace:
  - `~/.openclaw/workspace -> <vault>`
- Restarts OpenClaw gateway (default) so new workspace path is active.

## Optional environment variables

```bash
OPENCLAW_OBSIDIAN_VAULT_DIR="$HOME/storage/shared/Documents/MyVault"
OPENCLAW_OBSIDIAN_RESTART=0
```

## Notes

- Run `termux-setup-storage` first if `~/storage/shared` is missing.
- Keep vault path without special permission restrictions so Obsidian can open it.
