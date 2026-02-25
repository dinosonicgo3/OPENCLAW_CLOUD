# OpenClaw JSON Safe-Edit Spec (Termux)

## Why crashes happened
`openclaw.json` was being edited in-place with fields that current OpenClaw rejects, for example:
- `models.providers.google.api`
- `agents.defaults.compaction.memoryFlush.hardThresholdTokens`
- `channels.telegram.dmToken`

When these keys appear, OpenClaw skips/rejects config reload and can look like "service crashed".

## Mandatory edit protocol (copy-test-swap)
Always edit config with this sequence:
1. Copy source config to temp file.
2. Apply intended change on temp file.
3. Validate temp file:
   - valid JSON
   - pass `termux-openclaw-core-guard.sh --check`
4. If validation passes, atomically replace original file.
5. Keep timestamped backup.

Use:
```bash
bash ~/DINO_OPENCLAW/scripts/termux-safe-config-edit.sh --jq '<jq filter>'
```

## Guardrails enforced by core guard
`termux-openclaw-core-guard.sh` enforces:
- gateway auth/token safety for LAN bind
- local memory search settings for Termux
- compaction + memoryFlush required keys
- removal of unsupported keys:
  - `agents.defaults.compaction.keepRecentTokens`
  - `agents.defaults.compaction.memoryFlush.hardThresholdTokens`
  - `channels.telegram.dmToken`
  - `models.providers.google.api`

## Runtime behavior
- Boot/start/watchdog paths call core guard before/while service runs.
- If unsafe config is detected, it is healed from staged candidate and then swapped in.
- If staged candidate cannot pass validation, replacement is aborted.
