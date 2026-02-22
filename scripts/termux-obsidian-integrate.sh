#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

HOME_DIR="${HOME:-/data/data/com.termux/files/home}"
SHARED_ROOT="${OPENCLAW_SHARED_ROOT:-$HOME_DIR/storage/shared}"
WORKSPACE_LINK="${OPENCLAW_WORKSPACE_PATH:-$HOME_DIR/.openclaw/workspace}"
REPO_DIR="${OPENCLAW_TERMUX_REPO_DIR:-$HOME_DIR/DINO_OPENCLAW}"
LOG_FILE="${OPENCLAW_OBSIDIAN_LOG:-$HOME_DIR/openclaw-logs/obsidian-integration.log}"
VAULT_DIR="${OPENCLAW_OBSIDIAN_VAULT_DIR:-}"
RESTART_AFTER_LINK="${OPENCLAW_OBSIDIAN_RESTART:-1}"

mkdir -p "$(dirname "$LOG_FILE")" "$HOME_DIR/tmp"
export TMPDIR="${TMPDIR:-$HOME_DIR/tmp}"
export PATH="$HOME_DIR/.npm-global/bin:/data/data/com.termux/files/usr/bin:$PATH"

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  printf '[%s] [obsidian-integrate] %s\n' "$ts" "$*" | tee -a "$LOG_FILE" >/dev/null
}

is_obsidian_installed() {
  pm list packages 2>/dev/null | grep -q '^package:md\.obsidian$'
}

resolve_shared_root() {
  local candidate
  for candidate in "$SHARED_ROOT" "/storage/emulated/0" "/sdcard"; do
    if [ -d "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

shared_candidates() {
  cat <<EOF
$SHARED_ROOT
/storage/emulated/0/Android/data/com.termux/files
/storage/emulated/0/Android/media/com.termux
/storage/emulated/0/Documents
/sdcard/Documents
$HOME_DIR/storage
EOF
}

resolve_writable_base() {
  local candidate probe file
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    [ -d "$candidate" ] || continue
    probe="$candidate/.openclaw_probe_$$"
    if mkdir "$probe" >/dev/null 2>&1; then
      file="$probe/rw-test.md"
      if printf 'ok\n' >"$file" 2>/dev/null && cat "$file" >/dev/null 2>&1; then
        rm -f "$file" >/dev/null 2>&1 || true
        rmdir "$probe" >/dev/null 2>&1 || true
        printf '%s\n' "$candidate"
        return 0
      fi
      rm -f "$file" >/dev/null 2>&1 || true
      rmdir "$probe" >/dev/null 2>&1 || true
    fi
  done < <(shared_candidates)
  return 1
}

detect_vault_dir() {
  local found root default_vault writable_base
  root="$(resolve_shared_root || true)"
  writable_base="$(resolve_writable_base || true)"
  if [ -n "$writable_base" ]; then
    default_vault="${writable_base}/OpenClawVault"
  else
    default_vault="${root}/Documents/OpenClawVault"
  fi
  if [ -n "$VAULT_DIR" ]; then
    printf '%s\n' "$VAULT_DIR"
    return 0
  fi
  while IFS= read -r root; do
    [ -n "$root" ] || continue
    [ -d "$root" ] || continue
    found="$(find "$root" -maxdepth 6 -type d -name .obsidian 2>/dev/null | head -n 1 || true)"
    if [ -n "$found" ]; then
      dirname "$found"
      return 0
    fi
  done < <(shared_candidates)
  printf '%s\n' "$default_vault"
}

status() {
  local vault resolved root writable_base
  root="$(resolve_shared_root || true)"
  writable_base="$(resolve_writable_base || true)"
  vault="$(detect_vault_dir)"
  echo "obsidian_package=$(if is_obsidian_installed; then echo yes; else echo no; fi)"
  echo "shared_root_config=$SHARED_ROOT"
  echo "shared_root_resolved=${root:-<missing>}"
  echo "writable_base=${writable_base:-<missing>}"
  echo "vault_dir=$vault"
  echo "vault_exists=$(if [ -d "$vault" ]; then echo yes; else echo no; fi)"
  echo "vault_obsidian_dir=$(if [ -d "$vault/.obsidian" ]; then echo yes; else echo no; fi)"
  echo "workspace_path=$WORKSPACE_LINK"
  if [ -L "$WORKSPACE_LINK" ]; then
    resolved="$(readlink -f "$WORKSPACE_LINK" 2>/dev/null || true)"
    echo "workspace_symlink=yes"
    echo "workspace_target=$resolved"
  elif [ -d "$WORKSPACE_LINK" ]; then
    echo "workspace_symlink=no"
    echo "workspace_target=$WORKSPACE_LINK"
  else
    echo "workspace_symlink=missing"
  fi
}

seed_workspace_files() {
  local source="$1"
  local target="$2"
  [ -d "$source" ] || return 0
  mkdir -p "$target"
  cp -a -n "$source"/. "$target"/ 2>/dev/null || true
}

write_integration_note() {
  local vault="$1"
  local note="$vault/OPENCLAW-OBSIDIAN-INTEGRATION.md"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat >"$note" <<EOF
# OpenClaw x Obsidian Integration

- Integrated at: $ts
- Workspace symlink: $WORKSPACE_LINK -> $vault
- Repo script: $REPO_DIR/scripts/termux-obsidian-integrate.sh

## Notes

- OpenClaw now reads/writes workspace files directly in this vault.
- You can open this folder in Obsidian Android for real-time sync with OpenClaw.
EOF
}

restart_openclaw_if_needed() {
  [ "$RESTART_AFTER_LINK" = "1" ] || return 0
  if [ ! -x "$HOME_DIR/.termux/boot/openclaw-launch.sh" ]; then
    log "skip restart: boot launcher missing"
    return 0
  fi
  log "restarting openclaw to pick up workspace link"
  pkill -9 -f "openclaw gateway" >/dev/null 2>&1 || true
  pkill -9 -f "openclaw-gateway" >/dev/null 2>&1 || true
  pkill -9 -x openclaw >/dev/null 2>&1 || true
  tmux kill-session -t openclaw >/dev/null 2>&1 || true
  tmux new -d -s openclaw "$HOME_DIR/.termux/boot/openclaw-launch.sh"
}

link_workspace_to_vault() {
  local vault backup src root writable_base
  if ! is_obsidian_installed; then
    log "obsidian package (md.obsidian) not found"
    exit 1
  fi
  root="$(resolve_shared_root || true)"
  writable_base="$(resolve_writable_base || true)"
  if [ -z "$root" ] || [ -z "$writable_base" ]; then
    log "shared storage not ready (checked: $SHARED_ROOT, /storage/emulated/0, /sdcard)"
    exit 1
  fi

  vault="$(detect_vault_dir)"
  mkdir -p "$HOME_DIR/.openclaw/backups"
  if [ ! -d "$vault" ]; then
    mkdir "$vault"
  fi
  if [ ! -d "$vault/.obsidian" ]; then
    mkdir "$vault/.obsidian" >/dev/null 2>&1 || true
  fi

  if [ -L "$WORKSPACE_LINK" ]; then
    src="$(readlink -f "$WORKSPACE_LINK" 2>/dev/null || true)"
    if [ "$src" = "$vault" ]; then
      log "workspace already linked to vault: $vault"
    else
      seed_workspace_files "$src" "$vault"
      rm -f "$WORKSPACE_LINK"
    fi
  elif [ -d "$WORKSPACE_LINK" ]; then
    backup="$HOME_DIR/.openclaw/backups/workspace-pre-obsidian-$(date +%Y%m%d-%H%M%S)"
    mv "$WORKSPACE_LINK" "$backup"
    seed_workspace_files "$backup" "$vault"
    log "workspace backup created: $backup"
  fi

  ln -sfn "$vault" "$WORKSPACE_LINK"
  write_integration_note "$vault"
  restart_openclaw_if_needed

  log "integration complete: workspace -> $vault"
  printf 'workspace_link=%s\nvault_dir=%s\n' "$WORKSPACE_LINK" "$vault"
}

usage() {
  cat <<'EOF'
Usage:
  termux-obsidian-integrate.sh --status
  termux-obsidian-integrate.sh --link

Optional env:
  OPENCLAW_OBSIDIAN_VAULT_DIR=/path/to/vault
  OPENCLAW_OBSIDIAN_RESTART=0|1
EOF
}

case "${1:---status}" in
  --status)
    status
    ;;
  --link)
    link_workspace_to_vault
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
