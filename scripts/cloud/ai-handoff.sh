#!/usr/bin/env bash
set -euo pipefail

HANDOFF_DIR="${OPENCLAW_HANDOFF_DIR:-/home/ubuntu/OpenClawVault/interop/tasks}"
mkdir -p "$HANDOFF_DIR"

usage() {
  cat <<'EOF'
Usage:
  ai-handoff.sh enqueue --from <name> --to <name> --type <type> [--reason <text>] [--detail <text>]
  ai-handoff.sh claim --to <name> --actor <name>
  ai-handoff.sh complete --id <id> --status <done|failed|skipped> [--note <text>] [--actor <name>]
  ai-handoff.sh list [--to <name>] [--status <pending|processing|done|failed|skipped>]
EOF
}

json_escape() {
  jq -Rn --arg v "${1:-}" '$v'
}

cmd="${1:-}"
shift || true

case "$cmd" in
  enqueue)
    from=""
    to=""
    type=""
    reason=""
    detail=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --from) from="${2:-}"; shift 2 ;;
        --to) to="${2:-}"; shift 2 ;;
        --type) type="${2:-}"; shift 2 ;;
        --reason) reason="${2:-}"; shift 2 ;;
        --detail) detail="${2:-}"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    [ -n "$from" ] || { echo "--from required" >&2; exit 2; }
    [ -n "$to" ] || { echo "--to required" >&2; exit 2; }
    [ -n "$type" ] || { echo "--type required" >&2; exit 2; }
    ts="$(date +%s)"
    rid="$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    id="${ts}-${from}-to-${to}-${rid}"
    file="$HANDOFF_DIR/${id}.json"
    jq -n \
      --arg id "$id" \
      --arg from "$from" \
      --arg to "$to" \
      --arg type "$type" \
      --arg reason "$reason" \
      --arg detail "$detail" \
      --argjson now "$ts" \
      '{
        id:$id, from:$from, to:$to, type:$type,
        reason:$reason, detail:$detail,
        status:"pending",
        created_at:$now, updated_at:$now,
        claimed_by:null, claimed_at:null,
        completed_by:null, completed_at:null,
        note:null
      }' >"$file"
    chmod 600 "$file" >/dev/null 2>&1 || true
    jq -n --arg id "$id" --arg file "$file" '{ok:true,id:$id,file:$file}'
    ;;

  claim)
    to=""
    actor=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --to) to="${2:-}"; shift 2 ;;
        --actor) actor="${2:-}"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    [ -n "$to" ] || { echo "--to required" >&2; exit 2; }
    [ -n "$actor" ] || { echo "--actor required" >&2; exit 2; }
    shopt -s nullglob
    files=( "$HANDOFF_DIR"/*.json )
    shopt -u nullglob
    [ ${#files[@]} -gt 0 ] || exit 1
    IFS=$'\n' files=( $(printf '%s\n' "${files[@]}" | sort) )
    for f in "${files[@]}"; do
      [ -f "$f" ] || continue
      t="$(jq -r '.to // ""' "$f" 2>/dev/null || echo "")"
      s="$(jq -r '.status // ""' "$f" 2>/dev/null || echo "")"
      [ "$t" = "$to" ] || continue
      [ "$s" = "pending" ] || continue
      tmp="$(mktemp)"
      jq --arg actor "$actor" --argjson now "$(date +%s)" \
        '.status="processing" | .claimed_by=$actor | .claimed_at=$now | .updated_at=$now' \
        "$f" >"$tmp"
      mv "$tmp" "$f"
      cat "$f"
      exit 0
    done
    exit 1
    ;;

  complete)
    id=""
    status=""
    note=""
    actor=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --id) id="${2:-}"; shift 2 ;;
        --status) status="${2:-}"; shift 2 ;;
        --note) note="${2:-}"; shift 2 ;;
        --actor) actor="${2:-}"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    [ -n "$id" ] || { echo "--id required" >&2; exit 2; }
    [ -n "$status" ] || { echo "--status required" >&2; exit 2; }
    case "$status" in done|failed|skipped) ;; *) echo "invalid status" >&2; exit 2 ;; esac
    f="$HANDOFF_DIR/${id}.json"
    [ -f "$f" ] || { echo "task not found: $id" >&2; exit 3; }
    tmp="$(mktemp)"
    jq --arg status "$status" --arg note "$note" --arg actor "$actor" --argjson now "$(date +%s)" \
      '.status=$status | .note=$note | .completed_by=$actor | .completed_at=$now | .updated_at=$now' \
      "$f" >"$tmp"
    mv "$tmp" "$f"
    cat "$f"
    ;;

  list)
    to=""
    status=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --to) to="${2:-}"; shift 2 ;;
        --status) status="${2:-}"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
      esac
    done
    shopt -s nullglob
    files=( "$HANDOFF_DIR"/*.json )
    shopt -u nullglob
    [ ${#files[@]} -gt 0 ] || { echo '[]'; exit 0; }
    jq -s \
      --arg to "$to" \
      --arg status "$status" \
      '
        map(select(($to=="" or .to==$to) and ($status=="" or .status==$status)))
        | sort_by(.created_at)
      ' "${files[@]}"
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
