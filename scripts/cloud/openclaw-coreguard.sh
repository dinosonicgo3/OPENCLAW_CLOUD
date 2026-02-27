#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
ACTION="${1:---fix}"
BACKUP_DIR="${OPENCLAW_CONFIG_BACKUP_DIR:-$HOME/.openclaw/backups}"
mkdir -p "$BACKUP_DIR"

if [ ! -f "$CONFIG_PATH" ]; then
  echo "[cloud-coreguard] config not found: $CONFIG_PATH" >&2
  exit 1
fi

TMP_OUT="$(mktemp)"
status="$(python3 - "$CONFIG_PATH" "$TMP_OUT" "$ACTION" <<'PY'
import json
import os
import pathlib
import secrets
import sys

src = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
action = sys.argv[3]
obj = json.loads(src.read_text(encoding='utf-8'))
changed = False

def ensure_dict(parent, key):
    global changed
    if not isinstance(parent.get(key), dict):
        parent[key] = {}
        changed = True
    return parent[key]

def set_value(parent, key, value):
    global changed
    if parent.get(key) != value:
        parent[key] = value
        changed = True

gateway = ensure_dict(obj, 'gateway')
set_value(gateway, 'port', int(gateway.get('port') or 29876))
set_value(gateway, 'mode', 'local')
set_value(gateway, 'bind', 'lan')

auth = ensure_dict(gateway, 'auth')
set_value(auth, 'mode', 'token')
if not auth.get('token'):
    auth['token'] = secrets.token_hex(12)
    changed = True
rate = ensure_dict(auth, 'rateLimit')
set_value(rate, 'maxAttempts', 10)
set_value(rate, 'windowMs', 60000)
set_value(rate, 'lockoutMs', 300000)

control = ensure_dict(gateway, 'controlUi')
set_value(control, 'dangerouslyAllowHostHeaderOriginFallback', False)
allowed = control.get('allowedOrigins') if isinstance(control.get('allowedOrigins'), list) else []
port = gateway['port']
need = {f'http://localhost:{port}', f'http://127.0.0.1:{port}'}
public_ip = os.environ.get('OPENCLAW_PUBLIC_IP', '').strip()
if public_ip:
    need.add(f'http://{public_ip}:{port}')
new_allowed = []
for item in allowed:
    if isinstance(item, str) and item not in new_allowed:
        new_allowed.append(item)
for item in sorted(need):
    if item not in new_allowed:
        new_allowed.append(item)
if new_allowed != allowed:
    control['allowedOrigins'] = new_allowed
    changed = True

update = ensure_dict(obj, 'update')
set_value(update, 'channel', 'stable')

plugins = ensure_dict(obj, 'plugins')
entries = ensure_dict(plugins, 'entries')
tele_plugin = ensure_dict(entries, 'telegram')
set_value(tele_plugin, 'enabled', True)

channels = ensure_dict(obj, 'channels')
tele = ensure_dict(channels, 'telegram')
set_value(tele, 'enabled', True)
set_value(tele, 'dmPolicy', 'allowlist')
set_value(tele, 'groupPolicy', 'disabled')
if not isinstance(tele.get('allowFrom'), list):
    tele['allowFrom'] = []
    changed = True

agents = ensure_dict(obj, 'agents')
defs = ensure_dict(agents, 'defaults')
model = ensure_dict(defs, 'model')
set_value(model, 'primary', 'nvidia/z-ai/glm4.7')
fallbacks = [
    'nvidia/z-ai/glm5',
    'nvidia/moonshotai/kimi-k2.5',
    'nvidia/openai/gpt-oss-120b',
    'nvidia/nvidia/llama-3.1-nemotron-70b-instruct',
    'google/gemini-2.5-flash-lite-preview-09-2025',
    'groq/llama-3.3-70b-versatile',
]
if model.get('fallbacks') != fallbacks:
    model['fallbacks'] = fallbacks
    changed = True
models_allowlist = {
    'nvidia/z-ai/glm4.7': {},
    'nvidia/z-ai/glm5': {},
    'nvidia/moonshotai/kimi-k2.5': {},
    'nvidia/openai/gpt-oss-120b': {},
    'nvidia/nvidia/llama-3.1-nemotron-70b-instruct': {},
    'google/gemini-2.5-flash-lite-preview-09-2025': {},
    'groq/llama-3.3-70b-versatile': {},
}
if defs.get('models') != models_allowlist:
    defs['models'] = models_allowlist
    changed = True

set_value(defs, 'workspace', '/home/ubuntu/OpenClawVault')

memory_search = ensure_dict(defs, 'memorySearch')
set_value(memory_search, 'provider', 'local')
set_value(memory_search, 'fallback', 'none')
local_cfg = ensure_dict(memory_search, 'local')
set_value(local_cfg, 'modelCacheDir', '/home/ubuntu/.cache/openclaw/models')
store = ensure_dict(memory_search, 'store')
vector = ensure_dict(store, 'vector')
set_value(vector, 'enabled', True)
query = ensure_dict(memory_search, 'query')
hybrid = ensure_dict(query, 'hybrid')
set_value(hybrid, 'enabled', True)
set_value(hybrid, 'vectorWeight', 0.65)
set_value(hybrid, 'textWeight', 0.35)

compaction = ensure_dict(defs, 'compaction')
set_value(compaction, 'mode', 'safeguard')
set_value(compaction, 'reserveTokensFloor', 20000)
flush_cfg = ensure_dict(compaction, 'memoryFlush')
set_value(flush_cfg, 'enabled', True)
set_value(flush_cfg, 'softThresholdTokens', 4000)
set_value(
    flush_cfg,
    'prompt',
    'Write any lasting notes, rules, facts or preferences to memory/YYYY-MM-DD.md or MEMORY.md. Reply NO_REPLY if nothing to store.'
)

commands = ensure_dict(obj, 'commands')
set_value(commands, 'native', 'auto')
set_value(commands, 'nativeSkills', 'auto')
set_value(commands, 'restart', True)
set_value(commands, 'ownerDisplay', 'raw')

models = ensure_dict(obj, 'models')
providers = ensure_dict(models, 'providers')
if 'opencode' in providers:
    providers.pop('opencode', None)
    changed = True
nvidia = ensure_dict(providers, 'nvidia')
nvidia_models = nvidia.get('models') if isinstance(nvidia.get('models'), list) else []
normalized = []
for item in nvidia_models:
    if not isinstance(item, dict):
        continue
    m = dict(item)
    mid = str(m.get('id') or '').strip()
    if mid == 'zai-org/GLM-5':
        m['id'] = 'z-ai/glm5'
        m['name'] = 'GLM 5 (NVIDIA)'
        changed = True
    normalized.append(m)
if not any(str(x.get('id') or '').strip() == 'z-ai/glm5' for x in normalized):
    normalized.append({
        'id': 'z-ai/glm5',
        'name': 'GLM 5 (NVIDIA)',
        'reasoning': False,
        'input': ['text'],
        'contextWindow': 131072,
        'maxTokens': 8192
    })
    changed = True
if normalized != nvidia_models:
    nvidia['models'] = normalized
    changed = True

out.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('changed=1' if changed else 'changed=0')
if action == '--check' and changed:
    sys.exit(2)
PY
)"
rc=$?

if [ "$ACTION" = "--check" ]; then
  cat "$TMP_OUT" >/dev/null
  rm -f "$TMP_OUT"
  if [ $rc -eq 2 ]; then
    echo "[cloud-coreguard] drift detected"
    exit 2
  fi
  echo "[cloud-coreguard] check ok"
  exit 0
fi

ts="$(date +%Y%m%d-%H%M%S)"
cp -f "$CONFIG_PATH" "$BACKUP_DIR/openclaw.json.bak.$ts"
mv -f "$TMP_OUT" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH" || true

echo "[cloud-coreguard] fixed config ($status), backup=$BACKUP_DIR/openclaw.json.bak.$ts"
