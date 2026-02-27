#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
CFG="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
API_KEY="${NVIDIA_API_KEY:-}"

if [ -z "$API_KEY" ] && [ -f "$CFG" ] && command -v jq >/dev/null 2>&1; then
  API_KEY="$(jq -r '.models.providers.nvidia.apiKey // empty' "$CFG" 2>/dev/null || true)"
fi

if [ -z "$API_KEY" ]; then
  echo "[nvidia-model-catalog] missing NVIDIA_API_KEY and config apiKey" >&2
  exit 1
fi

resp="$(curl -fsS https://integrate.api.nvidia.com/v1/models -H "Authorization: Bearer $API_KEY")"

echo "# NVIDIA model ids"
echo "$resp" | jq -r '.data[]?.id' | sort -u

echo
if echo "$resp" | jq -e '.data[]? | select(.id=="z-ai/glm5")' >/dev/null; then
  echo "[ok] canonical GLM-5 id available: z-ai/glm5"
else
  echo "[warn] canonical GLM-5 id z-ai/glm5 not returned by NVIDIA API" >&2
  exit 2
fi