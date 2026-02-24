# 手機端核心修復流程（防遺失）

本文件定義 OpenClaw 手機端在 Termux 的「標準修復流程」。
目標是：即使更新中斷、看門狗回滾、或配置飄移，也能把系統拉回可用狀態。

## 核心原則

1. `gateway` 必須可在 `bind=lan` 下啟動。
2. `memorySearch` 必須固定為本地記憶（不走 remote）。
3. 修復流程要能被重複執行，且不破壞 Obsidian/workspace。
4. 修復腳本要內建於核心，避免只存在聊天紀錄。

## 已寫入核心腳本

1. `scripts/termux-openclaw-core-guard.sh`
2. `scripts/termux-rebuild-openclaw.sh`
3. `scripts/termux-openclaw-watchdog.sh`
4. `scripts/termux-main-system-update.sh`

## 自動修復內容

### A. Gateway 啟動安全（2026.2.23 相容）

`core-guard`/`rebuild` 會確保：

- `gateway.bind = "lan"` 時仍可啟動
- `gateway.auth.mode = "token"` 且 token 存在
- `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = true`

這可避免 `Gateway failed to start` 的 controlUi 相容問題。

### B. 記憶固定本地化

核心會強制：

- `agents.defaults.memorySearch.provider = "local"`
- `agents.defaults.memorySearch.fallback = "none"`
- `agents.defaults.memorySearch.local.modelPath = EmbeddingGemma-300M`
- `agents.defaults.memorySearch.local.modelCacheDir = ~/.cache/openclaw/models`
- 刪除 `.agents.defaults.memorySearch.remote`

watchdog 的 self-check 也會持續校正，避免被舊配置覆蓋。

### C. 更新失敗時回復機制

`termux-main-system-update.sh` 採雙路更新：

1. 先嘗試 `openclaw update`
2. 失敗時改用 `npm install -g openclaw@<target> --ignore-scripts`

並在流程中做 maintenance 握手，失敗則觸發救援。

## 手動執行標準修復（必要時）

```bash
cd ~/DINO_OPENCLAW
bash scripts/termux-openclaw-core-guard.sh --fix
bash scripts/termux-rebuild-openclaw.sh
bash scripts/termux-openclaw-watchdog.sh --baseline-refresh
bash scripts/termux-openclaw-watchdog.sh --selfcheck
```

## 驗證點

```bash
openclaw --version
openclaw health
jq '.gateway,.agents.defaults.memorySearch' ~/.openclaw/openclaw.json
```

健康標準：

1. `openclaw health` 通過
2. `memorySearch.provider` 為 `local`
3. `gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true`

