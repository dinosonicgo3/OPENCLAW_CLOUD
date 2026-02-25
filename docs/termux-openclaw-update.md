# Termux OpenClaw 更新說明（核心流程）

本檔案是手機端 OpenClaw 的正式更新說明，對應核心腳本：

- `scripts/termux-main-system-update.sh`

## 一鍵更新（建議）

```bash
ocupdate
```

或直接執行：

```bash
bash ~/DINO_OPENCLAW/scripts/termux-main-system-update.sh
```

指定版本（例如 2026.2.24）：

```bash
OPENCLAW_NPM_TARGET=2026.2.24 FORCE_NPM_UPDATE=1 bash ~/DINO_OPENCLAW/scripts/termux-main-system-update.sh
```

## 強制 npm 更新（當版本卡住）

```bash
ocupdate_force
```

等價於：

```bash
FORCE_NPM_UPDATE=1 bash ~/DINO_OPENCLAW/scripts/termux-main-system-update.sh
```

## 核心更新邏輯（腳本內建）

1. 啟動 watchdog 維護握手（避免更新期被誤判救援）。
2. 建立快照備份（`~/backups/openclaw-state-*.tar.gz`）。
3. 先跑 `openclaw update --yes`。
4. 自動比對目前版本 vs npm 最新版。
5. 若未達最新版或 update 失敗，自動走 Termux 專用 npm fallback：
   `npm install -g openclaw@<latest> --prefix ~/.npm-global --ignore-scripts`
6. 執行 `openclaw doctor --fix`。
7. 重啟 gateway 並做健康檢查。
8. 成功才送出維護完成握手；失敗則請 watchdog 啟動救援。
9. 若 30 分鐘內未完成握手，watchdog 會依規則自動回滾。

## 為什麼 fallback 用 `--ignore-scripts`

Termux 上偶發 native postinstall 編譯失敗（例如 `koffi` 類型問題）會中斷更新。  
`--ignore-scripts` 可降低這類失敗，優先確保 OpenClaw 主程式可用與可回復。

## 重要檔案

- 更新日誌：`~/openclaw-logs/main-system-update.log`
- 更新前狀態：`~/tmp/openclaw-update-status-before.json`
- update 結果：`~/tmp/openclaw-update-result.json`
- watchdog 狀態：`~/.openclaw-watchdog/state.json`

## 更新前後建議檢查

```bash
openclaw -V
openclaw health
tmux ls
tail -n 80 ~/openclaw-logs/main-system-update.log
```
