# OpenClaw 手機端 (Termux)

這是獨立於 PC 主專案的手機端部署倉庫，包含：

- `scripts/termux-rebuild-openclaw.sh`: 手機端一鍵重建
- `scripts/termux-openclaw-watchdog.sh`: 看門狗監控 + 自動救援
- `scripts/termux-main-system-update.sh`: 手機端主系統安全更新核心
- `scripts/termux-obsidian-integrate.sh`: Obsidian Vault 整合
- `docs/termux-rebuild.md`: 重建流程
- `docs/termux-openclaw-update.md`: 手機端 OpenClaw 更新說明
- `docs/termux-main-system-update-policy.md`: 主系統更新規範
- `docs/termux-watchdog.md`: 看門狗與握手協議
- `docs/termux-obsidian.md`: Obsidian 整合說明
- `docs/termux-repair-flow.md`: 手機端核心修復流程（防遺失）

## 目標

- 手機開機自啟 OpenClaw
- 每 30 分鐘健康檢查
- Telegram `/helpdog` 緊急救援
- `更新主系統` / `更新成功` 握手保護更新視窗
- 備援模型切換 Telegram 通知
- 已確認不可用模型 24h 熔斷（避免重複浪費）
- 逾時自動回滾最近 `穩定版*` 標籤並重建
