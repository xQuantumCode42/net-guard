# NetGuard 1.0.0

Rust 核心、Tauri／React 桌面介面與獨立背景服務的個人網路防護工具。

目前為開發中版本，尚未達成正式 release 條件。版號固定為 1.0.0，之後只依專案擁有者指示變更。

## 建置

需求：Rust 1.90、Node 20.16 以上、Windows Visual Studio C++ 工具與 WebView2。

```powershell
cd apps/desktop
npm ci
npm test
npm run build
cd ../..
cargo test
cargo build -p netguard-desktop -p netguard-agent
```

從專案根目錄執行 `powershell -NoProfile -File scripts/package-windows.ps1` 打包 Windows x64 開發成品。腳本以 Cargo 工作區的版號建立 `release/<版號>/windows-x64/`，目前為 `release/1.0.0/windows-x64/`。成品包含桌面程式、背景服務及 SHA-256 檢查碼。同版號重建前，請先將既有平台目錄移到備份位置。

開啟版本目錄內的 `netguard-desktop.exe`。保持背景服務執行檔在同一目錄。需要原生防護時，從介面選擇「啟動服務」，接受 Windows 權限提示。程式會等待背景服務回應並啟用防護。若升級前的服務卡住且介面回報管道錯誤 231，請在工作管理員結束舊的 `netguard-agent.exe`，再從新版介面啟動。

手動啟動服務：`netguard-agent --database <設定頁顯示的state.db路徑> --owner <SID或uid>`。加上 `--enable` 才會立即套用規則。關閉 UI 不會停止獨立服務；前景服務可用 Ctrl+C 停止。

## 現況

- Rust 規則核心：IP／CIDR、網域邊界、期限、排序、程序／協定／埠限制。
- SQLite 儲存、匯入匯出、訂閱例外及有限期操作紀錄。
- Windows WFP 動態規則、TCP 快照、限定使用者的 named-pipe 通訊。
- 桌面規則管理、連線活動、服務狀態、設定及手動 DROP 名單更新。
- Linux nftables 程式碼尚待 Ubuntu／Arch 實機驗證。
- macOS Network Extension 尚未實作完成，後端會明確回報不可用。
- 原生網域攔截、即時詢問、位元組計量、自動名單更新及正式開機服務安裝尚未完成。

網域與詢問規則可保存，但不代表原生生效。無法原生執行的允許規則會拒絕套用，避免略過白名單後意外封鎖。TCP 快照可能漏過短連線，不代表完整流量監控。

Spamhaus DROP 資料歸屬 The Spamhaus Project；下載須遵守其 [使用條款](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)。安裝檔沒有內嵌第三方名單；手動更新匯入的指標有效 48 小時。

正式 release 仍須完成設計文件列出的三平台、權限、故障恢復、簽章及共存驗收。不能以單元測試或單一平台編譯成功代替。
