# NetGuard 1.1.0

Rust 核心、Tauri／React 桌面介面與獨立背景服務的個人網路防護工具。

目前開發版號為 1.1.0。只依專案擁有者指示變更版號。既有 Windows 1.0.0 成品保留在原版本目錄。

## Linux x64

Ubuntu 與 Arch Linux 是首批目標。建議使用為該發行版建置的成品。Ubuntu 的安裝需要 systemd、nftables、iproute2。桌面模式還需要 GTK 3、WebKitGTK 4.1、AppIndicator 和可用的 polkit 授權代理。Arch 對應套件為 `nftables`、`iproute2`、`gtk3`、`webkit2gtk-4.1`、`libappindicator-gtk3` 和 `polkit`。

在成品目錄執行 `sudo bash install.sh`。GUI 套件包含命令列工具，CLI 套件可用於無圖形桌面的主機。也可在各發行版依 [Tauri 文件](https://v2.tauri.app/start/prerequisites/) 安裝建置依賴，再從專案根目錄執行下列其中一個命令。

```bash
bash scripts/package-linux.sh gui
bash scripts/package-linux.sh cli
```

成品位於 `release/1.1.0/linux-<發行版>-x64-<模式>/`，附 SHA-256 檢查碼。

`release/` 是本機打包輸出。需要分享成品時，可將套件壓縮後附加至 GitHub Releases。

- **GUI**：從應用程式選單開啟 NetGuard，點選「啟動服務」並授權。GUI 和 CLI 共用 systemd 背景服務及其規則。
- **CLI**：以一般使用者執行以下命令。只有啟動、停止或設定服務開機啟動需要管理員權限。

```bash
sudo systemctl start "netguard@$(id -u).service"
netguard status
netguard observe
netguard export > rules.json
netguard import rules.json
netguard pause
netguard enable
# 選用：開機時啟動服務和防護
sudo systemctl enable "netguard@$(id -u).service"
```

請以同一個登入帳號使用 GUI 和 CLI。這是單人端點防護，IP 封鎖作用於本機輸出流量。Linux 支援 IPv4／IPv6、網段及協定／埠規則，連線畫面提供 TCP 快照。網域、依程式封鎖與即時詢問目前仍有限制，可由 GUI 和 CLI 查詢生效與未支援的規則。

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

從專案根目錄執行 `powershell -NoProfile -File scripts/package-windows.ps1` 打包 Windows x64 開發成品。腳本以 Cargo 工作區的版號建立 `release/<版號>/windows-x64/`。成品包含桌面程式、背景服務及 SHA-256 檢查碼。同版號重建前，請先將既有平台目錄移到備份位置。

開啟版本目錄內的 `netguard-desktop.exe`。保持背景服務執行檔在同一目錄。需要原生防護時，從介面選擇「啟動服務」，接受 Windows 權限提示。程式會等待背景服務回應並啟用防護。若升級前的服務卡住且介面回報管道錯誤 231，請在工作管理員結束舊的 `netguard-agent.exe`，再從新版介面啟動。

手動啟動服務：`netguard-agent --database <設定頁顯示的state.db路徑> --owner <SID或uid>`。加上 `--enable` 才會立即套用規則。關閉 UI 不會停止獨立服務；前景服務可用 Ctrl+C 停止。

## 現況

- Rust 規則核心：IP／CIDR、網域邊界、期限、排序、程序／協定／埠限制。
- SQLite 儲存、匯入匯出、訂閱例外及有限期操作紀錄。
- Windows WFP 動態規則、TCP 快照、限定使用者的 named-pipe 通訊。
- 桌面規則管理、連線活動、服務狀態、設定及手動 DROP 名單更新。
- Ubuntu 24.04 WSL 已建置並啟動 GUI，也已透過隔離網路實測 CLI、原生 IP 封鎖、暫停和停止服務後的復原。Ubuntu 實機上的桌面授權流程與 Arch Linux 的建置及實機驗收仍待確認。
- macOS Network Extension 尚未實作完成，後端會明確回報不可用。
- 原生網域攔截、即時詢問、位元組計量、自動名單更新及正式開機服務安裝尚未完成。

網域與詢問規則可保存，但不代表原生生效。無法原生執行的允許規則會拒絕套用，避免略過白名單後意外封鎖。TCP 快照可能漏過短連線，不代表完整流量監控。

Spamhaus DROP 資料歸屬 The Spamhaus Project；下載須遵守其 [使用條款](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)。安裝檔沒有內嵌第三方名單；手動更新匯入的指標有效 48 小時。

正式 release 仍須完成設計文件列出的三平台、權限、故障恢復、簽章及共存驗收。不能以單元測試或單一平台編譯成功代替。
