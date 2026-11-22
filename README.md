# NetGuard

NetGuard 是本機網路防護工具。你可以從桌面介面查看目前的 TCP 連線、設定 IP 或網段黑白名單，以及查看哪些規則已生效。Linux 也提供命令列工具，適合沒有圖形桌面的主機。

**v1.1.1 使用指南審閱稿。** 以下步驟依目前儲存庫提供的版本撰寫。Windows 成品為 `1.0.0`，Linux 原始碼目前會建置 `1.1.0`。

## 先選你的作業系統

| 系統 | 使用方式 | 目前狀態 |
| --- | --- | --- |
| [Windows x64](#windows-x64) | 開啟現成的桌面程式 | 儲存庫提供 `1.0.0` 成品 |
| [Ubuntu x64](#ubuntu-x64) | 從原始碼建置 GUI 或純 CLI | Ubuntu 24.04 WSL 已驗證 GUI 啟動及 CLI 封鎖流程 |
| [Arch Linux x64](#arch-linux-x64) | 從原始碼建置 GUI 或純 CLI | 打包腳本已接受 Arch Linux，建置與實機驗收待完成 |
| [openSUSE](#opensuse) | 查看支援進度 | 目前無安裝包，打包腳本尚未支援 |

**第一次取得專案**可執行 `git clone https://github.com/xQuantumCode42/net-guard.git`，再進入 `net-guard` 目錄。已有專案時，在原本目錄執行 `git pull`。

Git 帶回原始碼與打包腳本，也包含已收錄的 Windows 成品。Linux 的 `release/` 成品由打包腳本產生。若之後有對應平台的安裝包，可從 [GitHub Releases](https://github.com/xQuantumCode42/net-guard/releases) 下載並跳過建置。

## Windows x64

1. 開啟 [`release/1.0.0/windows-x64/`](release/1.0.0/windows-x64)，確認 `netguard-desktop.exe` 與 `netguard-agent.exe` 在同一個目錄。
2. 雙擊 `netguard-desktop.exe`。
3. 在「防護總覽」點選「啟動服務」，接受 Windows 的管理員授權。
4. 介面顯示「原生防護已啟用」後，前往「規則管理」新增封鎖規則，或從「威脅名單」載入 IP 網段名單。若生效規則是 0 條，目前沒有 NetGuard 規則在封鎖連線。

如需自己建置，先安裝 Rust、Node.js、Visual Studio C++ Build Tools 和 WebView2，再於專案根目錄執行 `powershell -NoProfile -File scripts/package-windows.ps1`。成品會放到 `release/<版本>/windows-x64/`。可參考 [Tauri 的 Windows 建置需求](https://v2.tauri.app/start/prerequisites/#windows)。

## Ubuntu x64

使用 systemd 的 Ubuntu。純 CLI 需要 Rust 1.90、C 編譯工具、`nftables` 與 `iproute2`。GUI 另需 Node.js 20 以上、GTK 3、WebKitGTK 4.1、AppIndicator 開發套件，以及桌面環境的 polkit 授權代理與 `pkexec`。請參考 [Tauri 的 Debian／Ubuntu 建置需求](https://v2.tauri.app/start/prerequisites/#debian)。

在專案根目錄擇一執行：

| 用途 | 建置指令 | 目前成品目錄 |
| --- | --- | --- |
| 桌面 GUI，含 CLI | `bash scripts/package-linux.sh gui` | `release/1.1.0/linux-ubuntu-x64-gui/` |
| 伺服器或純終端機 | `bash scripts/package-linux.sh cli` | `release/1.1.0/linux-ubuntu-x64-cli/` |

建置完成後，進入成品目錄並執行 `sudo bash install.sh`。安裝後參考下方的 [Linux 日常操作](#linux-日常操作)。

## Arch Linux x64

使用 systemd 的 Arch Linux。純 CLI 需要 Rust 1.90、`base-devel`、`nftables` 與 `iproute2`。GUI 另需 Node.js 20 以上與 Tauri 的 Arch 開發套件，例如 `webkit2gtk-4.1` 和 `libappindicator-gtk3`，以及可用的 polkit 授權代理與 `pkexec`。請參考 [Tauri 的 Arch Linux 建置需求](https://v2.tauri.app/start/prerequisites/#arch)。

這是尚待驗收的從原始碼建置方式。在 Arch 主機的專案根目錄執行 `bash scripts/package-linux.sh gui` 或 `bash scripts/package-linux.sh cli`。建置成功後，進入 `release/1.1.0/linux-arch-x64-gui/` 或 `release/1.1.0/linux-arch-x64-cli/`，執行 `sudo bash install.sh`，再參考 [Linux 日常操作](#linux-日常操作)。

## openSUSE

openSUSE 是預定支援的平台。現有 NetGuard 打包腳本只接受 Ubuntu 與 Arch Linux，因此目前沒有可供 openSUSE 使用者照做的安裝流程。openSUSE 上的套件相依性、桌面授權與實際封鎖仍待驗證。可從 [GitHub Releases](https://github.com/xQuantumCode42/net-guard/releases) 查看之後是否提供對應的成品。

## Linux 日常操作

**桌面使用者**從應用程式選單開啟 NetGuard，點選「啟動服務」並完成系統授權。接著可在「規則管理」新增或調整規則。

**命令列使用者**在自己的帳號下執行下列指令。啟動 systemd 服務需要 `sudo`，平時使用 `netguard` 時請保留在原本的帳號。

```bash
sudo systemctl start "netguard@$(id -u).service"
netguard status
netguard observe
```

| 想做什麼 | 指令 |
| --- | --- |
| 暫停／恢復防護 | `netguard pause` ／ `netguard enable` |
| 匯出／匯入規則 | `netguard export > rules.json` ／ `netguard import rules.json` |
| 設定開機啟動 | `sudo systemctl enable "netguard@$(id -u).service"` |
| 查看服務啟動失敗原因 | `journalctl -u "netguard@$(id -u).service" -n 50 --no-pager` |

GUI 與 CLI 在同一個帳號下使用同一份服務規則。匯入設定會取代整份規則，匯入前可先匯出備份。關閉桌面視窗後，背景服務會繼續執行。

## 使用時要知道

- **連線畫面是 TCP 快照。** 短時間連線可能漏過，加密 HTTPS 的完整網址與內容不會顯示。
- **Linux 可執行 IP 與網段的原生封鎖。** 目前 Linux 的依程式封鎖、原生網域攔截和即時詢問尚未提供。請以介面或 CLI 回報的生效規則為準。
- **威脅名單需要手動載入或更新。** 目前使用 Spamhaus DROP 的高風險 IP 網段，資料歸屬 The Spamhaus Project。請參考 [Spamhaus DROP 使用條款](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)。

## 回報問題與參與開發

歡迎使用者與共同開發者提供意見。安裝卡在哪一步、哪個畫面不好懂、某個發行版的測試結果，以及希望增加的功能，都可以分享。即使沒有準備程式碼，也能先在 Issue 討論。

### 建立 Issue

1. 到 [GitHub Issues](https://github.com/xQuantumCode42/net-guard/issues) 搜尋是否已有相同的問題或提案。有的話，可以在原 Issue 補充資訊。
2. 選擇 **New issue**，用標題寫出遇到的問題或想改善的功能。
3. 若回報錯誤，請附上作業系統與版本、NetGuard 版本、使用 GUI 或 CLI、重現步驟、預期結果及實際錯誤。若提出建議，請說明使用情境，以及希望怎麼改善。貼上日誌前，請移除個資、金鑰及不想公開的網路資訊。
4. 選擇 **Create** 提交。可參考 [GitHub 建立 Issue 的說明](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-an-issue)。

### 提交 Pull Request（PR）

1. Fork 專案，從 `master` 建立工作分支，完成修改後推送到自己的 fork。請將 `target/` 和 `release/` 的建置成品留在本機。
2. 完成修改後，依變更範圍執行檢查。Rust 可執行 `cargo test --locked`；若修改 GUI，可在 `apps/desktop/` 執行 `npm ci` 和 `npm test`。如果涉及平台行為，請記下你實際測過的系統。
3. 到 [Pull requests](https://github.com/xQuantumCode42/net-guard/pulls) 開啟 PR，目標分支選原儲存庫的 `master`。
4. 說明要解決的問題、修改內容與驗證結果，並附上相關 Issue 編號。還想討論方向時，可以先開 Draft PR。可參考 [GitHub 從 fork 建立 PR 的說明](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork)。
