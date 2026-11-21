# 1.0.0 發佈驗收

狀態：開發中，未發佈。版號只依使用者指示更新。

## 2026-11-21 驗證紀錄

- Windows debug 桌面與 agent 建置成功，agent 回報版本 1.0.0。
- Rust 一般測試 15 項通過；UI 行為測試 3 項通過；前端 production build 通過。
- 版號一致性檢查通過；總覽與規則編輯器瀏覽器檢查無執行錯誤，截圖位於 `.local/`。
- 額外執行 WFP loopback 原生測試失敗：建立 WFP session 回傳 0x5（Access denied），目前權杖不是管理員。這不是封鎖驗證通過；需以管理員終端執行 `cargo test -p netguard-platform --test wfp_loopback -- --ignored`。
- 桌面完整操作與背景服務通訊仍需後續驗證。產出的 debug 執行檔不可視為正式簽章 release。

| 平台 | 現況 |
| --- | --- |
| Windows | WFP、服務、UI 已有程式碼，持續建置與原生驗證 |
| macOS 最新正式版 | Network Extension 實作、簽章與實機驗證未完成 |
| Ubuntu 最新 LTS | nftables 後端尚待實機測試 |
| Arch Linux | nftables 後端尚待實機測試 |

尚未完成：原生網域／DNS 攔截、即時詢問通知閉環、完整連線事件、位元組計量、自動名單更新、開機服務安裝及故障復原驗證。

以上仍屬 1.0.0 的待辦，並非從已核准設計刪除需求。獨立程式碼審閱曾因代理額度限制未完成，不可聲稱已通過審閱。
