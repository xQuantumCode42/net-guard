use crate::{now, Policy};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
pub struct Store {
    conn: Connection,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub at: i64,
    pub kind: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub schema_version: u32,
    pub policy: Policy,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA max_page_count=24000; CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, at INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL); PRAGMA user_version=1;").map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }
    pub fn load_policy(&self) -> Result<Policy, String> {
        use rusqlite::OptionalExtension;
        let json: Option<String> = self
            .conn
            .query_row("SELECT value FROM config WHERE key='policy'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;
        let policy: Policy = match json {
            Some(j) => serde_json::from_str(&j).map_err(|e| e.to_string())?,
            None => Policy::default(),
        };
        policy.validate()?;
        Ok(policy)
    }
    pub fn save_policy(&self, policy: &Policy) -> Result<(), String> {
        policy.validate()?;
        let json = serde_json::to_string(policy).map_err(|e| e.to_string())?;
        if json.len() > 8 * 1024 * 1024 {
            return Err("規則資料超過 8 MB".into());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO config(key,value) VALUES('policy',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [json]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn import(&self, text: &str) -> Result<Policy, String> {
        if text.len() > 8 * 1024 * 1024 {
            return Err("匯入檔案超過 8 MB".into());
        }
        let export: Export =
            serde_json::from_str(text).map_err(|e| format!("匯入格式錯誤：{e}"))?;
        if export.schema_version != 1 {
            return Err("不支援的設定格式版本".into());
        }
        self.save_policy(&export.policy)?;
        Ok(export.policy)
    }
    pub fn export(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&Export {
            schema_version: 1,
            policy: self.load_policy()?,
        })
        .map_err(|e| e.to_string())
    }
    pub fn append_event(&self, event: &Event) -> Result<(), String> {
        if event.message.len() > 4096 || event.kind.len() > 100 {
            return Err("事件過長".into());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO events(at,kind,message) VALUES(?1,?2,?3)",
            params![event.at, event.kind, event.message],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM events WHERE at < ?1 OR id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 15000)", [now() - 7 * 86400]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    pub fn events(&self, limit: usize) -> Result<Vec<Event>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT at,kind,message FROM events WHERE at >= ?1 ORDER BY id DESC LIMIT ?2")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![now() - 7 * 86400, limit.min(1000) as i64], |r| {
                Ok(Event {
                    at: r.get(0)?,
                    kind: r.get(1)?,
                    message: r.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn clear_events(&self) -> Result<(), String> {
        self.conn
            .execute("DELETE FROM events", [])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}
