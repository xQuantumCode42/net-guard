use netguard_core::Policy;
use netguard_platform::{ApplyReport, Capability};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    Status,
    GetPolicy,
    Apply { policy: Policy },
    Pause,
    Resume,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub connected: bool,
    pub active: bool,
    pub version: String,
    pub platform: String,
    pub report: ApplyReport,
    pub capabilities: Vec<Capability>,
    pub error: Option<String>,
}
impl Status {
    pub fn offline(error: impl Into<String>) -> Self {
        Self {
            connected: false,
            active: false,
            version: env!("CARGO_PKG_VERSION").into(),
            platform: std::env::consts::OS.into(),
            report: ApplyReport::default(),
            capabilities: netguard_platform::capabilities(),
            error: Some(error.into()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: Status,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}
pub fn read_message<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let size = u32::from_le_bytes(prefix) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err("訊息大小不合法".into());
    }
    let mut data = vec![0u8; size];
    reader.read_exact(&mut data).map_err(|e| e.to_string())?;
    serde_json::from_slice(&data).map_err(|e| e.to_string())
}
pub fn write_message(writer: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("訊息大小超過限制".into());
    }
    writer
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .map_err(|e| e.to_string())
}
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::{identity, request, serve};
#[cfg(windows)]
pub use windows::{identity, request, serve};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_oversize_rejection() {
        let mut wire = Vec::new();
        write_message(&mut wire, &Request::Pause).unwrap();
        assert!(matches!(
            read_message::<Request>(&mut wire.as_slice()).unwrap(),
            Request::Pause
        ));
        assert!(
            read_message::<Request>(&mut ((MAX_MESSAGE + 1) as u32).to_le_bytes().as_slice())
                .unwrap_err()
                .contains("大小")
        );
    }
    #[test]
    fn malformed_or_truncated_commands_cannot_execute() {
        for wire in [vec![1, 0, 0, 0, b'{'], vec![20, 0, 0, 0], vec![0, 0, 0, 0]] {
            assert!(read_message::<Request>(&mut wire.as_slice()).is_err());
        }
    }
}
