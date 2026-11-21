use super::*;
pub struct Backend;
impl Backend {
    pub fn new() -> Result<Self, String> {
        Err("macOS Network Extension 尚未簽章、安裝與驗證；防護未啟用".into())
    }
    pub fn apply(&mut self, _: &Policy) -> Result<ApplyReport, String> {
        Err("需要已驗證的 Network Extension".into())
    }
    pub fn stop(&mut self) {}
    pub fn tick(&mut self) -> Result<(), String> {
        Ok(())
    }
}
pub fn observe() -> Result<Vec<Flow>, String> {
    Err("macOS 流量事件需由已啟用的 Network Extension 提供".into())
}
