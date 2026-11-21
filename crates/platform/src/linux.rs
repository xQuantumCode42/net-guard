use super::*;
use std::{
    io::Write,
    process::{Command, Stdio},
};
pub struct Backend {
    table: String,
}
fn run(script: &str) -> Result<(), String> {
    let mut child = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("無法開啟 nft stdin")?
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let result = child.wait_with_output().map_err(|e| e.to_string())?;
    if result.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&result.stderr).into_owned())
    }
}
impl Backend {
    pub fn new() -> Result<Self, String> {
        let table = format!("netguard_{}", std::process::id());
        run(&format!("add table inet {table}\nadd set inet {table} lease {{ type nf_proto; flags timeout; timeout 5s; }}\nadd chain inet {table} output {{ type filter hook output priority 10; policy accept; }}\n"))?;
        Ok(Self { table })
    }
    pub fn apply(&mut self, policy: &Policy) -> Result<ApplyReport, String> {
        let plan = compile_policy(policy, now(), "linux")?;
        // nft applies the full batch atomically. No global flush and no shell.
        run(&nft_script(&plan, &self.table)?)?;
        Ok(plan.report)
    }
    pub fn stop(&mut self) {
        if !self.table.is_empty() {
            let _ = run(&format!("delete table inet {}\n", self.table));
            self.table.clear();
        }
    }
    pub fn tick(&mut self) -> Result<(), String> {
        run(&format!("flush set inet {} lease\nadd element inet {} lease {{ ipv4 timeout 5s, ipv6 timeout 5s }}\n", self.table, self.table))
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}
pub fn observe() -> Result<Vec<Flow>, String> {
    let output = Command::new("ss")
        .args(["-H", "-t", "-n", "-p", "state", "connected"])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let mut flows = vec![];
    for line in String::from_utf8_lossy(&output.stdout).lines().take(10000) {
        let cols: Vec<_> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        // ss with an explicit state filter omits its state column.
        let remote = cols[3];
        if let Some((addr, port)) = remote.rsplit_once(':') {
            if let (Ok(ip), Ok(port)) = (addr.trim_matches(['[', ']']).parse(), port.parse()) {
                flows.push(Flow {
                    remote_ip: ip,
                    remote_port: port,
                    protocol: 6,
                    program: None,
                    pid: None,
                    hostname: None,
                    observed_at: now(),
                    state: "observed".into(),
                });
            }
        }
    }
    Ok(flows)
}
