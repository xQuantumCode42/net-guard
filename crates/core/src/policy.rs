use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
    Ask,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Target {
    Any,
    Ip(IpAddr),
    Network(ipnet::IpNet),
    Domain(String),
    Subdomains(String),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub target: Target,
    pub action: Action,
    pub enabled: bool,
    pub program: Option<String>,
    pub protocol: Option<u8>,
    pub port: Option<u16>,
    pub expires_at: Option<i64>,
    pub source: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub exclusions: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: u8,
    pub program: Option<String>,
    pub pid: Option<u32>,
    pub hostname: Option<String>,
    pub observed_at: i64,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub rule_id: Option<String>,
    pub reason: String,
}
impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        if self.rules.len() > 50_000 || self.exclusions.len() > 50_000 {
            return Err("規則數量超過 50,000".into());
        }
        let mut ids = std::collections::HashSet::new();
        for r in &self.rules {
            if r.id.is_empty() || r.id.len() > 200 || !ids.insert(&r.id) {
                return Err("規則 ID 為空、過長或重複".into());
            }
            if r.name.trim().is_empty() || r.name.len() > 300 {
                return Err("請提供不超過 300 bytes 的規則名稱".into());
            }
            if r.program
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > 4096 || p.contains(['\0', '\n', '\r']))
            {
                return Err("無效的程式路徑".into());
            }
            if r.port == Some(0) || (r.port.is_some() && !matches!(r.protocol, Some(6 | 17))) {
                return Err("連接埠需搭配 TCP 或 UDP，範圍為 1–65535".into());
            }
            if let Target::Domain(d) | Target::Subdomains(d) = &r.target {
                normalize_domain(d)?;
            }
            if r.source.as_ref().is_some_and(|s| s.len() > 100) {
                return Err("來源名稱過長".into());
            }
        }
        Ok(())
    }
    pub fn active_rules(&self, now: i64) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.source.is_none())
            .chain(self.rules.iter().filter(|r| r.source.is_some()))
            .filter(|r| {
                r.enabled
                    && r.expires_at.is_none_or(|t| t > now)
                    && !(r.source.is_some() && self.exclusions.contains(&r.id))
            })
            .collect()
    }
    pub fn evaluate(&self, flow: &Flow, now: i64) -> Decision {
        for r in self.active_rules(now) {
            if r.program
                .as_ref()
                .is_some_and(|p| flow.program.as_ref() != Some(p))
                || r.protocol.is_some_and(|p| p != flow.protocol)
                || r.port.is_some_and(|p| p != flow.remote_port)
            {
                continue;
            }
            let matched = match &r.target {
                Target::Any => true,
                Target::Ip(ip) => ip == &flow.remote_ip,
                Target::Network(net) => net.contains(&flow.remote_ip),
                Target::Domain(d) | Target::Subdomains(d) => {
                    match (
                        normalize_domain(d),
                        flow.hostname
                            .as_deref()
                            .and_then(|h| normalize_domain(h).ok()),
                    ) {
                        (Ok(d), Some(h)) => {
                            h == d
                                || (matches!(r.target, Target::Subdomains(_))
                                    && h.ends_with(&format!(".{d}")))
                        }
                        _ => false,
                    }
                }
            };
            if matched {
                return Decision {
                    action: r.action,
                    rule_id: Some(r.id.clone()),
                    reason: r.name.clone(),
                };
            }
        }
        Decision {
            action: Action::Allow,
            rule_id: None,
            reason: "default".into(),
        }
    }
}

pub fn normalize_domain(input: &str) -> Result<String, String> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.trim() != name || name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return Err("請輸入網域名稱，而非 IP 或網址".into());
    }
    let ascii = idna::domain_to_ascii_strict(name)
        .map_err(|_| "無效的網域名稱")?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("無效的網域名稱".into());
    }
    Ok(ascii)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
