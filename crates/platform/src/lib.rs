use netguard_core::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub available: bool,
    pub detail: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyReport {
    pub applied: usize,
    pub unsupported: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct NativePlan {
    pub rules: Vec<Rule>,
    pub report: ApplyReport,
}
pub fn compile_policy(policy: &Policy, now: i64, platform: &str) -> Result<NativePlan, String> {
    policy.validate()?;
    let mut plan = NativePlan {
        rules: vec![],
        report: ApplyReport::default(),
    };
    for rule in policy.active_rules(now) {
        let unsupported = matches!(rule.target, Target::Domain(_) | Target::Subdomains(_))
            || rule.action == Action::Ask
            || (platform == "linux" && rule.program.is_some());
        if unsupported {
            if rule.action == Action::Allow {
                return Err(format!(
                    "平台無法執行允許規則「{}」，為避免錯誤封鎖，保留原規則",
                    rule.name
                ));
            }
            plan.report.unsupported.push(rule.id.clone());
        } else {
            plan.rules.push(rule.clone());
        }
    }
    plan.report.applied = plan.rules.len();
    Ok(plan)
}
pub fn nft_script(plan: &NativePlan, table: &str) -> Result<String, String> {
    if !table.starts_with("netguard_")
        || table.len() > 64
        || !table
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Err("無效的專用 table 名稱".into());
    }
    let mut script = format!("flush chain inet {table} output\nflush set inet {table} lease\nadd element inet {table} lease {{ ipv4 timeout 5s, ipv6 timeout 5s }}\n");
    for r in &plan.rules {
        let mut terms = Vec::new();
        match &r.target {
            Target::Ip(ip) => terms.push(format!(
                "{} daddr {ip}",
                if ip.is_ipv4() { "ip" } else { "ip6" }
            )),
            Target::Network(net) => terms.push(format!(
                "{} daddr {net}",
                if matches!(net, ipnet::IpNet::V4(_)) {
                    "ip"
                } else {
                    "ip6"
                }
            )),
            Target::Any => {}
            _ => return Err("不支援的原生網域規則".into()),
        }
        if r.program.is_some() {
            return Err("此 nftables 後端尚不支援依程式匹配".into());
        }
        if let Some(p) = r.protocol {
            terms.push(format!("meta l4proto {p}"));
        }
        if let Some(p) = r.port {
            terms.push(format!("th dport {p}"));
        }
        let verdict = match r.action {
            Action::Allow => "return",
            Action::Block => "drop",
            Action::Ask => return Err("詢問模式需要即時事件後端".into()),
        };
        script.push_str(&format!(
            "add rule inet {table} output meta nfproto @lease {} counter {verdict}\n",
            terms.join(" ")
        ));
    }
    Ok(script)
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
pub use linux::{observe, Backend};
#[cfg(target_os = "macos")]
pub use macos::{observe, Backend};
#[cfg(windows)]
pub use windows::{observe, Backend};

pub fn capabilities() -> Vec<Capability> {
    vec![
        Capability {
            name: "IP / CIDR 封鎖".into(),
            available: cfg!(any(windows, target_os = "linux")),
            detail: "需啟動具有系統權限的原生服務；僅涵蓋支援的網路路徑".into(),
        },
        Capability {
            name: "依程式封鎖".into(),
            available: cfg!(windows),
            detail: "Windows WFP 支援完整程式路徑；其他平台待驗證".into(),
        },
        Capability {
            name: "連線觀察".into(),
            available: cfg!(any(windows, target_os = "linux")),
            detail: "TCP 快照可能漏過短連線；不代表連線前事件或完整流量紀錄".into(),
        },
        Capability {
            name: "網域攔截 / 即時詢問".into(),
            available: false,
            detail: "目前只提供規則判斷測試；DNS 與即時事件後端尚未啟用".into(),
        },
        Capability {
            name: "上下載位元組統計".into(),
            available: false,
            detail: "尚未接上原生計量，不以連線數推算流量".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(id: &str, target: Target, action: Action) -> Rule {
        Rule {
            id: id.into(),
            name: id.into(),
            target,
            action,
            enabled: true,
            program: None,
            protocol: None,
            port: None,
            expires_at: None,
            source: None,
        }
    }
    #[test]
    fn unsupported_allow_must_not_silently_turn_into_deny() {
        let p = Policy {
            rules: vec![
                rule(
                    "domain",
                    Target::Domain("safe.example".into()),
                    Action::Allow,
                ),
                rule("block", Target::Any, Action::Block),
            ],
            ..Default::default()
        };
        assert!(compile_policy(&p, 1, "windows").is_err());
    }
    #[test]
    fn unsupported_blocks_are_reported_and_expiry_removed() {
        let mut r = rule("expired", Target::Any, Action::Allow);
        r.expires_at = Some(1);
        let p = Policy {
            rules: vec![
                r,
                rule(
                    "domain",
                    Target::Domain("bad.example".into()),
                    Action::Block,
                ),
                rule(
                    "ip",
                    Target::Ip("192.0.2.1".parse().unwrap()),
                    Action::Block,
                ),
            ],
            ..Default::default()
        };
        let plan = compile_policy(&p, 1, "windows").unwrap();
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.rules[0].id, "ip");
        assert_eq!(plan.report.unsupported, vec!["domain"]);
    }
    #[test]
    fn linux_rules_preserve_order_and_never_flush_global_ruleset() {
        let p = Policy {
            rules: vec![
                rule(
                    "allow",
                    Target::Ip("192.0.2.1".parse().unwrap()),
                    Action::Allow,
                ),
                rule(
                    "deny",
                    Target::Network("192.0.2.0/24".parse().unwrap()),
                    Action::Block,
                ),
            ],
            ..Default::default()
        };
        let s = nft_script(&compile_policy(&p, 1, "linux").unwrap(), "netguard_test").unwrap();
        assert!(s.contains("ip daddr 192.0.2.1 counter return"));
        assert!(s.contains("ip daddr 192.0.2.0/24 counter drop"));
        assert!(s.find("192.0.2.1 ").unwrap() < s.find("192.0.2.0/24").unwrap());
        assert!(!s.contains("flush ruleset"));
        assert!(nft_script(&compile_policy(&p, 1, "linux").unwrap(), "x; flush ruleset").is_err());
    }
}
