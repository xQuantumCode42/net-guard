use crate::{Action, Rule, Target};
pub fn parse_drop(text: &str) -> Result<Vec<Rule>, String> {
    if text.len() > 8 * 1024 * 1024 {
        return Err("名單超過 8 MB".into());
    }
    let mut rules = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| format!("第 {} 行不是有效 JSON", index + 1))?;
        if value.get("type").and_then(|v| v.as_str()) == Some("metadata") {
            continue;
        }
        let cidr = value
            .get("cidr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("第 {} 行缺少 cidr", index + 1))?;
        let net: ipnet::IpNet = cidr.parse().map_err(|_| format!("無效 CIDR：{cidr}"))?;
        if net.prefix_len() == 0 {
            return Err("訂閱不能包含全網段 /0".into());
        }
        let net = net.trunc();
        if !seen.insert(net) {
            continue;
        }
        rules.push(Rule {
            id: format!("drop:{net}"),
            name: format!("Spamhaus DROP · {net}"),
            target: Target::Network(net),
            action: Action::Block,
            enabled: true,
            program: None,
            protocol: None,
            port: None,
            expires_at: None,
            source: Some("spamhaus_drop".into()),
        });
        if rules.len() > 50_000 {
            return Err("訂閱超過 50,000 筆".into());
        }
    }
    if rules.is_empty() {
        return Err("沒有可匯入的網段".into());
    }
    Ok(rules)
}
