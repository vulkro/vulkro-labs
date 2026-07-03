//! Commodity parsing of an A2A (Agent2Agent) agent card and the pure
//! URL-derivation helpers. No analysis, no network: warden and the checks in
//! `mod.rs` run on top of these plain structs.
//!
//! Every optional field defaults, and `capabilities` / `signatures` are escape
//! -hatch Values, so an evolving A2A schema degrades to fewer findings rather
//! than a parse error.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentCard {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// The origin the card claims to speak for.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub provider: Option<Provider>,
    #[serde(default)]
    pub skills: Vec<Skill>,
    /// A2A signatures array (JWS). Parsed for PRESENCE / format only. Unknown
    /// card fields are ignored, so an evolving schema degrades gracefully.
    #[serde(default)]
    pub signatures: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Provider {
    #[serde(default)]
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Skill {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Structural signature status. There is deliberately NO `Verified` state: this
/// version does not perform cryptographic verification, so it cannot represent
/// a verified signature and can never claim one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePresence {
    Absent,
    PresentWellFormed,
    PresentMalformed,
}

/// Parse an agent card from JSON text.
pub fn parse_card(json_text: &str) -> Result<AgentCard> {
    serde_json::from_str(json_text).context("parsing the agent card (is it valid JSON?)")
}

/// The signature status and the declared JWS `alg` if an unprotected header
/// exposes it. A protected (base64url) header is NOT decoded (that is the crypto
/// path this version deliberately does not take), so `alg` is best-effort.
pub fn signature_presence(card: &AgentCard) -> (SignaturePresence, Option<String>) {
    let Some(sig) = card.signatures.first() else {
        return (SignaturePresence::Absent, None);
    };
    let has_protected = sig.get("protected").and_then(|v| v.as_str()).is_some();
    let has_signature = sig.get("signature").and_then(|v| v.as_str()).is_some();
    let alg = sig
        .get("header")
        .and_then(|h| h.get("alg"))
        .and_then(|a| a.as_str())
        .map(str::to_string);
    if has_protected && has_signature {
        (SignaturePresence::PresentWellFormed, alg)
    } else {
        (SignaturePresence::PresentMalformed, alg)
    }
}

/// Every human-facing (field_path, text) pair, to hand to warden::scan_content.
pub fn text_fields(card: &AgentCard) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(name) = &card.name {
        out.push(("name".to_string(), name.clone()));
    }
    if let Some(desc) = &card.description {
        out.push(("description".to_string(), desc.clone()));
    }
    if let Some(provider) = &card.provider {
        if let Some(org) = &provider.organization {
            out.push(("provider.organization".to_string(), org.clone()));
        }
    }
    for (i, skill) in card.skills.iter().enumerate() {
        if let Some(name) = &skill.name {
            out.push((format!("skills[{i}].name"), name.clone()));
        }
        if let Some(desc) = &skill.description {
            out.push((format!("skills[{i}].description"), desc.clone()));
        }
        for (j, tag) in skill.tags.iter().enumerate() {
            out.push((format!("skills[{i}].tags[{j}]"), tag.clone()));
        }
    }
    out
}

/// Given a host, an https URL, or a full well-known URL, return the ordered
/// candidate fetch URLs: the primary well-known path then the agent.json
/// fallback. https only.
pub fn candidate_urls(target: &str) -> Result<Vec<String>> {
    let target = target.trim();
    if target.is_empty() {
        anyhow::bail!("empty target: give a host (example.com) or an https URL");
    }
    if target.starts_with("http://") {
        anyhow::bail!(
            "cardcheck fetches over https only (got an http:// URL). Use https, or --file for a local card"
        );
    }
    if target.contains("/.well-known/") {
        return Ok(vec![target.to_string()]);
    }
    let host = if target.starts_with("https://") {
        host_of(target)
            .with_context(|| format!("could not read a host from '{target}'"))?
    } else if target.contains('/') {
        anyhow::bail!("give a host (example.com) or an https URL, not a path");
    } else {
        target.to_string()
    };
    Ok(vec![
        format!("https://{host}/.well-known/agent-card.json"),
        format!("https://{host}/.well-known/agent.json"),
    ])
}

/// The host component of a URL (userinfo and port stripped).
pub fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let after_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let host = after_userinfo.split(':').next().unwrap_or(after_userinfo);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Whether two hosts share a registrable-domain-ish suffix (last two labels).
/// A commodity approximation (no Public Suffix List): its failure mode is an
/// under-flag (a missed mismatch), never a false HIGH.
pub fn same_site(a: &str, b: &str) -> bool {
    registrable(a) == registrable(b)
}

fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|s| !s.is_empty()).collect();
    let n = labels.len();
    if n <= 2 {
        labels.join(".")
    } else {
        labels[n - 2..].join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_and_full_card() {
        assert!(parse_card(r#"{"name":"x"}"#).is_ok());
        let full = r#"{"name":"a","url":"https://a.example.com","provider":{"organization":"Acme"},"skills":[{"name":"s","description":"d","tags":["t"]}],"signatures":[]}"#;
        let card = parse_card(full).unwrap();
        assert_eq!(card.skills.len(), 1);
    }

    #[test]
    fn candidate_urls_builds_wellknown_then_fallback() {
        let urls = candidate_urls("example.com").unwrap();
        assert_eq!(urls[0], "https://example.com/.well-known/agent-card.json");
        assert_eq!(urls[1], "https://example.com/.well-known/agent.json");
        // a full well-known URL is returned as-is
        let direct = candidate_urls("https://x.com/.well-known/agent.json").unwrap();
        assert_eq!(direct, vec!["https://x.com/.well-known/agent.json".to_string()]);
        // http is rejected
        assert!(candidate_urls("http://x.com").is_err());
        assert!(candidate_urls("").is_err());
    }

    #[test]
    fn host_and_same_site() {
        assert_eq!(host_of("https://a.example.com/x"), Some("a.example.com".to_string()));
        assert!(same_site("api.example.com", "example.com"));
        assert!(!same_site("example.com", "evil.com"));
    }

    #[test]
    fn signature_presence_states() {
        let none = parse_card(r#"{"name":"x"}"#).unwrap();
        assert_eq!(signature_presence(&none).0, SignaturePresence::Absent);
        let good = parse_card(r#"{"signatures":[{"protected":"eyJ","signature":"abc"}]}"#).unwrap();
        assert_eq!(signature_presence(&good).0, SignaturePresence::PresentWellFormed);
        let bad = parse_card(r#"{"signatures":[{"protected":"eyJ"}]}"#).unwrap();
        assert_eq!(signature_presence(&bad).0, SignaturePresence::PresentMalformed);
    }

    #[test]
    fn text_fields_covers_human_fields() {
        let card = parse_card(
            r#"{"name":"n","description":"d","provider":{"organization":"Org"},"skills":[{"name":"s","description":"sd","tags":["tg"]}]}"#,
        )
        .unwrap();
        let fields = text_fields(&card);
        let paths: Vec<&str> = fields.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"name"));
        assert!(paths.contains(&"description"));
        assert!(paths.contains(&"provider.organization"));
        assert!(paths.contains(&"skills[0].name"));
        assert!(paths.contains(&"skills[0].description"));
        assert!(paths.contains(&"skills[0].tags[0]"));
    }
}
