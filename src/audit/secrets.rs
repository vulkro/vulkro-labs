//! Hand-rolled, no-regex, UTF-8-safe plaintext-secret classifier for CONFIG
//! values (MCP server env / headers / args).
//!
//! This looks ONLY at agent config, never source code, so it is deliberately
//! distinct from the paid engine's source-code secret scanning. It fires on
//! known token shapes (high precision) or a long, high-entropy, mixed-charset
//! value (entropy fallback), with a tight allowlist that rejects the common
//! non-secrets (true/false, ports, paths, and the ${VAR}/$VAR indirection that
//! is the CORRECT way to pass a secret and must never be flagged).

/// A value shorter than this (in chars) is never treated as a secret.
const MIN_SECRET_LEN: usize = 16;
/// The entropy fallback needs at least this many chars.
const ENTROPY_MIN_LEN: usize = 20;
/// ... and at least this many bits of Shannon entropy per char.
const ENTROPY_MIN_BITS: f64 = 3.5;

/// High-precision token prefixes for well-known providers.
const TOKEN_PREFIXES: &[&str] = &[
    "sk-", "sk_live_", "pk_live_", "rk_live_", "ghp_", "gho_", "ghu_", "ghs_",
    "github_pat_", "xoxb-", "xoxp-", "xapp-", "AKIA", "ASIA", "AIza", "ya29.",
    "glpat-", "shpat_", "npm_", "dop_v1_", "SG.", "Bearer ",
];

/// One config value that looks like a plaintext secret.
pub struct SecretHit {
    pub key: String,
    pub kind: &'static str,
    pub redacted: String,
}

/// Shannon entropy in bits per char, over the char (not byte) distribution.
pub fn shannon_entropy(s: &str) -> f64 {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let len = chars.len() as f64;
    let mut counts: std::collections::BTreeMap<char, usize> = std::collections::BTreeMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Whether `value` (from a config env/header/arg) looks like a plaintext secret.
pub fn looks_like_secret(key: &str, value: &str) -> Option<SecretHit> {
    let v = value.trim();
    if is_allowlisted(v) {
        return None;
    }
    // High-precision prefix match: fires even on a moderately short token.
    for prefix in TOKEN_PREFIXES {
        if v.starts_with(prefix) && v.chars().count() >= prefix.chars().count() + 6 {
            return Some(SecretHit {
                key: key.to_string(),
                kind: "token-prefix",
                redacted: redact(v),
            });
        }
    }
    // Entropy fallback: long, high-entropy, mixed-charset value.
    if v.chars().count() >= ENTROPY_MIN_LEN
        && shannon_entropy(v) >= ENTROPY_MIN_BITS
        && is_mixed_charset(v)
    {
        return Some(SecretHit {
            key: key.to_string(),
            kind: "high-entropy",
            redacted: redact(v),
        });
    }
    None
}

/// Values that must never be flagged: empty, env indirections, booleans, ports,
/// paths, plain URLs without embedded credentials, and anything too short.
fn is_allowlisted(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    // ${VAR} / $VAR indirection is the correct, non-leaking way to pass a secret.
    if v.contains("${") || v.starts_with('$') {
        return true;
    }
    if v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("false") {
        return true;
    }
    if v.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    if v.starts_with('/') || v.starts_with("./") || v.starts_with("../") || v.starts_with("~/") {
        return true;
    }
    if (v.starts_with("http://") || v.starts_with("https://")) && !v.contains('@') {
        return true;
    }
    v.chars().count() < MIN_SECRET_LEN
}

/// At least one digit and one letter: kills long prose (no digits) and long
/// digit runs (no letters), while base64/hex tokens have both.
fn is_mixed_charset(v: &str) -> bool {
    let has_digit = v.chars().any(|c| c.is_ascii_digit());
    let has_alpha = v.chars().any(|c| c.is_ascii_alphabetic());
    has_digit && has_alpha
}

/// Char-boundary-safe redaction: first 3 chars, an ellipsis, last 2 chars, or
/// "***" for a short value (so a short token is never mostly exposed).
pub fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "***".to_string();
    }
    let head: String = chars.iter().take(3).collect();
    let tail: String = chars.iter().rev().take(2).rev().collect();
    format!("{head}...{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_low_for_repeated_and_high_for_random() {
        assert!(shannon_entropy("aaaaaaaa") < 0.001);
        assert!(shannon_entropy("a1B2c3D4e5F6g7H8i9J0kLmN") > 4.0);
    }

    #[test]
    fn token_prefixes_are_detected() {
        let hit = looks_like_secret("AUTH", "Bearer sk-abcdef0123456789abcdef").unwrap();
        assert_eq!(hit.kind, "token-prefix");
        // the redacted evidence must not contain the full token
        assert!(!hit.redacted.contains("abcdef0123456789"));
        assert!(looks_like_secret("GITHUB_TOKEN", "ghp_0123456789abcdef0123456789abcdef0123").is_some());
    }

    #[test]
    fn non_secrets_are_not_flagged() {
        assert!(looks_like_secret("DEBUG", "true").is_none());
        assert!(looks_like_secret("PORT", "8080").is_none());
        assert!(looks_like_secret("HOME", "/usr/local/bin").is_none());
        assert!(looks_like_secret("KEY", "${API_KEY}").is_none());
        assert!(looks_like_secret("KEY", "$API_KEY").is_none());
        assert!(looks_like_secret("X", "").is_none());
        assert!(looks_like_secret("SHORT", "abc123").is_none());
        assert!(looks_like_secret("URL", "https://api.example.com/v1").is_none());
    }

    #[test]
    fn redact_is_char_boundary_safe() {
        let value = "ключ-1234567890-secret-значение";
        let red = redact(value);
        assert!(red.contains("..."));
        // did not panic on a multi-byte value
    }

    #[test]
    fn redact_hides_short_values_entirely() {
        assert_eq!(redact("short"), "***");
    }
}
