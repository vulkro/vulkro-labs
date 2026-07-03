//! Deterministic, keyless fingerprints for the trust store.
//!
//! FNV-1a 64-bit (a public-domain, non-cryptographic hash) over a normalized
//! byte stream. This is allowlist bookkeeping, not an integrity signature: a
//! fingerprint only ever SUPPRESSES a finding on a byte-identical artifact a
//! human already reviewed, so a fast commodity hash is sufficient. If this ever
//! guarded remotely-supplied content, it should be upgraded to a cryptographic
//! hash (a justified future dependency), noted here so the choice is conscious.

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use vulkro_feeds::{parse_tools, McpTool};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit of `bytes`, as 16 lowercase hex chars.
pub fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

/// Fingerprint any raw body (a skill file, a memory file) by its exact bytes.
pub fn bytes_fingerprint(bytes: &[u8]) -> String {
    fnv1a_hex(bytes)
}

/// The canonical, key-sorted form of one tool: only the fields warden reads
/// (name, description, inputSchema, annotations). serde_json's default Map is a
/// sorted BTreeMap, so serializing this is deterministic and key-order stable.
/// Shared with lock/drift so a manifest fingerprints and diffs identically.
pub fn canonical_tool_value(tool: &McpTool) -> Value {
    let mut m = Map::new();
    m.insert("name".to_string(), Value::String(tool.name.clone()));
    m.insert(
        "description".to_string(),
        tool.description
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    m.insert(
        "inputSchema".to_string(),
        tool.input_schema.clone().unwrap_or(Value::Null),
    );
    m.insert(
        "annotations".to_string(),
        tool.annotations.clone().unwrap_or(Value::Null),
    );
    Value::Object(m)
}

/// Fingerprint an MCP tool manifest by its canonical semantic content, so
/// cosmetic whitespace or key order does not defeat the pin but any semantic
/// change (a tool added / removed, a description or schema edited) does.
pub fn manifest_fingerprint(json_text: &str) -> Result<String> {
    let mut tools = parse_tools(json_text)?;
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let canonical: Vec<Value> = tools.iter().map(canonical_tool_value).collect();
    let bytes = serde_json::to_vec(&canonical).context("serializing the canonical manifest")?;
    Ok(fnv1a_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_known_vectors() {
        // Canonical FNV-1a 64-bit test vectors.
        assert_eq!(fnv1a_hex(b""), "cbf29ce484222325");
        assert_eq!(fnv1a_hex(b"a"), "af63dc4c8601ec8c");
    }

    #[test]
    fn manifest_fingerprint_ignores_key_order_and_whitespace() {
        let a = r#"{"tools":[{"name":"a","description":"does a"}]}"#;
        let b = r#"{  "tools" : [ {"description":"does a", "name":"a"} ] }"#;
        assert_eq!(manifest_fingerprint(a).unwrap(), manifest_fingerprint(b).unwrap());
    }

    #[test]
    fn manifest_fingerprint_changes_on_semantic_edit() {
        let base = r#"{"tools":[{"name":"a","description":"does a"}]}"#;
        let desc = r#"{"tools":[{"name":"a","description":"does a differently"}]}"#;
        let added = r#"{"tools":[{"name":"a","description":"does a"},{"name":"b"}]}"#;
        let fp = manifest_fingerprint(base).unwrap();
        assert_ne!(fp, manifest_fingerprint(desc).unwrap());
        assert_ne!(fp, manifest_fingerprint(added).unwrap());
    }

    #[test]
    fn manifest_fingerprint_is_order_independent_across_tools() {
        let a = r#"{"tools":[{"name":"a"},{"name":"b"}]}"#;
        let b = r#"{"tools":[{"name":"b"},{"name":"a"}]}"#;
        assert_eq!(manifest_fingerprint(a).unwrap(), manifest_fingerprint(b).unwrap());
    }

    #[test]
    fn bytes_fingerprint_is_utf8_safe_and_sensitive() {
        let one = bytes_fingerprint("café".as_bytes());
        let two = bytes_fingerprint("cafe".as_bytes());
        assert_ne!(one, two);
        // a one-byte edit changes it
        assert_ne!(bytes_fingerprint(b"hello"), bytes_fingerprint(b"hellp"));
    }
}
