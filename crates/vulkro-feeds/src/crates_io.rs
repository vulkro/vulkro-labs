//! Keyless crates.io client.
//!
//! Existence and the version list come from the sparse index
//! (index.crates.io), the path crates.io recommends for tooling. Reputation
//! (creation date, latest version, recent downloads) comes from the crates.io
//! API, and is fetched only when it can change a verdict, to keep load off the
//! API as the index guidance intends.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ecosystem::{PackageMetadata, Reputation};
use crate::http::HttpClient;

/// Base URL for the crates.io sparse index.
const INDEX_BASE: &str = "https://index.crates.io";
/// Base URL for the crates.io API.
const API_BASE: &str = "https://crates.io/api/v1/crates";

/// One line of a sparse-index file (one JSON object per published version).
#[derive(Deserialize)]
struct IndexEntry {
    vers: String,
}

#[derive(Deserialize)]
struct ApiResponse {
    #[serde(rename = "crate")]
    krate: ApiCrate,
}

#[derive(Deserialize)]
struct ApiCrate {
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    max_stable_version: Option<String>,
    #[serde(default)]
    newest_version: Option<String>,
    #[serde(default)]
    max_version: Option<String>,
    #[serde(default)]
    recent_downloads: Option<u64>,
    #[serde(default)]
    downloads: Option<u64>,
}

/// A keyless client for crates.io.
pub struct CratesIo<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> CratesIo<'a> {
    /// Create a client over the given transport.
    pub fn new(http: &'a dyn HttpClient) -> Self {
        Self { http }
    }

    /// Existence and version list via the sparse index. `Ok(None)` when the
    /// crate does not exist (HTTP 404).
    pub fn lookup(&self, name: &str) -> Result<Option<PackageMetadata>> {
        let url = format!("{INDEX_BASE}/{}", sparse_index_path(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying the crates.io index for '{name}'"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            anyhow::bail!(
                "the crates.io index returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        // The index file is newline-delimited JSON, one object per version.
        let mut versions = Vec::new();
        for line in resp.body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: IndexEntry = serde_json::from_str(line)
                .with_context(|| format!("parsing the crates.io index for '{name}'"))?;
            versions.push(entry.vers);
        }
        // A crate with an empty index file should not happen, but if it did we
        // still treat the 200 as "exists".
        Ok(Some(PackageMetadata {
            name: name.to_string(),
            latest_version: None,
            created: None,
            versions,
        }))
    }

    /// Reputation enrichment from the crates.io API: creation date, latest
    /// stable version, and recent (90-day) downloads.
    pub fn reputation(&self, name: &str) -> Result<Reputation> {
        let url = format!("{API_BASE}/{}", encode_name(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying the crates.io API for '{name}'"))?;
        if !resp.is_success() {
            // Reputation is best-effort; a non-2xx here should not fail the
            // whole verdict, so report no enrichment rather than erroring.
            return Ok(Reputation::default());
        }
        let api: ApiResponse = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing the crates.io API response for '{name}'"))?;
        let latest_version = api
            .krate
            .max_stable_version
            .or(api.krate.newest_version)
            .or(api.krate.max_version);
        Ok(Reputation {
            created: api.krate.created_at,
            latest_version,
            downloads: api.krate.recent_downloads.or(api.krate.downloads),
        })
    }
}

/// The sparse-index path for a crate name, per the crates.io index layout:
/// 1 char -> `1/{name}`, 2 -> `2/{name}`, 3 -> `3/{first}/{name}`, else
/// `{first two}/{next two}/{name}`. Crate names are ASCII, so char indexing is
/// byte-safe.
fn sparse_index_path(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    let chars: Vec<char> = name.chars().collect();
    match chars.len() {
        0 | 1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", chars[0]),
        _ => format!("{}{}/{}{}/{name}", chars[0], chars[1], chars[2], chars[3]),
    }
}

/// Encode a crate name for the API URL path. Crate names are ASCII
/// `[A-Za-z0-9_-]`, so nothing needs escaping.
fn encode_name(name: &str) -> &str {
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttp;

    #[test]
    fn sparse_index_paths_match_the_layout() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("serde"), "se/rd/serde");
        assert_eq!(sparse_index_path("Tokio"), "to/ki/tokio");
    }

    #[test]
    fn lookup_reads_versions_from_the_index() {
        let index =
            "{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n{\"name\":\"serde\",\"vers\":\"1.0.1\"}\n";
        let http = MockHttp::new().on_get("index.crates.io/se/rd/serde", 200, index);
        let info = CratesIo::new(&http).lookup("serde").unwrap().unwrap();
        assert!(info.has_version("1.0.0"));
        assert!(info.has_version("1.0.1"));
        assert!(!info.has_version("9.9.9"));
    }

    #[test]
    fn lookup_missing_crate_is_none() {
        let http = MockHttp::new().on_get("index.crates.io", 404, "Not Found");
        assert!(CratesIo::new(&http)
            .lookup("no-such-crate-xyz")
            .unwrap()
            .is_none());
    }

    #[test]
    fn reputation_reads_created_latest_and_downloads() {
        let body = r#"{"crate":{"created_at":"2014-12-05T20:00:00Z","max_stable_version":"1.0.200","newest_version":"1.0.200","recent_downloads":987654}}"#;
        let http = MockHttp::new().on_get("crates.io/api/v1/crates/serde", 200, body);
        let rep = CratesIo::new(&http).reputation("serde").unwrap();
        assert_eq!(rep.created.as_deref(), Some("2014-12-05T20:00:00Z"));
        assert_eq!(rep.latest_version.as_deref(), Some("1.0.200"));
        assert_eq!(rep.downloads, Some(987654));
    }

    #[test]
    fn reputation_tolerates_a_non_success_response() {
        let http = MockHttp::new().on_get("crates.io/api/v1/crates", 500, "oops");
        let rep = CratesIo::new(&http).reputation("serde").unwrap();
        assert!(rep.created.is_none() && rep.downloads.is_none());
    }
}
