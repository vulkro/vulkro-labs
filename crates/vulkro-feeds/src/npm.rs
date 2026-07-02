//! Keyless npm registry client: package existence, metadata, and download
//! counts, read live from the public npm endpoints.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ecosystem::{PackageMetadata, Reputation};
use crate::http::HttpClient;

/// Base URL for the public npm registry (existence + metadata).
const REGISTRY_BASE: &str = "https://registry.npmjs.org";
/// Base URL for the public npm download-counts API (last 7 days).
const DOWNLOADS_BASE: &str = "https://api.npmjs.org/downloads/point/last-week";

/// The subset of the registry "packument" document we read.
#[derive(Deserialize)]
struct Packument {
    #[serde(rename = "dist-tags", default)]
    dist_tags: DistTags,
    #[serde(default)]
    versions: BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default)]
    time: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
struct DistTags {
    latest: Option<String>,
}

/// The subset of the download-counts response we read. An error payload
/// (e.g. `{"error":"package X not found"}`) simply has no `downloads` field.
#[derive(Deserialize)]
struct DownloadsPoint {
    downloads: Option<u64>,
}

/// A keyless client for the public npm registry.
pub struct Npm<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> Npm<'a> {
    /// Create a client over the given transport.
    pub fn new(http: &'a dyn HttpClient) -> Self {
        Self { http }
    }

    /// Look up a package's public metadata. `Ok(None)` when the registry
    /// reports the package does not exist (HTTP 404).
    pub fn lookup(&self, name: &str) -> Result<Option<PackageMetadata>> {
        let url = format!("{REGISTRY_BASE}/{}", encode_name(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying the npm registry for '{name}'"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            anyhow::bail!(
                "the npm registry returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        let doc: Packument = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing npm registry metadata for '{name}'"))?;
        Ok(Some(PackageMetadata {
            name: name.to_string(),
            latest_version: doc.dist_tags.latest,
            created: doc.time.get("created").cloned(),
            versions: doc.versions.into_keys().collect(),
        }))
    }

    /// Reputation enrichment: the weekly download count. npm supplies age and
    /// latest version in the existence lookup, so those stay `None` here.
    pub fn reputation(&self, name: &str) -> Result<Reputation> {
        Ok(Reputation {
            downloads: self.weekly_downloads(name)?,
            ..Reputation::default()
        })
    }

    /// Read the package's download count for the last 7 days. `Ok(None)` when
    /// npm has no statistics yet (for example, a brand-new package).
    pub fn weekly_downloads(&self, name: &str) -> Result<Option<u64>> {
        let url = format!("{DOWNLOADS_BASE}/{}", encode_name(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying npm download counts for '{name}'"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            anyhow::bail!(
                "the npm downloads API returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        let point: DownloadsPoint = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing npm download counts for '{name}'"))?;
        Ok(point.downloads)
    }
}

/// Percent-encode a package name for a URL path. A scoped name carries a `/`
/// (e.g. `@babel/core`) that must become `%2F`; the leading `@` is left as-is,
/// and npm names use no other characters that require encoding.
fn encode_name(name: &str) -> String {
    name.replace('/', "%2F")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttp;

    const EXPRESS: &str = r#"{
        "dist-tags": {"latest": "4.18.2"},
        "versions": {"4.18.1": {}, "4.18.2": {}},
        "time": {"created": "2010-12-29T19:38:25.450Z", "4.18.2": "2022-10-08T20:14:32.495Z"}
    }"#;

    #[test]
    fn lookup_existing_package_parses_metadata() {
        let http = MockHttp::new().on_get("registry.npmjs.org/express", 200, EXPRESS);
        let info = Npm::new(&http).lookup("express").unwrap().unwrap();
        assert_eq!(info.latest_version.as_deref(), Some("4.18.2"));
        assert_eq!(info.created.as_deref(), Some("2010-12-29T19:38:25.450Z"));
        assert!(info.has_version("4.18.2"));
        assert!(!info.has_version("99.0.0"));
    }

    #[test]
    fn lookup_missing_package_is_none() {
        let http = MockHttp::new().on_get("registry.npmjs.org", 404, r#"{"error":"Not found"}"#);
        assert!(Npm::new(&http)
            .lookup("definitely-not-a-real-package-xyz")
            .unwrap()
            .is_none());
    }

    #[test]
    fn scoped_name_is_percent_encoded() {
        let http = MockHttp::new().on_get("registry.npmjs.org/@babel%2Fcore", 200, EXPRESS);
        // Would error on an unmatched request, so a success proves the URL was
        // encoded as @babel%2Fcore.
        assert!(Npm::new(&http).lookup("@babel/core").unwrap().is_some());
    }

    #[test]
    fn reputation_reads_weekly_downloads() {
        let http = MockHttp::new().on_get(
            "api.npmjs.org/downloads",
            200,
            r#"{"downloads": 1234, "package": "express"}"#,
        );
        assert_eq!(
            Npm::new(&http).reputation("express").unwrap().downloads,
            Some(1234)
        );
    }

    #[test]
    fn weekly_downloads_missing_stats_is_none() {
        let http = MockHttp::new().on_get(
            "api.npmjs.org/downloads",
            404,
            r#"{"error":"package new-thing not found"}"#,
        );
        assert_eq!(Npm::new(&http).weekly_downloads("new-thing").unwrap(), None);
    }
}
