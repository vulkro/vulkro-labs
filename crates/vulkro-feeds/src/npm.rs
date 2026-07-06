//! Keyless npm registry client: package existence, metadata, and download
//! counts, read live from the public npm endpoints.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ecosystem::{AttestationPresence, PackageMetadata, ProvenanceInfo, Reputation};
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
    // Values are timestamp strings, EXCEPT the `unpublished` key, whose value is
    // an object, so accept any JSON and read `created` only if it is a string.
    #[serde(default)]
    time: BTreeMap<String, serde_json::Value>,
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
            created: doc
                .time
                .get("created")
                .and_then(|v| v.as_str())
                .map(str::to_string),
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

    /// Read the published build-provenance / attestation metadata the npm
    /// registry advertises for a version (the pinned one, else the latest).
    ///
    /// This is a commodity PRESENCE read of public metadata: npm's `dist`
    /// object carries an `attestations` record ({ url, provenance }) and a
    /// `signatures` array when a package was published with provenance (npm
    /// `--provenance` / a trusted CI publisher). It performs NO cryptographic
    /// verification and never claims one. `Ok(None)` when the package does not
    /// exist.
    pub fn provenance(&self, name: &str, version: Option<&str>) -> Result<Option<ProvenanceInfo>> {
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
        let doc: ProvenancePackument = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing npm registry metadata for '{name}'"))?;

        // Choose the version to read: the pinned one, else dist-tags.latest.
        let chosen = version
            .map(str::to_string)
            .or_else(|| doc.dist_tags.latest.clone());
        let version_doc = chosen.as_deref().and_then(|v| doc.versions.get(v));

        let (presence, kinds) = match version_doc.map(|v| &v.dist) {
            Some(dist) => read_attestations(dist),
            None => (AttestationPresence::Absent, Vec::new()),
        };
        let source_repo = version_doc
            .and_then(|v| v.repository.as_ref())
            .and_then(repository_url)
            .or_else(|| doc.repository.as_ref().and_then(repository_url));

        Ok(Some(ProvenanceInfo {
            version: chosen,
            presence,
            kinds,
            source_repo,
        }))
    }
}

/// The subset of a packument needed to read provenance for one version.
#[derive(Deserialize)]
struct ProvenancePackument {
    #[serde(rename = "dist-tags", default)]
    dist_tags: DistTags,
    #[serde(default)]
    versions: BTreeMap<String, VersionDoc>,
    #[serde(default)]
    repository: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct VersionDoc {
    #[serde(default)]
    dist: Dist,
    #[serde(default)]
    repository: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct Dist {
    #[serde(default)]
    attestations: Option<Attestations>,
    #[serde(default)]
    signatures: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Attestations {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    provenance: Option<serde_json::Value>,
}

/// Classify the presence and kinds of a version's `dist` attestation metadata.
/// An `attestations` object with a URL is well-formed; one missing its URL is
/// malformed. Registry signatures alone (no attestations) are Absent for
/// provenance purposes but are noted as a `signature` kind.
fn read_attestations(dist: &Dist) -> (AttestationPresence, Vec<String>) {
    let mut kinds = Vec::new();
    let presence = match &dist.attestations {
        Some(att) => {
            if att.provenance.is_some() {
                kinds.push("provenance".to_string());
            }
            if att.url.as_deref().map(str::is_empty).unwrap_or(true) {
                AttestationPresence::PresentMalformed
            } else {
                AttestationPresence::PresentWellFormed
            }
        }
        None => AttestationPresence::Absent,
    };
    if !dist.signatures.is_empty() {
        kinds.push("registry-signature".to_string());
    }
    (presence, kinds)
}

/// The source-repo URL from an npm `repository` field, which may be a string or
/// an object with a `url`. Read for display and mismatch notes only.
fn repository_url(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Object(map) => map
            .get("url")
            .and_then(|u| u.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        _ => None,
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
    fn lookup_tolerates_unpublished_object_in_time() {
        // Regression: packages with unpublished versions carry an `unpublished`
        // key in `time` whose value is an object, not a timestamp string.
        let body = r#"{
            "dist-tags": {"latest": "1.2.1"},
            "versions": {"1.2.1": {}},
            "time": {
                "created": "2019-11-29T07:26:39.818Z",
                "1.2.1": "2019-12-05T03:53:32.935Z",
                "unpublished": {"time": "2022-05-18T01:20:55.154Z", "versions": ["1.0.1"]}
            }
        }"#;
        let http = MockHttp::new().on_get("registry.npmjs.org/express-helper", 200, body);
        let info = Npm::new(&http).lookup("express-helper").unwrap().unwrap();
        assert_eq!(info.created.as_deref(), Some("2019-11-29T07:26:39.818Z"));
        assert_eq!(info.latest_version.as_deref(), Some("1.2.1"));
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

    #[test]
    fn provenance_present_reads_attestations_and_repo() {
        let body = r#"{
            "dist-tags": {"latest": "2.0.0"},
            "repository": {"type": "git", "url": "git+https://github.com/acme/pkg.git"},
            "versions": {
                "2.0.0": {
                    "dist": {
                        "attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/pkg@2.0.0", "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}},
                        "signatures": [{"keyid": "x", "sig": "y"}]
                    }
                }
            }
        }"#;
        let http = MockHttp::new().on_get("registry.npmjs.org/pkg", 200, body);
        let info = Npm::new(&http).provenance("pkg", None).unwrap().unwrap();
        assert_eq!(info.presence, AttestationPresence::PresentWellFormed);
        assert_eq!(info.version.as_deref(), Some("2.0.0"));
        assert!(info.kinds.iter().any(|k| k == "provenance"));
        assert_eq!(info.source_repo.as_deref(), Some("git+https://github.com/acme/pkg.git"));
    }

    #[test]
    fn provenance_absent_when_no_attestations() {
        let body = r#"{
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dist": {}}}
        }"#;
        let http = MockHttp::new().on_get("registry.npmjs.org/plain", 200, body);
        let info = Npm::new(&http).provenance("plain", None).unwrap().unwrap();
        assert_eq!(info.presence, AttestationPresence::Absent);
        assert!(info.kinds.is_empty());
    }

    #[test]
    fn provenance_malformed_when_url_missing() {
        let body = r#"{
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dist": {"attestations": {"provenance": {"x": 1}}}}}
        }"#;
        let http = MockHttp::new().on_get("registry.npmjs.org/broken", 200, body);
        let info = Npm::new(&http).provenance("broken", None).unwrap().unwrap();
        assert_eq!(info.presence, AttestationPresence::PresentMalformed);
    }

    #[test]
    fn provenance_missing_package_is_none() {
        let http = MockHttp::new().on_get("registry.npmjs.org", 404, r#"{"error":"Not found"}"#);
        assert!(Npm::new(&http).provenance("ghost-xyz", None).unwrap().is_none());
    }
}
