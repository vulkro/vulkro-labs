//! Keyless PyPI client: package existence and metadata from the public PyPI
//! JSON API.
//!
//! PyPI does not expose download counts keyless (they were removed from the
//! JSON API years ago), so reputation here is age-only: the SUSPICIOUS
//! heuristic for PyPI relies on how new the project is.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ecosystem::{AttestationPresence, PackageMetadata, ProvenanceInfo, Reputation};
use crate::http::HttpClient;

/// Base URL for the public PyPI JSON API.
const PYPI_BASE: &str = "https://pypi.org/pypi";

#[derive(Deserialize)]
struct Project {
    info: Info,
    #[serde(default)]
    releases: BTreeMap<String, Vec<ReleaseFile>>,
}

#[derive(Deserialize)]
struct Info {
    version: Option<String>,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    project_urls: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ReleaseFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    /// The PEP 740 provenance URL for this file, present when the release was
    /// published with attestations. Read for PRESENCE only, never verified.
    #[serde(default)]
    provenance: Option<String>,
}

/// A keyless client for the public PyPI JSON API.
pub struct PyPi<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> PyPi<'a> {
    /// Create a client over the given transport.
    pub fn new(http: &'a dyn HttpClient) -> Self {
        Self { http }
    }

    /// Look up a project's public metadata. `Ok(None)` when PyPI reports the
    /// project does not exist (HTTP 404).
    pub fn lookup(&self, name: &str) -> Result<Option<PackageMetadata>> {
        let url = format!("{PYPI_BASE}/{}/json", encode_name(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying PyPI for '{name}'"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            anyhow::bail!(
                "PyPI returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        let project: Project = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing PyPI metadata for '{name}'"))?;

        // The project's age is the earliest upload time across all release
        // files. Some releases carry no files; those simply contribute nothing.
        let created = project
            .releases
            .values()
            .flatten()
            .filter_map(|f| f.upload_time_iso_8601.clone())
            .min();

        Ok(Some(PackageMetadata {
            name: name.to_string(),
            latest_version: project.info.version,
            created,
            versions: project.releases.into_keys().collect(),
        }))
    }

    /// PyPI exposes no keyless reputation beyond what the lookup already
    /// returned (age and latest version), so this is always empty.
    pub fn reputation(&self, _name: &str) -> Result<Reputation> {
        Ok(Reputation::default())
    }

    /// Read the PEP 740 attestation / provenance PRESENCE PyPI advertises for a
    /// version (the pinned one, else the latest). PyPI attaches a per-file
    /// `provenance` URL when a release was published with attestations. This is
    /// a commodity presence read of public metadata: it performs NO
    /// cryptographic verification and never claims one. `Ok(None)` when the
    /// project does not exist.
    pub fn provenance(&self, name: &str, version: Option<&str>) -> Result<Option<ProvenanceInfo>> {
        let url = format!("{PYPI_BASE}/{}/json", encode_name(name));
        let resp = self
            .http
            .get(&url)
            .with_context(|| format!("querying PyPI for '{name}'"))?;
        if resp.status == 404 {
            return Ok(None);
        }
        if !resp.is_success() {
            anyhow::bail!(
                "PyPI returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        let project: Project = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing PyPI metadata for '{name}'"))?;

        let chosen = version
            .map(str::to_string)
            .or_else(|| project.info.version.clone());
        // A release with any file carrying a provenance URL is well-formed; a
        // release with no files at all leaves presence Absent.
        let presence = match chosen.as_deref().and_then(|v| project.releases.get(v)) {
            Some(files) if files.iter().any(|f| provenance_present(&f.provenance)) => {
                AttestationPresence::PresentWellFormed
            }
            _ => AttestationPresence::Absent,
        };
        let kinds = if presence == AttestationPresence::PresentWellFormed {
            vec!["pep740-attestation".to_string()]
        } else {
            Vec::new()
        };

        Ok(Some(ProvenanceInfo {
            version: chosen,
            presence,
            kinds,
            source_repo: source_repo(&project.info),
        }))
    }
}

/// Whether a release file's `provenance` field is a non-empty URL.
fn provenance_present(field: &Option<String>) -> bool {
    field.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false)
}

/// The most likely source-repository URL from PyPI project metadata: a
/// project-url whose label looks like a source / repo / homepage, else
/// `home_page`. For display and mismatch notes only.
fn source_repo(info: &Info) -> Option<String> {
    for (label, url) in &info.project_urls {
        let lower = label.to_ascii_lowercase();
        let looks_like_repo =
            lower.contains("source") || lower.contains("repository") || lower.contains("github");
        if looks_like_repo && !url.trim().is_empty() {
            return Some(url.clone());
        }
    }
    info.home_page
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// Encode a project name for the URL path. PyPI names use only
/// `[A-Za-z0-9._-]`, so nothing needs escaping; we pass the name through.
fn encode_name(name: &str) -> &str {
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttp;

    const REQUESTS: &str = r#"{
        "info": {"name": "requests", "version": "2.31.0"},
        "releases": {
            "2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:44.000000Z"}],
            "0.2.0":  [{"upload_time_iso_8601": "2011-02-14T12:00:00.000000Z"}]
        }
    }"#;

    #[test]
    fn lookup_reads_latest_versions_and_earliest_created() {
        let http = MockHttp::new().on_get("pypi.org/pypi/requests/json", 200, REQUESTS);
        let info = PyPi::new(&http).lookup("requests").unwrap().unwrap();
        assert_eq!(info.latest_version.as_deref(), Some("2.31.0"));
        // Age is the earliest upload across all releases.
        assert_eq!(info.created.as_deref(), Some("2011-02-14T12:00:00.000000Z"));
        assert!(info.has_version("2.31.0"));
        assert!(info.has_version("0.2.0"));
        assert!(!info.has_version("9.9.9"));
    }

    #[test]
    fn lookup_missing_project_is_none() {
        let http = MockHttp::new().on_get("pypi.org/pypi", 404, r#"{"message": "Not Found"}"#);
        assert!(PyPi::new(&http)
            .lookup("no-such-pkg-xyz")
            .unwrap()
            .is_none());
    }

    #[test]
    fn reputation_is_empty() {
        let http = MockHttp::new();
        assert_eq!(
            PyPi::new(&http).reputation("requests").unwrap().downloads,
            None
        );
    }

    #[test]
    fn provenance_present_when_file_has_provenance_url() {
        let body = r#"{
            "info": {"version": "1.0.0", "project_urls": {"Source": "https://github.com/acme/pkg"}},
            "releases": {"1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z", "provenance": "https://pypi.org/integrity/pkg/1.0.0/pkg-1.0.0.tar.gz/provenance"}]}
        }"#;
        let http = MockHttp::new().on_get("pypi.org/pypi/pkg/json", 200, body);
        let info = PyPi::new(&http).provenance("pkg", None).unwrap().unwrap();
        assert_eq!(info.presence, AttestationPresence::PresentWellFormed);
        assert!(info.kinds.iter().any(|k| k == "pep740-attestation"));
        assert_eq!(info.source_repo.as_deref(), Some("https://github.com/acme/pkg"));
    }

    #[test]
    fn provenance_absent_when_no_file_provenance() {
        let body = r#"{
            "info": {"version": "1.0.0", "home_page": "https://example.com"},
            "releases": {"1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}]}
        }"#;
        let http = MockHttp::new().on_get("pypi.org/pypi/plainpy/json", 200, body);
        let info = PyPi::new(&http).provenance("plainpy", None).unwrap().unwrap();
        assert_eq!(info.presence, AttestationPresence::Absent);
        assert_eq!(info.source_repo.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn provenance_missing_project_is_none() {
        let http = MockHttp::new().on_get("pypi.org/pypi", 404, r#"{"message":"Not Found"}"#);
        assert!(PyPi::new(&http).provenance("nope-xyz", None).unwrap().is_none());
    }
}
