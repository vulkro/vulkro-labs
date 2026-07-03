//! Keyless OSV.dev client for malicious-package detection.
//!
//! Malicious packages surface in OSV as advisories whose id starts with
//! `MAL-`, sourced from the OpenSSF malicious-packages project (Apache-2.0).
//! We query live and read only those records; we do not cache or redistribute
//! the OSV corpus (which mixes per-source licenses). See ATTRIBUTION.md.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::http::HttpClient;

/// The OSV.dev single-package query endpoint.
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
/// The id prefix OSV uses for malicious-package records.
const MALICIOUS_PREFIX: &str = "MAL-";

/// A malicious-package finding: the matching `MAL-` advisory ids and a summary.
#[derive(Debug, Clone)]
pub struct MaliciousReport {
    /// The matching advisory ids (each begins with `MAL-`).
    pub ids: Vec<String>,
    /// A human-readable summary from the first matching advisory, if any.
    pub summary: Option<String>,
}

/// One known (non-malicious) security advisory affecting the queried version: a
/// CVE / GHSA / PYSEC / RUSTSEC record.
#[derive(Debug, Clone)]
pub struct Advisory {
    /// The advisory id (e.g. `GHSA-...`, `CVE-...`).
    pub id: String,
    /// A human-readable summary, if any.
    pub summary: Option<String>,
    /// The severity label OSV reports (`CRITICAL` / `HIGH` / `MODERATE` /
    /// `LOW`), uppercased, when present.
    pub severity: Option<String>,
}

/// The full advisory picture for a package version from one OSV query: any
/// malicious-package flag, plus the non-malicious vulnerabilities that affect
/// the queried version. Both come from a single request.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryReport {
    pub malicious: Option<MaliciousReport>,
    pub vulnerabilities: Vec<Advisory>,
}

#[derive(Deserialize)]
struct QueryResponse {
    #[serde(default)]
    vulns: Vec<Vuln>,
}

#[derive(Deserialize)]
struct Vuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    /// Present (a timestamp) when the advisory has been withdrawn; such records
    /// are ignored.
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
}

#[derive(Deserialize)]
struct DatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,
}

/// A keyless client for the OSV.dev query API.
pub struct Osv<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> Osv<'a> {
    /// Create a client over the given transport.
    pub fn new(http: &'a dyn HttpClient) -> Self {
        Self { http }
    }

    /// Check whether `name` (optionally at `version`) in `ecosystem` is flagged
    /// malicious.
    ///
    /// `ecosystem` must be an exact OSV ecosystem string (for npm, the literal
    /// `"npm"`). A name-only query is sufficient to catch a fully-malicious
    /// package, since `MAL-` records typically flag every version. Returns
    /// `Ok(None)` when no `MAL-` record matches.
    pub fn malicious(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Option<MaliciousReport>> {
        Ok(self.advisories(ecosystem, name, version)?.malicious)
    }

    /// Query OSV once and return both the malicious-package flag (if any) and
    /// the non-malicious advisories (CVE / GHSA / ...) affecting the queried
    /// version. When `version` is given, OSV matches advisory ranges against it
    /// server-side, so the vulnerabilities reflect that exact version.
    /// Withdrawn advisories are ignored.
    pub fn advisories(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<AdvisoryReport> {
        let body = build_query(ecosystem, name, version);
        let resp = self
            .http
            .post(OSV_QUERY_URL, "application/json", body.as_bytes())
            .with_context(|| format!("querying OSV for '{name}'"))?;
        // OSV returns 200 with an empty `vulns` list for a clean package; a 404
        // (not expected here) is treated the same as "nothing found".
        if resp.status == 404 {
            return Ok(AdvisoryReport::default());
        }
        if !resp.is_success() {
            anyhow::bail!(
                "the OSV API returned HTTP {} for '{name}' (try again shortly)",
                resp.status
            );
        }
        let parsed: QueryResponse = serde_json::from_str(&resp.body)
            .with_context(|| format!("parsing the OSV response for '{name}'"))?;

        let mut mal_ids = Vec::new();
        let mut mal_summary = None;
        let mut vulnerabilities = Vec::new();
        for vuln in parsed.vulns {
            if vuln.withdrawn.is_some() {
                continue;
            }
            if vuln.id.starts_with(MALICIOUS_PREFIX) {
                if mal_summary.is_none() {
                    mal_summary = vuln.summary;
                }
                mal_ids.push(vuln.id);
            } else {
                let severity = vuln
                    .database_specific
                    .and_then(|d| d.severity)
                    .map(|s| s.to_uppercase());
                vulnerabilities.push(Advisory {
                    id: vuln.id,
                    summary: vuln.summary,
                    severity,
                });
            }
        }
        let malicious = if mal_ids.is_empty() {
            None
        } else {
            Some(MaliciousReport {
                ids: mal_ids,
                summary: mal_summary,
            })
        };
        Ok(AdvisoryReport {
            malicious,
            vulnerabilities,
        })
    }
}

/// Build the JSON request body, using `serde_json` so the package name and
/// version are escaped safely.
fn build_query(ecosystem: &str, name: &str, version: Option<&str>) -> String {
    let package = serde_json::json!({ "name": name, "ecosystem": ecosystem });
    let query = match version {
        Some(v) => serde_json::json!({ "package": package, "version": v }),
        None => serde_json::json!({ "package": package }),
    };
    query.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttp;

    #[test]
    fn detects_malicious_mal_record() {
        let body = r#"{"vulns":[{"id":"MAL-2024-1095","summary":"malicious package"}]}"#;
        let http = MockHttp::new().on_post("api.osv.dev/v1/query", Some("evil-pkg"), 200, body);
        let report = Osv::new(&http)
            .malicious("npm", "evil-pkg", None)
            .unwrap()
            .unwrap();
        assert_eq!(report.ids, vec!["MAL-2024-1095".to_string()]);
        assert_eq!(report.summary.as_deref(), Some("malicious package"));
    }

    #[test]
    fn non_malicious_advisories_are_ignored() {
        // A regular (non-MAL) advisory must not be reported as malicious.
        let body = r#"{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","summary":"a normal CVE"}]}"#;
        let http = MockHttp::new().on_post("api.osv.dev/v1/query", None, 200, body);
        assert!(Osv::new(&http)
            .malicious("npm", "some-pkg", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn advisories_surfaces_cve_and_skips_withdrawn() {
        let body = r#"{"vulns":[
            {"id":"GHSA-aaaa","summary":"prototype pollution","database_specific":{"severity":"high"}},
            {"id":"CVE-2020-0001","withdrawn":"2021-01-01T00:00:00Z"},
            {"id":"MAL-2024-1","summary":"malware"}
        ]}"#;
        let http = MockHttp::new().on_post("api.osv.dev/v1/query", None, 200, body);
        let report = Osv::new(&http)
            .advisories("npm", "some-pkg", Some("1.0.0"))
            .unwrap();
        assert!(report.malicious.is_some());
        assert_eq!(report.vulnerabilities.len(), 1);
        assert_eq!(report.vulnerabilities[0].id, "GHSA-aaaa");
        assert_eq!(report.vulnerabilities[0].severity.as_deref(), Some("HIGH"));
    }

    #[test]
    fn empty_vulns_is_clean() {
        let http = MockHttp::new().on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#);
        assert!(Osv::new(&http)
            .malicious("npm", "express", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn version_is_included_in_the_query_body() {
        // The body matcher only fires if the version reached the request body.
        let http = MockHttp::new().on_post(
            "api.osv.dev/v1/query",
            Some("\"version\":\"1.2.3\""),
            200,
            r#"{"vulns":[{"id":"MAL-2024-1"}]}"#,
        );
        assert!(Osv::new(&http)
            .malicious("npm", "evil-pkg", Some("1.2.3"))
            .unwrap()
            .is_some());
    }
}
