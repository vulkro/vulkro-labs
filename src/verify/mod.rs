//! The `verify` package bouncer: gather public signals for a package and apply
//! the verdict policy.
//!
//! Data comes from [`vulkro_feeds`] (npm, PyPI, and crates.io registries plus
//! OSV.dev), queried live from the user's machine. Registry access is
//! ecosystem-dispatched through `vulkro_feeds::registry`, so this policy code
//! never branches per ecosystem.

pub mod manifest;
pub mod report;
pub mod verdict;

use anyhow::{Context, Result};
use time::OffsetDateTime;

use vulkro_feeds::{registry, Ecosystem, HttpClient, Osv};

use self::report::PackageReport;
use self::verdict::{classify, Signals, Thresholds};

/// A parsed package request: an ecosystem plus `name` or `name@version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
}

impl PackageRef {
    /// Parse `name` or `name@version` in the given ecosystem, handling scoped
    /// npm names (`@scope/name`, `@scope/name@version`).
    pub fn parse(input: &str, ecosystem: Ecosystem) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            anyhow::bail!("empty package name");
        }
        // The version separator is the first '@' that is not the leading scope
        // '@'. Scoped npm names have their scope '@' at index 0 and no other
        // '@' before the version, so skipping the first character finds the
        // right one. '@' is ASCII, so these byte offsets are char boundaries.
        let separator = input
            .char_indices()
            .skip(1)
            .find(|&(_, c)| c == '@')
            .map(|(i, _)| i);
        match separator {
            Some(i) => {
                let name = &input[..i];
                let version = &input[i + 1..];
                if name.is_empty() {
                    anyhow::bail!("empty package name in '{input}'");
                }
                if version.is_empty() {
                    anyhow::bail!("empty version in '{input}' (expected name@version)");
                }
                Ok(Self {
                    ecosystem,
                    name: name.to_string(),
                    version: Some(version.to_string()),
                })
            }
            None => Ok(Self {
                ecosystem,
                name: input.to_string(),
                version: None,
            }),
        }
    }
}

/// Verifies packages against public feeds.
pub struct Verifier<'a> {
    http: &'a dyn HttpClient,
    thresholds: Thresholds,
    now: OffsetDateTime,
}

impl<'a> Verifier<'a> {
    /// Create a verifier over the given transport, with default thresholds and
    /// the current UTC time.
    pub fn new(http: &'a dyn HttpClient) -> Self {
        Self {
            http,
            thresholds: Thresholds::default(),
            now: OffsetDateTime::now_utc(),
        }
    }

    /// Use the given SUSPICIOUS thresholds instead of the defaults.
    pub fn with_thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Override the reference "now" (used by tests for deterministic age math).
    #[cfg(test)]
    fn with_now(mut self, now: OffsetDateTime) -> Self {
        self.now = now;
        self
    }

    /// Gather signals for one package and classify it.
    pub fn verify(&self, package: &PackageRef) -> Result<PackageReport> {
        let eco = package.ecosystem;
        let core = registry::lookup(self.http, eco, &package.name)
            .with_context(|| format!("verifying '{}'", package.name))?;
        let malicious = Osv::new(self.http)
            .malicious(eco.osv_name(), &package.name, package.version.as_deref())
            .with_context(|| format!("verifying '{}'", package.name))?;

        let exists = core.is_some();
        let requested_version_exists = match (&package.version, &core) {
            (Some(version), Some(core)) => Some(core.has_version(version)),
            _ => None,
        };

        // Only fetch reputation when it could change the verdict, i.e. the
        // package exists, is not malicious, and (if a version was asked for)
        // that version is published. This spares an extra request for missing,
        // malicious, or bad-version packages.
        let need_reputation =
            exists && malicious.is_none() && requested_version_exists != Some(false);

        let core_created = core.as_ref().and_then(|c| c.created.clone());
        let core_latest = core.as_ref().and_then(|c| c.latest_version.clone());
        let (created, latest_version, downloads) = if need_reputation {
            let rep = registry::reputation(self.http, eco, &package.name)
                .with_context(|| format!("verifying '{}'", package.name))?;
            (
                rep.created.or(core_created),
                rep.latest_version.or(core_latest),
                rep.downloads,
            )
        } else {
            (core_created, core_latest, None)
        };

        let signals = Signals {
            exists,
            requested_version_exists,
            malicious,
            created,
            latest_version,
            downloads,
            downloads_window: eco.downloads_window(),
        };
        let (verdict, reason) = classify(&signals, &self.thresholds, self.now);

        let Signals {
            latest_version,
            created,
            downloads,
            malicious,
            ..
        } = signals;
        Ok(PackageReport {
            ecosystem: eco,
            name: package.name.clone(),
            version: package.version.clone(),
            verdict,
            reason,
            latest_version,
            created,
            downloads,
            malicious_ids: malicious.map(|m| m.ids).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::verdict::Verdict;
    use super::*;
    use time::format_description::well_known::Rfc3339;
    use vulkro_feeds::MockHttp;

    fn fixed_now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-02T00:00:00Z", &Rfc3339).unwrap()
    }

    const NPM_OLD_POPULAR: &str = r#"{
        "dist-tags": {"latest": "4.18.2"},
        "versions": {"4.18.2": {}},
        "time": {"created": "2010-12-29T19:38:25.450Z"}
    }"#;

    fn npm(name: &str) -> PackageRef {
        PackageRef::parse(name, Ecosystem::Npm).unwrap()
    }

    #[test]
    fn parse_plain_name() {
        assert_eq!(npm("express").name, "express");
        assert_eq!(npm("express").version, None);
    }

    #[test]
    fn parse_name_at_version() {
        let p = npm("express@4.18.2");
        assert_eq!(p.name, "express");
        assert_eq!(p.version.as_deref(), Some("4.18.2"));
    }

    #[test]
    fn parse_scoped_name_and_version() {
        assert_eq!(npm("@babel/core").name, "@babel/core");
        assert_eq!(npm("@babel/core").version, None);
        let p = npm("@babel/core@7.24.0");
        assert_eq!(p.name, "@babel/core");
        assert_eq!(p.version.as_deref(), Some("7.24.0"));
    }

    #[test]
    fn npm_express_is_ok() {
        let http = MockHttp::new()
            .on_get("registry.npmjs.org/express", 200, NPM_OLD_POPULAR)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("api.npmjs.org/downloads", 200, r#"{"downloads":50000000}"#);
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&npm("express"))
            .unwrap();
        assert_eq!(report.verdict, Verdict::Ok);
    }

    #[test]
    fn npm_nonexistent_is_missing() {
        // Downloads is intentionally not stubbed: a missing package must not
        // trigger a reputation request (the mock errors on unstubbed calls).
        let http = MockHttp::new()
            .on_get("registry.npmjs.org", 404, r#"{"error":"Not found"}"#)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#);
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&npm("some-name-that-does-not-exist-xyz"))
            .unwrap();
        assert_eq!(report.verdict, Verdict::Missing);
    }

    #[test]
    fn osv_flagged_name_is_malicious() {
        let http = MockHttp::new()
            .on_get("registry.npmjs.org", 200, NPM_OLD_POPULAR)
            .on_post(
                "api.osv.dev/v1/query",
                None,
                200,
                r#"{"vulns":[{"id":"MAL-2024-1095","summary":"credential stealer"}]}"#,
            );
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&npm("evil-pkg"))
            .unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.malicious_ids, vec!["MAL-2024-1095".to_string()]);
    }

    #[test]
    fn npm_unpublished_version_is_missing() {
        let http = MockHttp::new()
            .on_get("registry.npmjs.org", 200, NPM_OLD_POPULAR)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#);
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&npm("express@99.0.0"))
            .unwrap();
        assert_eq!(report.verdict, Verdict::Missing);
    }

    #[test]
    fn pypi_new_package_is_suspicious_on_age_alone() {
        // PyPI has no keyless downloads, so only age drives SUSPICIOUS. No
        // downloads stub is provided, proving no reputation download is made.
        let project = r#"{
            "info": {"version": "0.0.1"},
            "releases": {"0.0.1": [{"upload_time_iso_8601": "2026-06-29T00:00:00Z"}]}
        }"#;
        let http = MockHttp::new()
            .on_get("pypi.org/pypi/brand-new-lib/json", 200, project)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#);
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&PackageRef::parse("brand-new-lib", Ecosystem::PyPI).unwrap())
            .unwrap();
        assert_eq!(report.verdict, Verdict::Suspicious);
    }

    #[test]
    fn crates_existing_crate_is_ok_via_index_then_api() {
        let index = "{\"name\":\"serde\",\"vers\":\"1.0.200\"}\n";
        let api = r#"{"crate":{"created_at":"2014-12-05T20:00:00Z","max_stable_version":"1.0.200","recent_downloads":9000000}}"#;
        let http = MockHttp::new()
            .on_get("index.crates.io/se/rd/serde", 200, index)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("crates.io/api/v1/crates/serde", 200, api);
        let report = Verifier::new(&http)
            .with_now(fixed_now())
            .verify(&PackageRef::parse("serde", Ecosystem::Crates).unwrap())
            .unwrap();
        assert_eq!(report.verdict, Verdict::Ok);
        assert_eq!(report.latest_version.as_deref(), Some("1.0.200"));
    }

    #[test]
    #[ignore = "hits the live npm and OSV network; run with --ignored"]
    fn live_npm_express_is_ok() {
        let http = vulkro_feeds::UreqClient::new();
        let report = Verifier::new(&http).verify(&npm("express")).unwrap();
        assert_eq!(report.verdict, Verdict::Ok);
    }

    #[test]
    #[ignore = "hits the live PyPI and OSV network; run with --ignored"]
    fn live_pypi_requests_is_ok() {
        let http = vulkro_feeds::UreqClient::new();
        let report = Verifier::new(&http)
            .verify(&PackageRef::parse("requests", Ecosystem::PyPI).unwrap())
            .unwrap();
        assert_eq!(report.verdict, Verdict::Ok);
    }

    #[test]
    #[ignore = "hits the live crates.io and OSV network; run with --ignored"]
    fn live_crates_serde_is_ok() {
        let http = vulkro_feeds::UreqClient::new();
        let report = Verifier::new(&http)
            .verify(&PackageRef::parse("serde", Ecosystem::Crates).unwrap())
            .unwrap();
        assert_eq!(report.verdict, Verdict::Ok);
    }
}
