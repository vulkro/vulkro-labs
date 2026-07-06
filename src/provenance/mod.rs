//! `provenance`: a build-provenance / attestation PRESENCE bouncer.
//!
//! Before you trust a published package, provenance answers a commodity
//! question from public registry metadata: did the publisher attach build
//! provenance / attestations, and are they structurally well-formed? For npm it
//! reads the packument's `dist.attestations` / provenance signal; for PyPI it
//! reads PEP 740 attestation presence on the release files.
//!
//! On verification it is deliberately HONEST, exactly like `cardcheck` is for
//! signatures: this tool reports whether provenance is PRESENT and well-formed,
//! and it NEVER cryptographically verifies an attestation and never claims to.
//! The presence type ([`vulkro_feeds::AttestationPresence`]) has no "verified"
//! state by construction, so a verified attestation cannot be represented or
//! claimed. Cryptographic verification needs a trust root and a crypto stack
//! that are out of scope for a free commodity tool.
//!
//! A widely-used package published WITHOUT provenance is a REVIEW signal, not a
//! hard fail: most of the ecosystem still ships without attestations. A package
//! that is MISSING or MALICIOUS (surfaced by reusing `verify`) is an AVOID.

use anyhow::{Context, Result};

use vulkro_feeds::{registry, AttestationPresence, Ecosystem, HttpClient};

use crate::inspect::Trust;
use crate::verify::verdict::{Thresholds, Verdict};
use crate::verify::{PackageRef, Verifier};
use crate::warden::report::{Finding, Severity};

/// The provenance report for one package.
pub struct ProvenanceReport {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    /// The registry existence / malicious verdict (from the verify engine).
    pub verdict: Verdict,
    /// Structural provenance presence, or `None` when the ecosystem exposes no
    /// keyless provenance metadata (crates.io) so absence is "not available".
    pub presence: Option<AttestationPresence>,
    /// Attestation kinds the registry advertises (for display).
    pub kinds: Vec<String>,
    /// The source repository the package links to, if any.
    pub source_repo: Option<String>,
    pub findings: Vec<Finding>,
    pub trust: Trust,
}

impl ProvenanceReport {
    pub fn is_flagged(&self) -> bool {
        self.trust.is_flagged()
    }

    /// The `name` or `name@version` label for display.
    pub fn display_name(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }
}

/// Check the build-provenance presence for one package.
pub fn provenance(
    http: &dyn HttpClient,
    package: &PackageRef,
    thresholds: Thresholds,
) -> Result<ProvenanceReport> {
    // Reuse the verify engine so a MISSING / MALICIOUS package is an AVOID here
    // too: provenance on a hallucinated or malicious name is meaningless.
    let verified = Verifier::new(http)
        .with_thresholds(thresholds)
        .verify(package)
        .with_context(|| format!("verifying '{}'", package.name))?;

    let info = registry::provenance(http, package.ecosystem, &package.name, package.version.as_deref())
        .with_context(|| format!("reading provenance for '{}'", package.name))?;

    let supported = registry::provenance_supported(package.ecosystem);
    let mut findings = Vec::new();

    // 1. Registry verdict: a missing / malicious / lookalike package outranks
    // everything (provenance on a hallucinated or bad name is meaningless).
    if matches!(
        verified.verdict,
        Verdict::Missing | Verdict::Malicious | Verdict::Lookalike
    ) {
        findings.push(mk(
            Severity::High,
            "registry",
            format!("{}: {}", verified.verdict.label(), verified.reason),
        ));
    }

    // For an ecosystem with no keyless provenance metadata (crates.io) the
    // presence is reported as None ("not available"), never as a false Absent.
    let presence = if supported {
        info.as_ref().map(|i| i.presence)
    } else {
        None
    };
    let (kinds, source_repo) = match &info {
        Some(i) => (i.kinds.clone(), i.source_repo.clone()),
        None => (Vec::new(), None),
    };

    // 2. Provenance presence and well-formedness (never verification).
    if supported {
        match presence {
            Some(AttestationPresence::PresentWellFormed) => findings.push(mk(
                Severity::Info,
                "provenance",
                "provenance present and well-formed, NOT cryptographically verified by provenance"
                    .to_string(),
            )),
            Some(AttestationPresence::PresentMalformed) => findings.push(mk(
                Severity::Medium,
                "provenance",
                "provenance present but malformed (missing expected parts)".to_string(),
            )),
            // Absent provenance is a REVIEW signal only for a real package; for
            // a missing / malicious one the registry finding above dominates.
            Some(AttestationPresence::Absent) if !verified.verdict.is_flagged() => {
                findings.push(mk(
                    Severity::Low,
                    "provenance",
                    "published without build provenance / attestations; it cannot be traced \
                     to a source build. This is common today, so it is a review signal, not a \
                     hard fail"
                        .to_string(),
                ));
            }
            Some(AttestationPresence::Absent) => {}
            None => {}
        }
    } else {
        findings.push(mk(
            Severity::Info,
            "provenance",
            format!(
                "{} does not expose keyless build-provenance metadata; presence cannot be checked",
                package.ecosystem.label()
            ),
        ));
    }

    // 3. Source-repo note (informational). A linked repo is shown; a linked repo
    // that does not look like the package name is a low REVIEW hint.
    if let Some(repo) = &source_repo {
        if !repo_matches_name(repo, &package.name) {
            findings.push(mk(
                Severity::Low,
                "source-repo",
                format!(
                    "linked source repo '{repo}' does not obviously match the package name '{}'; \
                     confirm it is the intended source",
                    package.name
                ),
            ));
        }
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.category.cmp(b.category)));
    let trust = decide(&findings);

    Ok(ProvenanceReport {
        ecosystem: package.ecosystem,
        name: package.name.clone(),
        version: package.version.clone(),
        verdict: verified.verdict,
        presence,
        kinds,
        source_repo,
        findings,
        trust,
    })
}

/// Collapse findings into a Trust, mirroring inspect / cardcheck: any HIGH is
/// Avoid, any MEDIUM is Review, else Green. Absent provenance (a LOW finding)
/// stays GREEN so a normal, unattested-but-real package is not over-flagged.
fn decide(findings: &[Finding]) -> Trust {
    if findings.iter().any(|f| f.severity == Severity::High) {
        Trust::Avoid
    } else if findings.iter().any(|f| f.severity == Severity::Medium) {
        Trust::Review
    } else {
        Trust::Green
    }
}

/// A loose match between a source-repo URL and a package name: the URL contains
/// the bare package name OR, for a scoped npm name, the scope (a scoped package
/// like `@babel/core` legitimately lives under the org repo `babel/babel`). A
/// commodity heuristic whose failure mode is an under-flag (a missed mismatch),
/// never a false AVOID (it is LOW only).
fn repo_matches_name(repo: &str, name: &str) -> bool {
    let repo = repo.to_ascii_lowercase();
    let name_lower = name.to_ascii_lowercase();
    // The scope of a scoped npm name (`@scope/x` -> `scope`), if any.
    if let Some(rest) = name_lower.strip_prefix('@') {
        if let Some((scope, _)) = rest.split_once('/') {
            if !scope.is_empty() && repo.contains(scope) {
                return true;
            }
        }
    }
    let bare = name_lower
        .rsplit('/')
        .next()
        .unwrap_or(&name_lower)
        .to_ascii_lowercase();
    if bare.is_empty() {
        return true;
    }
    repo.contains(&bare)
}

fn mk(severity: Severity, category: &'static str, message: String) -> Finding {
    Finding {
        severity,
        category,
        tool: None,
        message,
        evidence: None,
    }
}

/// Render a compact human report, mirroring inspect / cardcheck.
pub fn render_human(report: &ProvenanceReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}  {} ({})\n",
        report.trust.label(),
        report.display_name(),
        report.ecosystem.label()
    ));
    out.push_str(&format!("  registry   {}\n", report.verdict.label()));

    let presence = match report.presence {
        Some(AttestationPresence::Absent) => "absent",
        Some(AttestationPresence::PresentWellFormed) => {
            "present, well-formed, NOT cryptographically verified by provenance"
        }
        Some(AttestationPresence::PresentMalformed) => "present but malformed",
        None => "not available for this ecosystem",
    };
    out.push_str(&format!("  provenance {presence}\n"));
    if !report.kinds.is_empty() {
        out.push_str(&format!("  kinds      {}\n", report.kinds.join(", ")));
    }
    out.push_str(&format!(
        "  source     {}\n",
        report.source_repo.as_deref().unwrap_or("none linked")
    ));

    if !report.findings.is_empty() {
        out.push_str("  findings:\n");
        for f in &report.findings {
            out.push_str(&format!(
                "    {:<6} {:<12} {}\n",
                f.severity.label(),
                f.category,
                f.message,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vulkro_feeds::MockHttp;

    const NPM_OLD_POPULAR: &str = r#"{
        "dist-tags": {"latest": "4.18.2"},
        "versions": {"4.18.2": {}},
        "time": {"created": "2010-12-29T19:38:25.450Z"}
    }"#;

    fn npm(name: &str) -> PackageRef {
        PackageRef::parse(name, Ecosystem::Npm).unwrap()
    }

    #[test]
    fn present_wellformed_is_green_and_never_says_verified() {
        // A real, popular package published WITH provenance.
        let packument = r#"{
            "dist-tags": {"latest": "4.18.2"},
            "versions": {"4.18.2": {"dist": {"attestations": {"url": "https://registry.npmjs.org/-/npm/v1/attestations/express@4.18.2", "provenance": {"predicateType": "x"}}}}},
            "time": {"created": "2010-12-29T19:38:25.450Z"}
        }"#;
        let http = MockHttp::new()
            .on_get("registry.npmjs.org/express", 200, packument)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("api.npmjs.org/downloads", 200, r#"{"downloads":50000000}"#);
        let report = provenance(&http, &npm("express"), Thresholds::default()).unwrap();
        assert_eq!(report.trust, Trust::Green);
        assert_eq!(report.presence, Some(AttestationPresence::PresentWellFormed));

        // The output must NEVER claim a verified attestation.
        let rendered = render_human(&report);
        assert!(rendered.contains("NOT cryptographically verified"));
        assert!(!rendered.to_lowercase().contains("verified attestation"));
        assert!(!rendered.to_lowercase().contains("provenance verified"));
        assert!(!rendered.to_lowercase().contains("valid provenance"));
    }

    #[test]
    fn absent_provenance_on_real_package_is_green_review_signal() {
        // No attestations: a LOW review signal, still GREEN (not over-flagged).
        let http = MockHttp::new()
            .on_get("registry.npmjs.org/express", 200, NPM_OLD_POPULAR)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("api.npmjs.org/downloads", 200, r#"{"downloads":50000000}"#);
        let report = provenance(&http, &npm("express"), Thresholds::default()).unwrap();
        assert_eq!(report.presence, Some(AttestationPresence::Absent));
        assert_eq!(report.trust, Trust::Green);
        assert!(report
            .findings
            .iter()
            .any(|f| f.category == "provenance" && f.severity == Severity::Low));
    }

    #[test]
    fn malformed_provenance_is_review() {
        let packument = r#"{
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {"dist": {"attestations": {"provenance": {"x": 1}}}}},
            "time": {"created": "2010-12-29T19:38:25.450Z"}
        }"#;
        let http = MockHttp::new()
            .on_get("registry.npmjs.org/thing", 200, packument)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("api.npmjs.org/downloads", 200, r#"{"downloads":5000000}"#);
        let report = provenance(&http, &npm("thing"), Thresholds::default()).unwrap();
        assert_eq!(report.presence, Some(AttestationPresence::PresentMalformed));
        assert_eq!(report.trust, Trust::Review);
    }

    #[test]
    fn missing_package_is_avoid() {
        let http = MockHttp::new()
            .on_get("registry.npmjs.org", 404, r#"{"error":"Not found"}"#)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#);
        let report = provenance(&http, &npm("ghost-xyz-nope"), Thresholds::default()).unwrap();
        assert_eq!(report.verdict, Verdict::Missing);
        assert_eq!(report.trust, Trust::Avoid);
    }

    #[test]
    fn malicious_package_is_avoid() {
        let http = MockHttp::new()
            .on_get("registry.npmjs.org/evil", 200, NPM_OLD_POPULAR)
            .on_post(
                "api.osv.dev/v1/query",
                None,
                200,
                r#"{"vulns":[{"id":"MAL-2024-1","summary":"stealer"}]}"#,
            );
        let report = provenance(&http, &npm("evil"), Thresholds::default()).unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.trust, Trust::Avoid);
    }

    #[test]
    fn crates_reports_provenance_not_available_without_error() {
        let index = "{\"name\":\"serde\",\"vers\":\"1.0.200\"}\n";
        let api = r#"{"crate":{"created_at":"2014-12-05T20:00:00Z","max_stable_version":"1.0.200","recent_downloads":9000000}}"#;
        let http = MockHttp::new()
            .on_get("index.crates.io/se/rd/serde", 200, index)
            .on_post("api.osv.dev/v1/query", None, 200, r#"{"vulns":[]}"#)
            .on_get("crates.io/api/v1/crates/serde", 200, api);
        let report = provenance(
            &http,
            &PackageRef::parse("serde", Ecosystem::Crates).unwrap(),
            Thresholds::default(),
        )
        .unwrap();
        assert_eq!(report.trust, Trust::Green);
        let rendered = render_human(&report);
        assert!(rendered.contains("not available for this ecosystem"));
    }

    #[test]
    fn repo_match_heuristic() {
        assert!(repo_matches_name("https://github.com/expressjs/express", "express"));
        assert!(repo_matches_name("git+https://github.com/babel/babel.git", "@babel/core"));
        assert!(!repo_matches_name("https://github.com/attacker/typosquat", "left-pad"));
    }

    #[test]
    fn decide_matches_inspect_semantics() {
        assert_eq!(decide(&[mk(Severity::High, "x", "m".into())]), Trust::Avoid);
        assert_eq!(decide(&[mk(Severity::Medium, "x", "m".into())]), Trust::Review);
        assert_eq!(decide(&[mk(Severity::Low, "x", "m".into())]), Trust::Green);
    }
}
