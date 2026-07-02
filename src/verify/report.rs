//! The per-package report and its human / JSON rendering.

use anyhow::{Context, Result};
use serde::{Serialize, Serializer};

use vulkro_feeds::Ecosystem;

use super::verdict::Verdict;

/// The result of verifying one package.
#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    /// The ecosystem the package was checked in.
    #[serde(serialize_with = "serialize_ecosystem")]
    pub ecosystem: Ecosystem,
    /// The package name.
    pub name: String,
    /// The requested version, if the input was `name@version`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The verdict.
    #[serde(serialize_with = "serialize_verdict")]
    pub verdict: Verdict,
    /// A short human-readable explanation.
    pub reason: String,
    /// The latest version, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    /// The registry creation timestamp (RFC 3339), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// The download count, if the ecosystem exposes one keyless.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloads: Option<u64>,
    /// Matching OSV `MAL-` advisory ids, if any.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub malicious_ids: Vec<String>,
}

impl PackageReport {
    /// The `name` or `name@version` label for display.
    pub fn display_name(&self) -> String {
        match &self.version {
            Some(version) => format!("{}@{}", self.name, version),
            None => self.name.clone(),
        }
    }
}

fn serialize_verdict<S: Serializer>(verdict: &Verdict, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(verdict.label())
}

fn serialize_ecosystem<S: Serializer>(eco: &Ecosystem, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(eco.key())
}

/// Render an aligned text table, one row per package: ecosystem, name, verdict,
/// reason.
pub fn render_human(reports: &[PackageReport]) -> String {
    let eco_width = reports
        .iter()
        .map(|r| r.ecosystem.label().chars().count())
        .max()
        .unwrap_or(0);
    let name_width = reports
        .iter()
        .map(|r| r.display_name().chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for report in reports {
        out.push_str(&format!(
            "{eco:<eco_width$}  {name:<name_width$}  {verdict:<10}  {reason}\n",
            eco = report.ecosystem.label(),
            name = report.display_name(),
            verdict = report.verdict.label(),
            reason = report.reason,
        ));
    }
    out
}

/// Render the reports as a pretty-printed JSON array.
pub fn render_json(reports: &[PackageReport]) -> Result<String> {
    serde_json::to_string_pretty(reports).context("serializing the JSON report")
}

/// A one-line summary of how many packages landed in each verdict.
pub fn summary_line(reports: &[PackageReport]) -> String {
    let mut ok = 0;
    let mut missing = 0;
    let mut malicious = 0;
    let mut suspicious = 0;
    for report in reports {
        match report.verdict {
            Verdict::Ok => ok += 1,
            Verdict::Missing => missing += 1,
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => suspicious += 1,
        }
    }
    format!(
        "{total} checked: {ok} OK, {malicious} MALICIOUS, {missing} MISSING, {suspicious} SUSPICIOUS",
        total = reports.len(),
    )
}

/// The funnel note: public-metadata checks here, deeper analysis in the paid
/// offline scan. Message and pointer only, no paywall logic.
pub fn funnel_note() -> &'static str {
    "verify checks public package metadata. The full offline Vulkro scan adds deep dependency and code analysis. See https://vulkro.com"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PackageReport {
        PackageReport {
            ecosystem: Ecosystem::Npm,
            name: "express".to_string(),
            version: None,
            verdict: Verdict::Ok,
            reason: "latest 4.18.2".to_string(),
            latest_version: Some("4.18.2".to_string()),
            created: Some("2010-12-29T19:38:25.450Z".to_string()),
            downloads: Some(50_000_000),
            malicious_ids: Vec::new(),
        }
    }

    #[test]
    fn json_uses_labels_for_verdict_and_ecosystem() {
        let json = render_json(&[sample()]).unwrap();
        assert!(json.contains("\"verdict\": \"OK\""));
        assert!(json.contains("\"ecosystem\": \"npm\""));
        assert!(json.contains("\"downloads\": 50000000"));
    }

    #[test]
    fn json_omits_empty_optionals() {
        let json = render_json(&[sample()]).unwrap();
        assert!(!json.contains("malicious_ids"));
        assert!(!json.contains("\"version\""));
    }

    #[test]
    fn display_name_includes_version_when_present() {
        let mut report = sample();
        report.version = Some("4.18.2".to_string());
        assert_eq!(report.display_name(), "express@4.18.2");
    }

    #[test]
    fn summary_counts_each_verdict() {
        let line = summary_line(&[sample()]);
        assert_eq!(
            line,
            "1 checked: 1 OK, 0 MALICIOUS, 0 MISSING, 0 SUSPICIOUS"
        );
    }
}
