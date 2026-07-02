//! The verdict types and the pure classification policy.
//!
//! [`classify`] is a pure function of the gathered [`Signals`], the
//! [`Thresholds`], and an injected `now`, so its logic (including package-age
//! math) is fully unit-testable without a clock or the network.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use vulkro_feeds::MaliciousReport;

/// The per-package verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Exists, not malicious, healthy reputation.
    Ok,
    /// Not in the registry (a likely AI hallucination or slopsquat), or the
    /// requested version was never published.
    Missing,
    /// Flagged malicious by OSV (an OpenSSF `MAL-` record).
    Malicious,
    /// Exists but is suspiciously new or very low-download.
    Suspicious,
}

impl Verdict {
    /// The uppercase label shown to users and emitted in JSON.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::Missing => "MISSING",
            Verdict::Malicious => "MALICIOUS",
            Verdict::Suspicious => "SUSPICIOUS",
        }
    }

    /// Whether this verdict counts as flagged. Any flagged package makes the
    /// process exit with code 1.
    pub fn is_flagged(self) -> bool {
        !matches!(self, Verdict::Ok)
    }
}

/// Tunable thresholds for the SUSPICIOUS heuristic.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// A package created fewer than this many days ago is "very new".
    pub min_age_days: i64,
    /// A package with fewer than this many downloads is "low reputation".
    pub min_downloads: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_age_days: 30,
            min_downloads: 100,
        }
    }
}

/// The raw facts gathered about one package, before policy is applied.
#[derive(Debug, Default)]
pub struct Signals {
    /// Whether the package name exists in the registry.
    pub exists: bool,
    /// If a specific version was requested: whether that version is published.
    /// `None` when no version was requested.
    pub requested_version_exists: Option<bool>,
    /// A malicious-package report, if OSV flagged the package.
    pub malicious: Option<MaliciousReport>,
    /// The registry creation timestamp (RFC 3339), if known.
    pub created: Option<String>,
    /// The latest version, if known.
    pub latest_version: Option<String>,
    /// The download count, if the ecosystem exposes one keyless.
    pub downloads: Option<u64>,
    /// The window the download count covers ("weekly", "90-day"), for wording.
    pub downloads_window: Option<&'static str>,
}

/// Apply the verdict policy. Precedence: MALICIOUS, then MISSING, then
/// SUSPICIOUS, then OK. Malicious outranks missing so a known-bad name is
/// surfaced even if it has since been unpublished. Returns the verdict and a
/// short human-readable reason.
pub fn classify(
    signals: &Signals,
    thresholds: &Thresholds,
    now: OffsetDateTime,
) -> (Verdict, String) {
    // 1. Malicious outranks everything.
    if let Some(report) = &signals.malicious {
        let ids = report.ids.join(", ");
        let reason = match &report.summary {
            Some(summary) => format!("flagged malicious by OSV ({ids}): {summary}"),
            None => format!("flagged malicious by OSV ({ids})"),
        };
        return (Verdict::Malicious, reason);
    }

    // 2. Existence (whole package, then the requested version).
    if !signals.exists {
        return (Verdict::Missing, "not found in the registry".to_string());
    }
    if signals.requested_version_exists == Some(false) {
        return (
            Verdict::Missing,
            "the requested version was never published".to_string(),
        );
    }

    // 3. Reputation: very new, or very low download count.
    let mut reasons = Vec::new();
    if let Some(created) = &signals.created {
        if let Some(age) = age_days(created, now) {
            if age < thresholds.min_age_days {
                reasons.push(format!("created {age} day(s) ago"));
            }
        }
    }
    if let Some(downloads) = signals.downloads {
        if downloads < thresholds.min_downloads {
            reasons.push(format!("only {downloads} {} downloads", window(signals)));
        }
    }
    if !reasons.is_empty() {
        return (Verdict::Suspicious, reasons.join("; "));
    }

    // 4. Otherwise OK.
    (Verdict::Ok, ok_reason(signals))
}

/// Build a short descriptive reason for an OK package.
fn ok_reason(signals: &Signals) -> String {
    let mut bits = Vec::new();
    if let Some(latest) = &signals.latest_version {
        bits.push(format!("latest {latest}"));
    }
    if let Some(downloads) = signals.downloads {
        bits.push(format!("{downloads} {} downloads", window(signals)));
    }
    if bits.is_empty() {
        "exists with a healthy reputation".to_string()
    } else {
        bits.join(", ")
    }
}

/// The download-window word for messages, defaulting to "recent".
fn window(signals: &Signals) -> &'static str {
    signals.downloads_window.unwrap_or("recent")
}

/// Whole days between an RFC 3339 timestamp and `now`. `None` if unparseable.
fn age_days(created: &str, now: OffsetDateTime) -> Option<i64> {
    let created = OffsetDateTime::parse(created, &Rfc3339).ok()?;
    Some((now - created).whole_days())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-02T00:00:00Z", &Rfc3339).unwrap()
    }

    /// An old, popular, existing package.
    fn healthy() -> Signals {
        Signals {
            exists: true,
            requested_version_exists: None,
            malicious: None,
            created: Some("2010-01-01T00:00:00Z".to_string()),
            latest_version: Some("1.0.0".to_string()),
            downloads: Some(1_000_000),
            downloads_window: Some("weekly"),
        }
    }

    #[test]
    fn old_and_popular_is_ok() {
        let (verdict, _) = classify(&healthy(), &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Ok);
    }

    #[test]
    fn very_new_is_suspicious() {
        let mut signals = healthy();
        signals.created = Some("2026-06-25T00:00:00Z".to_string()); // 7 days old
        let (verdict, reason) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Suspicious);
        assert!(reason.contains("7 day"));
    }

    #[test]
    fn low_downloads_is_suspicious() {
        let mut signals = healthy();
        signals.downloads = Some(5);
        let (verdict, reason) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Suspicious);
        assert!(reason.contains("5 weekly downloads"));
    }

    #[test]
    fn missing_package_outranks_reputation() {
        let mut signals = healthy();
        signals.exists = false;
        let (verdict, _) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Missing);
    }

    #[test]
    fn missing_requested_version_is_missing() {
        let mut signals = healthy();
        signals.requested_version_exists = Some(false);
        let (verdict, _) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Missing);
    }

    #[test]
    fn malicious_outranks_missing() {
        let mut signals = healthy();
        signals.exists = false;
        signals.malicious = Some(MaliciousReport {
            ids: vec!["MAL-2024-1".to_string()],
            summary: None,
        });
        let (verdict, _) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn unparseable_created_does_not_trip_age() {
        let mut signals = healthy();
        signals.created = Some("not-a-date".to_string());
        let (verdict, _) = classify(&signals, &Thresholds::default(), now());
        assert_eq!(verdict, Verdict::Ok);
    }

    #[test]
    fn age_only_reputation_without_downloads_still_classifies() {
        // PyPI supplies no download count; a new package is still SUSPICIOUS on
        // age alone, and an old one with no downloads signal is OK.
        let mut signals = healthy();
        signals.downloads = None;
        signals.downloads_window = None;
        assert_eq!(
            classify(&signals, &Thresholds::default(), now()).0,
            Verdict::Ok
        );
        signals.created = Some("2026-06-30T00:00:00Z".to_string());
        assert_eq!(
            classify(&signals, &Thresholds::default(), now()).0,
            Verdict::Suspicious
        );
    }
}
