//! `sarif`: one shared SARIF 2.1.0 (and flat JSON) mapping layer for the whole
//! suite.
//!
//! Every finding-producing command already computes a typed report. This module
//! is the single place those reports become machine output, so the mapping stays
//! consistent as commands evolve and GitHub code-scanning can ingest any of them.
//! It performs no I/O and no network: it re-expresses findings already decided
//! on-machine, so nothing new leaves the machine and the leak boundary holds.
//!
//! Rule ids live in the reserved free namespace `vulkro-live/<command>/<slug>`
//! so they never collide with the paid engine's `vulkro/...` ids in a merged
//! code-scanning view.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::inspect::{InspectReport, Trust};
use crate::verify::report::PackageReport;
use crate::verify::verdict::Verdict;
use crate::warden::report::{Finding, Severity};

const TOOL_URI: &str = "https://vulkro.com";

/// Shared output-format selector for the finding-producing commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// A human-readable table (the default).
    #[default]
    Text,
    /// A flat JSON array of findings.
    Json,
    /// SARIF 2.1.0 for CI code-scanning (GitHub, etc.).
    Sarif,
}

/// The `result.level` values SARIF allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
}

impl SarifLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            SarifLevel::Error => "error",
            SarifLevel::Warning => "warning",
            SarifLevel::Note => "note",
        }
    }
}

/// A physical (file) and / or logical (tool / package name) location.
#[derive(Debug, Clone, Default)]
pub struct Loc {
    pub file: Option<String>,
    pub logical: Option<String>,
}

impl Loc {
    fn logical(name: impl Into<String>) -> Self {
        Loc {
            file: None,
            logical: Some(name.into()),
        }
    }

    fn file(path: impl Into<String>) -> Self {
        Loc {
            file: Some(path.into()),
            logical: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.file.is_none() && self.logical.is_none()
    }
}

/// One SARIF result, before serialization, in a tool-neutral shape.
#[derive(Debug, Clone)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: String,
    pub loc: Loc,
}

// --- level mappers -----------------------------------------------------------

/// High -> error, Medium -> warning, Low / Info -> note.
pub fn level_from_severity(sev: Severity) -> SarifLevel {
    match sev {
        Severity::High => SarifLevel::Error,
        Severity::Medium => SarifLevel::Warning,
        Severity::Low | Severity::Info => SarifLevel::Note,
    }
}

/// Malicious / Missing / Lookalike -> error, Vulnerable / Suspicious -> warning,
/// Ok -> note. Suspicious and Vulnerable are warnings (not errors) so a free
/// heuristic never reads as a hard CI failure it cannot justify.
pub fn level_from_verdict(v: Verdict) -> SarifLevel {
    match v {
        Verdict::Malicious | Verdict::Missing | Verdict::Lookalike => SarifLevel::Error,
        Verdict::Vulnerable | Verdict::Suspicious => SarifLevel::Warning,
        Verdict::Ok => SarifLevel::Note,
    }
}

/// Avoid -> error, Review -> warning, Green -> note.
pub fn level_from_trust(t: Trust) -> SarifLevel {
    match t {
        Trust::Avoid => SarifLevel::Error,
        Trust::Review => SarifLevel::Warning,
        Trust::Green => SarifLevel::Note,
    }
}

fn verdict_slug(v: Verdict) -> &'static str {
    match v {
        Verdict::Ok => "ok",
        Verdict::Missing => "missing",
        Verdict::Malicious => "malicious",
        Verdict::Lookalike => "lookalike",
        Verdict::Vulnerable => "vulnerable",
        Verdict::Suspicious => "suspicious",
    }
}

fn trust_slug(t: Trust) -> &'static str {
    match t {
        Trust::Green => "green",
        Trust::Review => "review",
        Trust::Avoid => "avoid",
    }
}

// --- per-report builders -----------------------------------------------------

/// verify: one result per flagged package (an OK verdict emits nothing).
pub fn results_from_verify(reports: &[PackageReport], manifest: Option<&Path>) -> Vec<SarifResult> {
    let mut out = Vec::new();
    for r in reports {
        if !r.verdict.is_flagged() {
            continue;
        }
        let loc = match manifest {
            Some(path) => Loc {
                file: Some(path.display().to_string()),
                logical: Some(r.display_name()),
            },
            None => Loc::logical(r.display_name()),
        };
        out.push(SarifResult {
            rule_id: format!("vulkro-live/verify/{}", verdict_slug(r.verdict)),
            level: level_from_verdict(r.verdict),
            message: format!("{} ({}): {}", r.display_name(), r.ecosystem.key(), r.reason),
            loc,
        });
    }
    out
}

/// verify --lockfile: the per-package verdicts (located at the lockfile) plus
/// the commodity `LOCKFILE-INTEGRITY` findings, all under the verify namespace.
/// Integrity rule ids are `vulkro-live/verify/lockfile-<category>`.
pub fn results_from_lockfile(
    report: &crate::verify::lockfile::LockfileReport,
    lockfile: &Path,
) -> Vec<SarifResult> {
    let mut out = results_from_verify(&report.packages, Some(lockfile));
    let source = lockfile.display().to_string();
    for f in &report.integrity {
        out.push(SarifResult {
            rule_id: format!("vulkro-live/verify/lockfile-{}", f.category),
            level: level_from_severity(f.severity),
            message: finding_message(f),
            loc: Loc {
                file: Some(source.clone()),
                logical: f.tool.clone(),
            },
        });
    }
    out
}

/// warden: one result per finding, located at the tool name (logical) and the
/// source file (physical) when the source is a real file.
pub fn results_from_warden(findings: &[Finding], source: &str) -> Vec<SarifResult> {
    findings
        .iter()
        .map(|f| SarifResult {
            rule_id: format!("vulkro-live/warden/{}", f.category),
            level: level_from_severity(f.severity),
            message: finding_message(f),
            loc: Loc {
                file: source_file(source),
                logical: f.tool.clone(),
            },
        })
        .collect()
}

/// inspect: the trust verdict (when flagged) plus every manifest finding, all
/// located at the server spec.
pub fn results_from_inspect(report: &InspectReport) -> Vec<SarifResult> {
    let mut out = Vec::new();
    if report.verdict.is_flagged() {
        let message = match (&report.package, &report.note) {
            (Some(pkg), _) => format!("{}: {} {}", report.spec, pkg.verdict.label(), pkg.reason),
            (None, Some(note)) => format!("{}: could not resolve: {note}", report.spec),
            (None, None) => report.spec.clone(),
        };
        out.push(SarifResult {
            rule_id: format!("vulkro-live/inspect/{}", trust_slug(report.verdict)),
            level: level_from_trust(report.verdict),
            message,
            loc: Loc::logical(report.spec.clone()),
        });
    }
    for f in &report.findings {
        out.push(SarifResult {
            rule_id: format!("vulkro-live/warden/{}", f.category),
            level: level_from_severity(f.severity),
            message: finding_message(f),
            loc: Loc::logical(report.spec.clone()),
        });
    }
    out
}

/// provenance: the trust verdict (when flagged) plus every provenance finding,
/// all located at the package name. Rule ids use the provenance namespace.
pub fn results_from_provenance(
    reports: &[crate::provenance::ProvenanceReport],
) -> Vec<SarifResult> {
    let mut out = Vec::new();
    for report in reports {
        if report.trust.is_flagged() {
            out.push(SarifResult {
                rule_id: format!("vulkro-live/provenance/{}", trust_slug(report.trust)),
                level: level_from_trust(report.trust),
                message: format!(
                    "{}: {} provenance",
                    report.display_name(),
                    match report.trust {
                        Trust::Avoid => "avoid",
                        Trust::Review => "review",
                        Trust::Green => "green",
                    }
                ),
                loc: Loc::logical(report.display_name()),
            });
        }
        for f in &report.findings {
            out.push(SarifResult {
                rule_id: format!("vulkro-live/provenance/{}", f.category),
                level: level_from_severity(f.severity),
                message: format!("{}: {}", report.display_name(), finding_message(f)),
                loc: Loc::logical(report.display_name()),
            });
        }
    }
    out
}

/// audit: every server (via inspect), instruction findings, and network hooks.
pub fn results_from_audit(report: &crate::audit::AuditReport) -> Vec<SarifResult> {
    let mut out = Vec::new();
    for server in &report.servers {
        out.extend(results_from_inspect(&server.report));
    }
    for text in &report.texts {
        out.extend(results_from_warden(&text.findings, &text.source));
    }
    for hook in &report.hooks {
        out.push(SarifResult {
            rule_id: "vulkro-live/audit/network-hook".to_string(),
            level: SarifLevel::Warning,
            message: format!("hook reaches the network: {}", hook.command),
            loc: Loc::file(hook.source.clone()),
        });
    }
    for secret in &report.secrets {
        out.push(SarifResult {
            rule_id: "vulkro-live/audit/config-secret".to_string(),
            level: SarifLevel::Error,
            message: format!(
                "{}: config value '{}' looks like a plaintext secret ({}, {})",
                secret.server, secret.key, secret.kind, secret.redacted
            ),
            loc: Loc::file(secret.source.clone()),
        });
    }
    for setting in &report.settings {
        out.push(SarifResult {
            rule_id: format!("vulkro-live/audit/{}", setting.kind),
            level: level_from_severity(setting.severity),
            message: setting.detail.clone(),
            loc: Loc::file(setting.source.clone()),
        });
    }
    out
}

/// foresee: one result per planted trap, located at the manifest.
pub fn results_from_foresee(report: &crate::foresee::ForeseeReport) -> Vec<SarifResult> {
    let manifest = report.manifest.display().to_string();
    report
        .traps
        .iter()
        .map(|trap| SarifResult {
            rule_id: "vulkro-live/foresee/trap".to_string(),
            level: level_from_verdict(trap.verdict),
            message: format!(
                "predicted name '{}' is already registered as a trap ({}): {}",
                trap.name,
                trap.verdict.label(),
                trap.reason
            ),
            loc: Loc {
                file: Some(manifest.clone()),
                logical: Some(trap.name.clone()),
            },
        })
        .collect()
}

/// skillscan: one result per finding, located at the skill path.
pub fn results_from_skillscan(report: &crate::skillscan::SkillscanReport) -> Vec<SarifResult> {
    let mut out = Vec::new();
    for skill in &report.skills {
        for f in &skill.findings {
            out.push(SarifResult {
                rule_id: format!("vulkro-live/skillscan/{}", f.category),
                level: level_from_severity(f.severity),
                message: format!("{}: {}", skill.name, finding_message(f)),
                loc: Loc {
                    file: Some(skill.path.clone()),
                    logical: Some(skill.name.clone()),
                },
            });
        }
    }
    out
}

/// memcheck: one result per finding, located at the memory artifact.
pub fn results_from_memcheck(report: &crate::memcheck::MemcheckReport) -> Vec<SarifResult> {
    let mut out = Vec::new();
    for artifact in &report.artifacts {
        for f in &artifact.findings {
            out.push(SarifResult {
                rule_id: format!("vulkro-live/memcheck/{}", f.category),
                level: level_from_severity(f.severity),
                message: finding_message(f),
                loc: Loc::file(artifact.source.clone()),
            });
        }
    }
    out
}

/// drift: one result per change, located at the tool name.
pub fn results_from_drift(report: &crate::lock::DriftReport) -> Vec<SarifResult> {
    report
        .changes
        .iter()
        .map(|c| SarifResult {
            rule_id: format!("vulkro-live/drift/{}", c.kind.key()),
            level: level_from_severity(c.severity),
            message: format!("{}: {}", c.tool, c.message),
            loc: Loc::logical(c.tool.clone()),
        })
        .collect()
}

fn finding_message(f: &Finding) -> String {
    match &f.evidence {
        Some(ev) => format!("{}: {} (evidence: {ev})", f.category, f.message),
        None => format!("{}: {}", f.category, f.message),
    }
}

/// A source label is a real physical file unless it is stdin / a dash / empty.
fn source_file(source: &str) -> Option<String> {
    if source.is_empty() || source == "stdin" || source == "-" || source == "--result" {
        None
    } else {
        Some(source.to_string())
    }
}

// --- serialization -----------------------------------------------------------

/// Serialize results as one SARIF 2.1.0 log. The rules[] table is derived from
/// the distinct rule ids present, in first-seen order, so every result's ruleId
/// resolves (GitHub rejects a run otherwise) and the output is deterministic.
pub fn render(results: Vec<SarifResult>) -> Result<String> {
    let mut rule_ids: Vec<&str> = Vec::new();
    for r in &results {
        if !rule_ids.contains(&r.rule_id.as_str()) {
            rule_ids.push(r.rule_id.as_str());
        }
    }
    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": id,
                "shortDescription": { "text": rule_short(id) },
                "helpUri": TOOL_URI,
            })
        })
        .collect();
    let result_values: Vec<Value> = results.iter().map(result_json).collect();

    let log = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vulkro-live",
                    "informationUri": TOOL_URI,
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "results": result_values,
        }],
    });
    serde_json::to_string_pretty(&log).context("serializing the SARIF log")
}

/// Serialize results as a flat JSON array (the machine format for the commands
/// that had no `--json` before). `--json` and `--format json` are identical.
pub fn render_json(results: &[SarifResult]) -> Result<String> {
    let arr: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "rule": r.rule_id,
                "level": r.level.as_str(),
                "message": r.message,
                "file": r.loc.file,
                "name": r.loc.logical,
            })
        })
        .collect();
    serde_json::to_string_pretty(&arr).context("serializing the JSON findings")
}

fn result_json(r: &SarifResult) -> Value {
    let mut obj = Map::new();
    obj.insert("ruleId".to_string(), Value::String(r.rule_id.clone()));
    obj.insert("level".to_string(), Value::String(r.level.as_str().to_string()));
    obj.insert("message".to_string(), json!({ "text": r.message }));
    if !r.loc.is_empty() {
        let mut location = Map::new();
        if let Some(file) = &r.loc.file {
            location.insert(
                "physicalLocation".to_string(),
                json!({ "artifactLocation": { "uri": file } }),
            );
        }
        if let Some(logical) = &r.loc.logical {
            location.insert(
                "logicalLocations".to_string(),
                json!([{ "fullyQualifiedName": logical, "kind": "module" }]),
            );
        }
        obj.insert("locations".to_string(), json!([Value::Object(location)]));
    }
    Value::Object(obj)
}

/// A short human description for a rule id: the last path segment, spaced.
fn rule_short(id: &str) -> String {
    let slug = id.rsplit('/').next().unwrap_or(id);
    slug.replace('-', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::report::PackageReport;
    use vulkro_feeds::Ecosystem;

    fn report(name: &str, verdict: Verdict) -> PackageReport {
        PackageReport {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: None,
            verdict,
            reason: "reason".to_string(),
            latest_version: None,
            created: None,
            downloads: None,
            malicious_ids: Vec::new(),
            vulnerability_ids: Vec::new(),
        }
    }

    #[test]
    fn severity_levels() {
        assert_eq!(level_from_severity(Severity::High), SarifLevel::Error);
        assert_eq!(level_from_severity(Severity::Medium), SarifLevel::Warning);
        assert_eq!(level_from_severity(Severity::Low), SarifLevel::Note);
        assert_eq!(level_from_severity(Severity::Info), SarifLevel::Note);
    }

    #[test]
    fn verdict_levels() {
        assert_eq!(level_from_verdict(Verdict::Malicious), SarifLevel::Error);
        assert_eq!(level_from_verdict(Verdict::Missing), SarifLevel::Error);
        assert_eq!(level_from_verdict(Verdict::Lookalike), SarifLevel::Error);
        assert_eq!(level_from_verdict(Verdict::Vulnerable), SarifLevel::Warning);
        assert_eq!(level_from_verdict(Verdict::Suspicious), SarifLevel::Warning);
        assert_eq!(level_from_verdict(Verdict::Ok), SarifLevel::Note);
    }

    #[test]
    fn trust_levels() {
        assert_eq!(level_from_trust(Trust::Avoid), SarifLevel::Error);
        assert_eq!(level_from_trust(Trust::Review), SarifLevel::Warning);
        assert_eq!(level_from_trust(Trust::Green), SarifLevel::Note);
    }

    #[test]
    fn verify_missing_with_manifest_has_both_locations() {
        let results =
            results_from_verify(&[report("ghost", Verdict::Missing)], Some(Path::new("package.json")));
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.rule_id, "vulkro-live/verify/missing");
        assert_eq!(r.level, SarifLevel::Error);
        assert_eq!(r.loc.file.as_deref(), Some("package.json"));
        assert_eq!(r.loc.logical.as_deref(), Some("ghost"));
    }

    #[test]
    fn verify_without_manifest_is_logical_only() {
        let results = results_from_verify(&[report("ghost", Verdict::Missing)], None);
        assert!(results[0].loc.file.is_none());
        assert_eq!(results[0].loc.logical.as_deref(), Some("ghost"));
    }

    #[test]
    fn verify_ok_emits_no_result() {
        let results = results_from_verify(&[report("express", Verdict::Ok)], None);
        assert!(results.is_empty());
    }

    #[test]
    fn warden_finding_maps_to_tool_and_rule() {
        let findings = vec![Finding {
            severity: Severity::High,
            category: "prompt-injection",
            tool: Some("evil".to_string()),
            message: "injection phrase".to_string(),
            evidence: None,
        }];
        let results = results_from_warden(&findings, "stdin");
        assert_eq!(results[0].rule_id, "vulkro-live/warden/prompt-injection");
        assert_eq!(results[0].level, SarifLevel::Error);
        assert_eq!(results[0].loc.logical.as_deref(), Some("evil"));
        assert!(results[0].loc.file.is_none()); // stdin is not a physical file
    }

    #[test]
    fn render_derives_rules_and_is_deterministic() {
        let results = results_from_verify(
            &[
                report("a", Verdict::Missing),
                report("b", Verdict::Missing),
                report("c", Verdict::Malicious),
            ],
            None,
        );
        let json = render(results.clone()).unwrap();
        // rules[] has exactly the two distinct ids in first-seen order.
        assert!(json.contains("vulkro-live/verify/missing"));
        assert!(json.contains("vulkro-live/verify/malicious"));
        // no wall-clock timestamp is emitted.
        assert!(!json.contains("invocations"));
        // serializing the same results twice is byte-identical.
        assert_eq!(json, render(results).unwrap());
    }

    #[test]
    fn render_empty_is_valid_log() {
        let json = render(Vec::new()).unwrap();
        assert!(json.contains("\"version\": \"2.1.0\""));
        assert!(json.contains("\"results\": []"));
    }

    #[test]
    fn rule_short_humanizes_the_slug() {
        assert_eq!(rule_short("vulkro-live/warden/prompt-injection"), "prompt injection");
    }
}
