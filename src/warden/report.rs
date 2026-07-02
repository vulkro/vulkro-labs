//! `warden` findings and their human / JSON rendering.

use anyhow::{Context, Result};
use serde::{Serialize, Serializer};

/// Finding severity. Ordering (High < Medium < Low < Info) is used to sort
/// most-severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// The uppercase label shown to users and emitted in JSON.
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    /// Whether this severity should fail the run (exit code 1). High and Medium
    /// are actionable; Low and Info are informational.
    pub fn is_actionable(self) -> bool {
        matches!(self, Severity::High | Severity::Medium)
    }
}

/// One thing `warden` noticed about an MCP tool manifest.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    #[serde(serialize_with = "serialize_severity")]
    pub severity: Severity,
    /// A short category, e.g. `prompt-injection`, `tool-shadowing`.
    pub category: &'static str,
    /// The tool this finding is about, if it is tool-specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// A human-readable explanation.
    pub message: String,
    /// A short snippet of the offending text, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

fn serialize_severity<S: Serializer>(sev: &Severity, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(sev.label())
}

/// Whether any finding is actionable (High or Medium).
pub fn any_actionable(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity.is_actionable())
}

/// Render an aligned text table, one row per finding, most severe first.
pub fn render_human(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No issues found in the MCP tool manifest.\n".to_string();
    }
    let tool_width = findings
        .iter()
        .map(|f| f.tool.as_deref().unwrap_or("-").chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for finding in findings {
        out.push_str(&format!(
            "{sev:<6}  {tool:<tool_width$}  {category:<16}  {message}\n",
            sev = finding.severity.label(),
            tool = finding.tool.as_deref().unwrap_or("-"),
            category = finding.category,
            message = finding.message,
        ));
        if let Some(evidence) = &finding.evidence {
            out.push_str(&format!(
                "{:<6}  {:<tool_width$}  {:<16}  evidence: {evidence}\n",
                "", "", "",
            ));
        }
    }
    out
}

/// Render the findings as a pretty-printed JSON array.
pub fn render_json(findings: &[Finding]) -> Result<String> {
    serde_json::to_string_pretty(findings).context("serializing the JSON findings")
}

/// A one-line summary counting findings by severity.
pub fn summary_line(findings: &[Finding]) -> String {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;
    for finding in findings {
        match finding.severity {
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }
    format!(
        "{total} finding(s): {high} HIGH, {medium} MEDIUM, {low} LOW, {info} INFO",
        total = findings.len(),
    )
}

/// The funnel note: static heuristics here, deeper analysis in the paid scan.
/// Message and pointer only, no paywall logic.
pub fn funnel_note() -> &'static str {
    "warden runs static, commodity heuristics on tool metadata. The full offline Vulkro scan adds deeper analysis. See https://vulkro.com"
}
