//! A deterministic snapshot of the audited surface, for `--diff` and
//! `--write-baseline`.
//!
//! The snapshot is a committable, diff-friendly file (sorted, deduped, no
//! timestamps: git records who and when). `diff` reports only what appeared
//! since the baseline, so a reviewer sees exactly what changed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::warden::report::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Snapshot {
    pub servers: Vec<String>,
    pub dangerous: Vec<String>,
    pub network_hooks: Vec<String>,
    pub secret_keys: Vec<String>,
}

impl Snapshot {
    /// Sort and dedup every list so the file is deterministic and diff-friendly.
    pub fn normalized(mut self) -> Snapshot {
        for list in [
            &mut self.servers,
            &mut self.dangerous,
            &mut self.network_hooks,
            &mut self.secret_keys,
        ] {
            list.sort();
            list.dedup();
        }
        self
    }
}

pub fn load_baseline(path: &Path) -> Result<Snapshot> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading baseline {}; regenerate it with `vulkro-live audit --write-baseline {}`",
            path.display(),
            path.display()
        )
    })?;
    let snap: Snapshot = serde_json::from_str(&text)
        .with_context(|| format!("parsing baseline {} (is it a valid audit snapshot?)", path.display()))?;
    Ok(snap.normalized())
}

pub fn write_baseline(path: &Path, snap: &Snapshot) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(snap).context("serializing the audit snapshot")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(path.to_path_buf())
}

/// Findings for everything present now but absent in the baseline.
pub fn diff(baseline: &Snapshot, current: &Snapshot) -> Vec<Finding> {
    let mut findings = Vec::new();
    let added = |old: &[String], new: &[String]| -> Vec<String> {
        new.iter().filter(|x| !old.contains(x)).cloned().collect()
    };
    for s in added(&baseline.dangerous, &current.dangerous) {
        findings.push(mk(Severity::High, "diff-setting-added", format!("new dangerous setting since the baseline: {s}")));
    }
    for s in added(&baseline.secret_keys, &current.secret_keys) {
        findings.push(mk(Severity::High, "diff-secret-added", format!("new config secret since the baseline: {s}")));
    }
    for s in added(&baseline.servers, &current.servers) {
        findings.push(mk(Severity::Medium, "diff-server-added", format!("new MCP server since the baseline: {s}")));
    }
    for s in added(&baseline.network_hooks, &current.network_hooks) {
        findings.push(mk(Severity::Medium, "diff-network-hook", format!("new network hook since the baseline: {s}")));
    }
    findings
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_sorts_and_dedups() {
        let s = Snapshot {
            servers: vec!["b".into(), "a".into(), "b".into()],
            ..Default::default()
        }
        .normalized();
        assert_eq!(s.servers, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn diff_reports_only_additions() {
        let baseline = Snapshot {
            servers: vec!["npx old-server".into()],
            ..Default::default()
        }
        .normalized();
        let current = Snapshot {
            servers: vec!["npx old-server".into(), "npx new-server".into()],
            dangerous: vec!["auto-approve: x".into()],
            network_hooks: vec!["curl http://x".into()],
            secret_keys: vec!["srv/TOKEN".into()],
        }
        .normalized();
        let findings = diff(&baseline, &current);
        assert_eq!(findings.len(), 4);
        assert!(findings.iter().any(|f| f.category == "diff-server-added"));
        assert!(findings.iter().any(|f| f.category == "diff-setting-added" && f.severity == Severity::High));
        assert!(findings.iter().any(|f| f.category == "diff-secret-added" && f.severity == Severity::High));
        assert!(findings.iter().any(|f| f.category == "diff-network-hook"));
    }

    #[test]
    fn identical_snapshots_have_no_drift() {
        let s = Snapshot {
            servers: vec!["a".into()],
            ..Default::default()
        }
        .normalized();
        assert!(diff(&s, &s).is_empty());
    }
}
