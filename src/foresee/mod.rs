//! `foresee`: find the slopsquat traps planted for THIS project before your AI
//! ever names one.
//!
//! Every other supply-chain check is reactive: a name appears, then it is
//! checked. foresee is predictive. It reads the project's real dependency stack
//! and deterministically enumerates the plausible-but-absent package names an
//! LLM is statistically likely to invent for a project like this, then checks
//! each against the registry (reusing `verify`). A predicted name that is
//! already registered, recently and with near-zero reputation, is a trap lying
//! in wait. Names that do not exist yet are written to a committable guardrail
//! file the agent can be told never to install.
//!
//! Pure keyless commodity: deterministic string combinatorics plus the same
//! public registry checks `verify` already makes. No model, no backend.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use vulkro_feeds::{Ecosystem, HttpClient};

use crate::trust::TrustStore;
use crate::verify::manifest;
use crate::verify::report::PackageReport;
use crate::verify::verdict::{Thresholds, Verdict};
use crate::verify::{PackageRef, Verifier};

/// A registered package is only counted a planted trap (not just an obscure
/// real package) when it was created within this many days.
const FRESH_TRAP_DAYS: i64 = 365;
/// ... and has fewer than this many weekly downloads.
const FRESH_TRAP_DOWNLOADS: u64 = 50;

/// The default number of predicted names checked against the registry.
pub const DEFAULT_LIMIT: usize = 80;

/// A predicted name that already exists and looks planted.
pub struct Trap {
    pub name: String,
    pub verdict: Verdict,
    pub reason: String,
}

/// The result of a foresee run.
pub struct ForeseeReport {
    pub ecosystem: Ecosystem,
    pub manifest: PathBuf,
    pub checked: usize,
    pub traps: Vec<Trap>,
    /// Predicted names to never install (both absent hallucinations and traps).
    pub guardrail: Vec<String>,
}

impl ForeseeReport {
    pub fn is_flagged(&self) -> bool {
        !self.traps.is_empty()
    }
}

/// Predict and check the slopsquat surface for the project rooted at `dir`.
pub fn foresee(
    http: &dyn HttpClient,
    dir: &Path,
    limit: usize,
    thresholds: Thresholds,
    trust: Option<&TrustStore>,
) -> Result<ForeseeReport> {
    let manifest_path = find_manifest(dir).with_context(|| {
        format!(
            "no dependency manifest (package.json, requirements.txt, pyproject.toml, or \
             Cargo.toml) found in {}; foresee needs your stack to predict what your AI \
             might invent",
            dir.display()
        )
    })?;
    let (ecosystem, existing) = manifest::read_manifest(&manifest_path)?;

    let names: Vec<String> = candidates(ecosystem, &existing)
        .into_iter()
        .take(limit)
        .collect();
    let checked = names.len();

    let verifier = Verifier::new(http).with_thresholds(thresholds);
    let mut traps = Vec::new();
    let mut guardrail = Vec::new();
    for name in names {
        let package = PackageRef {
            ecosystem,
            name: name.clone(),
            version: None,
        };
        let report = verifier
            .verify(&package)
            .with_context(|| format!("checking predicted name '{name}'"))?;
        // A predicted name the developer has explicitly cleared at its current
        // version is not a trap: skip it.
        if let Some(store) = trust {
            if let Some(version) = report.latest_version.as_deref() {
                if store.allows_package(ecosystem, &name, version) {
                    continue;
                }
            }
        }
        match report.verdict {
            // A name that does not exist yet: a pure hallucination to guard.
            Verdict::Missing => guardrail.push(name),
            // Registered and flagged bad, or a typosquat: a definite trap.
            Verdict::Malicious | Verdict::Lookalike => {
                guardrail.push(name.clone());
                traps.push(Trap {
                    name,
                    verdict: report.verdict,
                    reason: report.reason,
                });
            }
            // A low-reputation, established, or CVE-carrying package matching a
            // predicted name is a planted trap only if it is freshly registered
            // AND barely used; an old or popular package is a real (if obscure)
            // package an AI could legitimately reach for, not a trap.
            Verdict::Suspicious | Verdict::Ok | Verdict::Vulnerable => {
                if is_fresh_squat(&report) {
                    guardrail.push(name.clone());
                    traps.push(Trap {
                        name,
                        verdict: report.verdict,
                        reason: report.reason,
                    });
                }
            }
        }
    }

    Ok(ForeseeReport {
        ecosystem,
        manifest: manifest_path,
        checked,
        traps,
        guardrail,
    })
}

/// Whether a registered package looks freshly planted (created recently and
/// barely used) rather than a real but obscure package. A missing download
/// count (a brand-new package with no stats) counts as low.
fn is_fresh_squat(report: &PackageReport) -> bool {
    let recent = report
        .created
        .as_deref()
        .and_then(age_days)
        .map(|days| days <= FRESH_TRAP_DAYS)
        .unwrap_or(false);
    let low_use = report
        .downloads
        .map(|d| d < FRESH_TRAP_DOWNLOADS)
        .unwrap_or(true);
    recent && low_use
}

/// Whole days since an RFC 3339 timestamp, or `None` if unparseable.
fn age_days(created: &str) -> Option<i64> {
    let created = OffsetDateTime::parse(created, &Rfc3339).ok()?;
    Some((OffsetDateTime::now_utc() - created).whole_days())
}

/// Render a human report.
pub fn render_human(report: &ForeseeReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "foresee: checked {} predicted name(s) your AI might invent for this {} project ({}).\n",
        report.checked,
        report.ecosystem.label(),
        report.manifest.display(),
    ));

    if report.traps.is_empty() {
        out.push_str("\nNo planted trap found: none of the predicted names is a registered squat yet.\n");
    } else {
        out.push_str(&format!(
            "\n{} planted trap(s) already waiting in the registry:\n",
            report.traps.len()
        ));
        for trap in &report.traps {
            out.push_str(&format!(
                "  TRAP  {:<32} {:<11} {}\n",
                trap.name,
                trap.verdict.label(),
                trap.reason,
            ));
        }
    }
    out
}

/// Write the guardrail file the agent can be pointed at.
pub fn write_guardrail(dir: &Path, report: &ForeseeReport) -> Result<PathBuf> {
    let doc = json!({
        "note": "Package names your AI might hallucinate for this project. Do not install any of \
                 these unless you deliberately and independently confirmed it.",
        "ecosystem": report.ecosystem.key(),
        "do_not_install": report.guardrail,
        "planted_traps": report
            .traps
            .iter()
            .map(|t| json!({"name": t.name, "verdict": t.verdict.label(), "reason": t.reason}))
            .collect::<Vec<_>>(),
    });
    let path = dir.join(".vulkro-foresee.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

// --- candidate generation ----------------------------------------------------

/// Deterministically enumerate plausible-but-absent names for the project: the
/// project's own dependency names (most relevant, emitted first) and a few "AI
/// magnet" packages LLMs cluster hallucinations around, each combined with the
/// affixes an LLM reaches for.
fn candidates(ecosystem: Ecosystem, existing: &[String]) -> Vec<String> {
    let existing_set: HashSet<String> = existing.iter().map(|n| n.to_lowercase()).collect();
    let (suffixes, prefixes) = affixes(ecosystem);

    let mut seeds: Vec<String> = Vec::new();
    let mut seed_seen = HashSet::new();
    for name in existing {
        let seed = base_name(name);
        if !seed.is_empty() && seed_seen.insert(seed.clone()) {
            seeds.push(seed);
        }
    }
    for &magnet in ai_magnets(ecosystem) {
        if seed_seen.insert(magnet.to_string()) {
            seeds.push(magnet.to_string());
        }
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for seed in &seeds {
        let mut variants: Vec<String> = Vec::new();
        for suffix in suffixes {
            variants.push(format!("{seed}{suffix}"));
        }
        for prefix in prefixes {
            variants.push(format!("{prefix}{seed}"));
        }
        for variant in variants {
            let lower = variant.to_lowercase();
            if !existing_set.contains(&lower) && seen.insert(lower.clone()) {
                out.push(lower);
            }
        }
    }
    out
}

/// The unscoped, lowercased base of a package name (`@babel/core` -> `core`).
fn base_name(name: &str) -> String {
    let unscoped = name
        .strip_prefix('@')
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, n)| n)
        .unwrap_or(name);
    unscoped.to_lowercase()
}

/// (suffixes, prefixes) an LLM reaches for, per ecosystem.
fn affixes(ecosystem: Ecosystem) -> (&'static [&'static str], &'static [&'static str]) {
    match ecosystem {
        Ecosystem::Npm => (
            &[
                "-utils", "-util", "-helper", "-helpers", "-toolkit", "-sdk", "-client", "-core",
                "-async", "-pro", "-plus", "-cli", "-config", "-middleware", "-api", "-tools",
                "-wrapper", "-lite", "-hooks", "-js",
            ],
            &["use-", "node-"],
        ),
        Ecosystem::PyPI => (
            &[
                "-utils", "-helper", "-client", "-sdk", "-toolkit", "-async", "-tools", "-api",
                "-core", "-plus", "-lib", "-py",
            ],
            &["py-", "python-"],
        ),
        Ecosystem::Crates => (
            &[
                "-utils", "-helper", "-client", "-sdk", "-core", "-async", "-tools", "-derive",
                "-macros",
            ],
            &[],
        ),
    }
}

/// Popular packages LLMs commonly hallucinate variants around.
fn ai_magnets(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &[
            "openai", "langchain", "react", "express", "axios", "next", "vue", "tailwindcss",
            "stripe", "firebase", "supabase", "prisma", "zod", "vitest", "puppeteer",
        ],
        Ecosystem::PyPI => &[
            "openai", "langchain", "requests", "fastapi", "django", "flask", "pandas", "numpy",
            "transformers", "pydantic", "httpx", "sqlalchemy", "celery", "boto3",
        ],
        Ecosystem::Crates => &[
            "serde", "tokio", "axum", "reqwest", "clap", "sqlx", "anyhow", "tracing",
        ],
    }
}

/// The first known manifest present in `dir`.
fn find_manifest(dir: &Path) -> Option<PathBuf> {
    for file in [
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Cargo.toml",
    ] {
        let path = dir.join(file);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_combine_deps_with_affixes_and_exclude_existing() {
        let existing = vec!["express".to_string(), "react".to_string()];
        let out = candidates(Ecosystem::Npm, &existing);
        assert!(out.contains(&"express-utils".to_string()));
        assert!(out.contains(&"use-react".to_string()));
        // The real dependency itself is never a candidate.
        assert!(!out.contains(&"express".to_string()));
        assert!(!out.contains(&"react".to_string()));
    }

    #[test]
    fn scoped_names_seed_from_the_unscoped_part() {
        assert_eq!(base_name("@babel/core"), "core");
        assert_eq!(base_name("express"), "express");
    }

    #[test]
    fn ai_magnets_seed_even_with_no_deps() {
        let out = candidates(Ecosystem::PyPI, &[]);
        assert!(out.contains(&"langchain-sdk".to_string()));
    }

    #[test]
    fn candidates_are_deduped() {
        let existing = vec!["openai".to_string()]; // also an npm magnet
        let out = candidates(Ecosystem::Npm, &existing);
        let dupes = out.iter().filter(|c| *c == "openai-sdk").count();
        assert_eq!(dupes, 1);
    }
}
