//! Parse a dependency LOCKFILE and emit commodity `LOCKFILE-INTEGRITY`
//! findings, on top of `verify`'s normal per-package verdicts.
//!
//! A manifest (`package.json`, `requirements.txt`) lists version RANGES; a
//! lockfile pins the EXACT resolved version, its download URL, and an integrity
//! hash. That extra pinned metadata makes three supply-chain problems
//! commodity-detectable without any closed engine:
//!
//!   - a `resolved` / tarball URL that points OFF the official registry host
//!     (the dependency-repoint / registry-confusion class);
//!   - a locked version that is missing its integrity hash where the ecosystem
//!     normally records one;
//!   - a locked version that no longer exists / was unpublished, or is flagged
//!     MALICIOUS (surfaced by re-running the `verify` engine per package).
//!
//! Everything here is string / URL / host inspection and structural parsing of
//! public lockfile formats: no taint, no dataflow, no detector logic. The
//! ecosystem is inferred from the file name, exactly like [`super::manifest`].

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use vulkro_feeds::Ecosystem;

use crate::warden::report::{Finding, Severity};

/// One exact dependency pinned by a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedEntry {
    /// The package / crate name.
    pub name: String,
    /// The exact locked version, when the format records one.
    pub version: Option<String>,
    /// The `resolved` / tarball URL the artifact is fetched from, if any.
    pub resolved: Option<String>,
    /// Whether the entry carries an integrity / checksum hash.
    pub has_integrity: bool,
}

/// The parsed lockfile: its ecosystem and every locked entry.
#[derive(Debug, Clone)]
pub struct Lockfile {
    pub ecosystem: Ecosystem,
    pub entries: Vec<LockedEntry>,
}

/// The official registry host(s) an ecosystem resolves artifacts from. A
/// `resolved` URL whose host is not one of these is the off-registry signal.
///
/// For crates.io the canonical `source` is `registry+https://github.com/
/// rust-lang/crates.io-index` (a git index hosted on github.com), so github.com
/// is accepted as the canonical index host alongside the artifact CDN hosts.
/// This is deliberately narrow: only the exact canonical crates index counts.
fn official_hosts(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &["registry.npmjs.org"],
        Ecosystem::PyPI => &["files.pythonhosted.org", "pypi.org"],
        Ecosystem::Crates => &["static.crates.io", "crates.io", "index.crates.io"],
    }
}

/// The canonical crates.io index source string. A `Cargo.lock` `source` that is
/// exactly this is the default registry; anything else is off-registry.
const CRATES_CANONICAL_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Read and parse a lockfile, inferring the ecosystem from its file name.
pub fn read_lockfile(path: &Path) -> Result<Lockfile> {
    let ecosystem = infer_ecosystem(path)?;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let entries = match lockfile_kind(path)? {
        LockKind::NpmPackageLock => parse_package_lock(&text)?,
        LockKind::YarnLock => parse_yarn_lock(&text),
        LockKind::PnpmLock => parse_pnpm_lock(&text),
        LockKind::CargoLock => parse_cargo_lock(&text)?,
        LockKind::PoetryLock => parse_poetry_lock(&text)?,
        LockKind::RequirementsTxt => parse_hashed_requirements(&text),
    };
    Ok(Lockfile { ecosystem, entries })
}

/// The concrete lockfile format, from the file name.
enum LockKind {
    NpmPackageLock,
    YarnLock,
    PnpmLock,
    CargoLock,
    PoetryLock,
    RequirementsTxt,
}

fn lockfile_kind(path: &Path) -> Result<LockKind> {
    let file = file_name_lower(path);
    match file.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => Ok(LockKind::NpmPackageLock),
        "yarn.lock" => Ok(LockKind::YarnLock),
        "pnpm-lock.yaml" => Ok(LockKind::PnpmLock),
        "cargo.lock" => Ok(LockKind::CargoLock),
        "poetry.lock" => Ok(LockKind::PoetryLock),
        f if f.starts_with("requirements") && f.ends_with(".txt") => Ok(LockKind::RequirementsTxt),
        other => anyhow::bail!(
            "cannot tell which lockfile '{other}' is; supported lockfiles are \
             package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, poetry.lock, \
             and a hashed requirements.txt"
        ),
    }
}

/// Infer the ecosystem from a lockfile's file name.
pub fn infer_ecosystem(path: &Path) -> Result<Ecosystem> {
    match lockfile_kind(path)? {
        LockKind::NpmPackageLock | LockKind::YarnLock | LockKind::PnpmLock => Ok(Ecosystem::Npm),
        LockKind::CargoLock => Ok(Ecosystem::Crates),
        LockKind::PoetryLock | LockKind::RequirementsTxt => Ok(Ecosystem::PyPI),
    }
}

fn file_name_lower(path: &Path) -> String {
    path.file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

// --- npm: package-lock.json --------------------------------------------------

/// Parse `package-lock.json` (lockfileVersion 2/3 `packages`, or v1
/// `dependencies`). Only registry-installed entries are kept: the root package
/// and workspace/link entries (which have no `resolved`) are skipped.
pub fn parse_package_lock(text: &str) -> Result<Vec<LockedEntry>> {
    use serde_json::Value;

    let root: Value =
        serde_json::from_str(text).context("parsing package-lock.json (is it valid JSON?)")?;
    let mut entries = Vec::new();

    // v2 / v3: the `packages` map, keyed by node_modules path.
    if let Some(packages) = root.get("packages").and_then(|p| p.as_object()) {
        for (key, node) in packages {
            // The root entry has an empty key; skip it (it is the project).
            if key.is_empty() {
                continue;
            }
            let name = node
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| name_from_node_modules_key(key));
            entries.push(LockedEntry {
                name,
                version: str_field(node, "version"),
                resolved: str_field(node, "resolved"),
                has_integrity: has_str(node, "integrity"),
            });
        }
        return Ok(entries);
    }

    // v1: the recursive `dependencies` map, keyed by package name.
    if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
        collect_v1_dependencies(deps, &mut entries);
    }
    Ok(entries)
}

fn collect_v1_dependencies(
    deps: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<LockedEntry>,
) {
    for (name, node) in deps {
        out.push(LockedEntry {
            name: name.clone(),
            version: str_field(node, "version"),
            resolved: str_field(node, "resolved"),
            has_integrity: has_str(node, "integrity"),
        });
        if let Some(nested) = node.get("dependencies").and_then(|d| d.as_object()) {
            collect_v1_dependencies(nested, out);
        }
    }
}

/// The package name from a `node_modules/...` key, honoring one level of
/// scope: `node_modules/@scope/name` -> `@scope/name`, and a nested
/// `node_modules/a/node_modules/b` -> `b`.
fn name_from_node_modules_key(key: &str) -> String {
    let tail = key.rsplit("node_modules/").next().unwrap_or(key);
    tail.to_string()
}

fn str_field(node: &serde_json::Value, field: &str) -> Option<String> {
    node.get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn has_str(node: &serde_json::Value, field: &str) -> bool {
    node.get(field).and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
}

// --- npm: yarn.lock (classic v1 text format) ---------------------------------

/// Parse a classic `yarn.lock`: blocks separated by blank lines, each a
/// `"name@range", ...:` header followed by indented `version`, `resolved`, and
/// `integrity` lines.
pub fn parse_yarn_lock(text: &str) -> Vec<LockedEntry> {
    let mut entries = Vec::new();
    let mut current: Option<LockedEntry> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let is_header = !line.starts_with(' ') && line.ends_with(':');
        if is_header {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            if let Some(name) = yarn_header_name(line) {
                current = Some(LockedEntry {
                    name,
                    version: None,
                    resolved: None,
                    has_integrity: false,
                });
            }
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(v) = yarn_value(trimmed, "version") {
            entry.version = Some(v);
        } else if let Some(v) = yarn_value(trimmed, "resolved") {
            entry.resolved = Some(v);
        } else if trimmed.starts_with("integrity ") || trimmed.starts_with("integrity\t") {
            entry.has_integrity = true;
        }
    }
    if let Some(entry) = current.take() {
        entries.push(entry);
    }
    entries
}

/// The package name from a yarn block header. The header is one or more
/// comma-separated `"name@range"` (or bare `name@range`) descriptors; the name
/// is the same across them, so read the first.
fn yarn_header_name(header: &str) -> Option<String> {
    let header = header.trim_end_matches(':').trim();
    let first = header.split(',').next()?.trim().trim_matches('"');
    at_version_name(first)
}

/// Split a `name@range` descriptor into just the name, honoring a leading
/// scope `@`. `@scope/name@^1.0` -> `@scope/name`; `left-pad@^1` -> `left-pad`.
fn at_version_name(descriptor: &str) -> Option<String> {
    let descriptor = descriptor.trim();
    if descriptor.is_empty() {
        return None;
    }
    let name = if let Some(rest) = descriptor.strip_prefix('@') {
        match rest.find('@') {
            Some(i) => format!("@{}", &rest[..i]),
            None => descriptor.to_string(),
        }
    } else {
        match descriptor.find('@') {
            Some(i) => descriptor[..i].to_string(),
            None => descriptor.to_string(),
        }
    };
    (!name.is_empty()).then_some(name)
}

/// Read a `key value` or `key "value"` line from a yarn block body.
fn yarn_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    if !rest.starts_with(' ') && !rest.starts_with('\t') {
        return None;
    }
    Some(rest.trim().trim_matches('"').to_string())
}

// --- npm: pnpm-lock.yaml -----------------------------------------------------

/// Parse a `pnpm-lock.yaml` `packages:` section without a YAML dependency.
/// pnpm keys each package as `  /name@version:` (or `  name@version:` in newer
/// formats) and records a nested `resolution: { integrity: ... , tarball: ... }`.
/// This is a line-oriented reader for exactly those fields.
pub fn parse_pnpm_lock(text: &str) -> Vec<LockedEntry> {
    let mut entries = Vec::new();
    let mut in_packages = false;
    let mut current: Option<LockedEntry> = None;

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // A top-level key ends the `packages:` section.
        if !line.starts_with(' ') {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            in_packages = line.trim_end_matches(':') == "packages";
            continue;
        }
        if !in_packages {
            continue;
        }
        // A package key is indented exactly two spaces and ends with ':'.
        let indent = line.len() - line.trim_start().len();
        let body = line.trim_start();
        if indent == 2 && body.ends_with(':') {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = pnpm_key_entry(body.trim_end_matches(':').trim());
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        // Inline form: `resolution: {integrity: sha512-..., tarball: https://...}`.
        if let Some(inner) = body.strip_prefix("resolution:") {
            let inner = inner.trim();
            if inner.starts_with('{') {
                apply_pnpm_resolution_inline(entry, inner);
                continue;
            }
        }
        // Multi-line form: `integrity:` / `tarball:` on their own lines.
        if let Some(tarball) = pnpm_inline_value(body, "tarball:") {
            entry.resolved = Some(tarball);
        } else if body.starts_with("integrity:") {
            let value = body.trim_start_matches("integrity:").trim();
            if !value.is_empty() {
                entry.has_integrity = true;
            }
        }
    }
    if let Some(entry) = current.take() {
        entries.push(entry);
    }
    entries
}

/// Build a locked entry from a pnpm package key like `/left-pad@1.3.0` or
/// `left-pad@1.3.0` or `/@scope/name@1.0.0(peer@1)` (peer suffix trimmed).
fn pnpm_key_entry(key: &str) -> Option<LockedEntry> {
    let key = key.trim().trim_start_matches('/').trim_matches('\'').trim_matches('"');
    // Drop a trailing peer-deps suffix in parentheses.
    let key = match key.find('(') {
        Some(i) => &key[..i],
        None => key,
    };
    let (name, version) = split_name_version(key);
    let name = name?;
    Some(LockedEntry {
        name,
        version,
        resolved: None,
        has_integrity: false,
    })
}

/// Split `name@version` (scope-aware) into `(name, Some(version))`, or
/// `(name, None)` when there is no version segment.
fn split_name_version(descriptor: &str) -> (Option<String>, Option<String>) {
    let descriptor = descriptor.trim();
    if descriptor.is_empty() {
        return (None, None);
    }
    let at = if let Some(rest) = descriptor.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        descriptor.find('@')
    };
    match at {
        Some(i) => {
            let name = &descriptor[..i];
            let version = &descriptor[i + 1..];
            (
                (!name.is_empty()).then(|| name.to_string()),
                (!version.is_empty()).then(|| version.to_string()),
            )
        }
        None => (Some(descriptor.to_string()), None),
    }
}

fn pnpm_inline_value(body: &str, key: &str) -> Option<String> {
    let rest = body.strip_prefix(key)?;
    let value = rest.trim().trim_matches('\'').trim_matches('"');
    (!value.is_empty()).then(|| value.to_string())
}

/// Read `integrity` and `tarball` from an inline pnpm `{integrity: ..., tarball:
/// ...}` resolution object (a comma-separated `key: value` list inside braces).
fn apply_pnpm_resolution_inline(entry: &mut LockedEntry, inline: &str) {
    let inner = inline.trim().trim_start_matches('{').trim_end_matches('}');
    for pair in inner.split(',') {
        let Some((key, value)) = pair.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('\'').trim_matches('"');
        if value.is_empty() {
            continue;
        }
        if key == "integrity" {
            entry.has_integrity = true;
        } else if key == "tarball" {
            entry.resolved = Some(value.to_string());
        }
    }
}

// --- crates.io: Cargo.lock ---------------------------------------------------

/// Parse `Cargo.lock`: an array of `[[package]]` tables, each with `name`,
/// `version`, and (for registry crates) `source` and `checksum`. Crates with no
/// `source` are local path deps; those are skipped, like the manifest parser.
pub fn parse_cargo_lock(text: &str) -> Result<Vec<LockedEntry>> {
    #[derive(serde::Deserialize)]
    struct CargoLock {
        #[serde(default)]
        package: Vec<CargoPackage>,
    }
    #[derive(serde::Deserialize)]
    struct CargoPackage {
        name: String,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        checksum: Option<String>,
    }

    let lock: CargoLock = toml::from_str(text).context("parsing Cargo.lock")?;
    let mut entries = Vec::new();
    for pkg in lock.package {
        // No `source` means a local path dependency (the workspace crate
        // itself), not a crates.io package. Skip it.
        let Some(source) = pkg.source else {
            continue;
        };
        entries.push(LockedEntry {
            name: pkg.name,
            version: pkg.version,
            // Cargo.lock records the registry as a `source` URL, not a
            // per-artifact tarball URL, so it doubles as the resolved host.
            resolved: Some(source),
            has_integrity: pkg.checksum.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
        });
    }
    Ok(entries)
}

// --- PyPI: poetry.lock and a hashed requirements.txt -------------------------

/// Parse `poetry.lock`: `[[package]]` tables with `name` and `version`, plus a
/// `[metadata.files]` map of per-package file hashes. A package with a files
/// entry has integrity; one without does not.
pub fn parse_poetry_lock(text: &str) -> Result<Vec<LockedEntry>> {
    let value: toml::Value = toml::from_str(text).context("parsing poetry.lock")?;

    // metadata.files maps package name -> array of { file, hash }.
    let files = value
        .get("metadata")
        .and_then(|m| m.get("files"))
        .and_then(|f| f.as_table());

    let mut entries = Vec::new();
    if let Some(packages) = value.get("package").and_then(|p| p.as_array()) {
        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let version = pkg
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            // A path / url / git source is not a PyPI package; skip it.
            if let Some(source) = pkg.get("source").and_then(|s| s.as_table()) {
                let kind = source.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if matches!(kind, "directory" | "file" | "git" | "url") {
                    continue;
                }
            }
            let has_integrity = files
                .and_then(|f| f.get(name))
                .and_then(|arr| arr.as_array())
                .map(|arr| !arr.is_empty())
                .unwrap_or(false);
            entries.push(LockedEntry {
                name: name.to_string(),
                version,
                resolved: None,
                has_integrity,
            });
        }
    }
    Ok(entries)
}

/// Parse a pip-compiled / hashed `requirements.txt`: `name==version` lines,
/// each optionally followed (same or continued lines) by one or more
/// `--hash=algo:digest`. A pinned line with at least one hash has integrity.
pub fn parse_hashed_requirements(text: &str) -> Vec<LockedEntry> {
    // Join backslash-continued lines so `pkg==1.0 \\\n  --hash=...` is one unit.
    let joined = text.replace("\\\n", " ");
    let mut by_name: BTreeMap<String, LockedEntry> = BTreeMap::new();

    for raw in joined.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() || line.starts_with('-') || line.contains("://") {
            continue;
        }
        // Only exact-pinned (`==`) lines are lockfile entries; a range is not.
        let Some((name_part, rest)) = line.split_once("==") else {
            continue;
        };
        let name = pep508_name(name_part.trim());
        if name.is_empty() {
            continue;
        }
        // The version is the token after `==`, up to whitespace, a marker (`;`)
        // or the first `--hash`.
        let version = rest
            .split_whitespace()
            .next()
            .map(|v| v.trim_end_matches(';').to_string())
            .filter(|v| !v.is_empty());
        let has_integrity = line.contains("--hash=") || line.contains("--hash ");
        by_name
            .entry(name.clone())
            .and_modify(|e| {
                e.has_integrity = e.has_integrity || has_integrity;
                if e.version.is_none() {
                    e.version = version.clone();
                }
            })
            .or_insert(LockedEntry {
                name,
                version,
                resolved: None,
                has_integrity,
            });
    }
    by_name.into_values().collect()
}

fn strip_comment(line: &str) -> &str {
    if let Some(stripped) = line.strip_prefix('#') {
        let _ = stripped;
        return "";
    }
    match line.find(" #") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// The PEP 508 distribution name (up to the first non-name character).
fn pep508_name(spec: &str) -> String {
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(spec.len());
    spec[..end].to_string()
}

// --- integrity findings ------------------------------------------------------

/// The commodity `LOCKFILE-INTEGRITY` findings for one parsed lockfile: an
/// off-registry `resolved` host (HIGH) and a missing integrity hash where the
/// ecosystem normally records one (MEDIUM). Existence / malicious checks are
/// added by the caller (they re-run the `verify` engine per package).
pub fn integrity_findings(lockfile: &Lockfile) -> Vec<Finding> {
    let mut findings = Vec::new();
    let hosts = official_hosts(lockfile.ecosystem);
    let integrity_expected = integrity_expected(lockfile.ecosystem);

    for entry in &lockfile.entries {
        if let Some(resolved) = &entry.resolved {
            // The canonical crates.io index source is always official.
            let canonical_crates =
                lockfile.ecosystem == Ecosystem::Crates && resolved == CRATES_CANONICAL_SOURCE;
            if !canonical_crates {
                if let Some(host) = host_of(resolved) {
                    if !host_is_official(&host, hosts) {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: "off-registry-resolved",
                            tool: Some(entry.display_name()),
                            message: format!(
                                "resolves from '{host}', not the official registry ({}); \
                                 a repointed dependency source is a supply-chain risk",
                                hosts.join(", ")
                            ),
                            evidence: Some(truncate(resolved, 120)),
                        });
                    }
                }
            }
        }
        if integrity_expected && !entry.has_integrity && entry.resolved.is_some() {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "missing-integrity",
                tool: Some(entry.display_name()),
                message: "locked without an integrity hash; the fetched artifact \
                          cannot be checksum-verified"
                    .to_string(),
                evidence: None,
            });
        }
    }
    findings
}

/// Whether the ecosystem's lockfiles normally record an integrity hash. All
/// three do (npm `integrity`, Cargo `checksum`, poetry file hashes / pip
/// `--hash`), so a missing one is meaningful.
fn integrity_expected(_ecosystem: Ecosystem) -> bool {
    true
}

impl Lockfile {
    /// The distinct locked packages to re-verify, as `PackageRef`s pinned to
    /// their exact locked version, de-duplicated by name@version. A lockfile
    /// commonly repeats a name at several versions; each distinct pin is
    /// verified once.
    pub fn package_refs(&self) -> Vec<super::PackageRef> {
        let mut seen = std::collections::BTreeSet::new();
        let mut refs = Vec::new();
        for entry in &self.entries {
            let key = format!("{}@{}", entry.name, entry.version.as_deref().unwrap_or(""));
            if seen.insert(key) {
                refs.push(super::PackageRef {
                    ecosystem: self.ecosystem,
                    name: entry.name.clone(),
                    version: entry.version.clone(),
                });
            }
        }
        refs
    }
}

/// The full result of a `verify --lockfile` run: the parsed ecosystem, the
/// per-package verdicts, and the commodity integrity findings.
pub struct LockfileReport {
    pub ecosystem: Ecosystem,
    pub source: String,
    pub packages: Vec<super::report::PackageReport>,
    pub integrity: Vec<Finding>,
}

impl LockfileReport {
    /// Whether anything is flagged: any non-OK package or any actionable
    /// integrity finding (HIGH / MEDIUM).
    pub fn is_flagged(&self) -> bool {
        self.packages.iter().any(|p| p.verdict.is_flagged())
            || crate::warden::report::any_actionable(&self.integrity)
    }
}

/// Render a compact human report: the integrity findings first (the
/// lockfile-specific signal), then the per-package verdict table.
pub fn render_human(report: &LockfileReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} ({}): {} package(s) locked\n",
        report.source,
        report.ecosystem.label(),
        report.packages.len()
    ));
    if report.integrity.is_empty() {
        out.push_str("  integrity: no lockfile-integrity issues\n");
    } else {
        out.push_str(&format!(
            "  integrity: {} finding(s)\n",
            report.integrity.len()
        ));
        for f in &report.integrity {
            out.push_str(&format!(
                "    {:<6} {:<24} {}\n",
                f.severity.label(),
                f.tool.as_deref().unwrap_or(f.category),
                f.message,
            ));
        }
    }
    out.push('\n');
    out.push_str(&super::report::render_human(&report.packages));
    out
}

impl LockedEntry {
    /// The `name` or `name@version` label for display.
    pub fn display_name(&self) -> String {
        match &self.version {
            Some(v) => format!("{}@{}", self.name, v),
            None => self.name.clone(),
        }
    }
}

/// The host of a URL, or `None` for a non-URL string (e.g. a Cargo registry
/// source with a `registry+` prefix is unwrapped first).
fn host_of(url: &str) -> Option<String> {
    // Cargo sources look like `registry+https://github.com/rust-lang/crates.io-index`.
    let url = url
        .strip_prefix("registry+")
        .or_else(|| url.strip_prefix("sparse+"))
        .unwrap_or(url);
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let after_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let host = after_userinfo.split(':').next().unwrap_or(after_userinfo);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Whether a host equals or is a subdomain of any official host. A subdomain of
/// the registry (e.g. a CDN under the registry domain) is treated as official;
/// an unrelated host is not.
fn host_is_official(host: &str, official: &[&str]) -> bool {
    official.iter().any(|o| {
        let o = o.to_ascii_lowercase();
        host == o || host.ends_with(&format!(".{o}"))
    })
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn npm_lock(entries: Vec<LockedEntry>) -> Lockfile {
        Lockfile {
            ecosystem: Ecosystem::Npm,
            entries,
        }
    }

    #[test]
    fn infers_ecosystem_from_name() {
        assert_eq!(infer_ecosystem(Path::new("package-lock.json")).unwrap(), Ecosystem::Npm);
        assert_eq!(infer_ecosystem(Path::new("yarn.lock")).unwrap(), Ecosystem::Npm);
        assert_eq!(infer_ecosystem(Path::new("pnpm-lock.yaml")).unwrap(), Ecosystem::Npm);
        assert_eq!(infer_ecosystem(Path::new("Cargo.lock")).unwrap(), Ecosystem::Crates);
        assert_eq!(infer_ecosystem(Path::new("poetry.lock")).unwrap(), Ecosystem::PyPI);
        assert_eq!(
            infer_ecosystem(Path::new("requirements.txt")).unwrap(),
            Ecosystem::PyPI
        );
        assert!(infer_ecosystem(Path::new("mystery.lock")).is_err());
    }

    #[test]
    fn package_lock_v3_reads_resolved_and_integrity() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root"},
                "node_modules/express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-abc"
                },
                "node_modules/@scope/pkg": {
                    "version": "1.0.0",
                    "resolved": "https://npm.evil.example.com/@scope/pkg/-/pkg-1.0.0.tgz",
                    "integrity": "sha512-def"
                },
                "node_modules/no-hash": {
                    "version": "0.1.0",
                    "resolved": "https://registry.npmjs.org/no-hash/-/no-hash-0.1.0.tgz"
                }
            }
        }"#;
        let entries = parse_package_lock(text).unwrap();
        // The root ("") entry is skipped.
        assert_eq!(entries.len(), 3);
        let express = entries.iter().find(|e| e.name == "express").unwrap();
        assert_eq!(express.version.as_deref(), Some("4.18.2"));
        assert!(express.has_integrity);
        let scoped = entries.iter().find(|e| e.name == "@scope/pkg").unwrap();
        assert!(scoped.resolved.as_deref().unwrap().contains("npm.evil.example.com"));
    }

    #[test]
    fn off_registry_resolved_is_high() {
        let lock = npm_lock(vec![LockedEntry {
            name: "pkg".into(),
            version: Some("1.0.0".into()),
            resolved: Some("https://npm.evil.example.com/pkg/-/pkg-1.0.0.tgz".into()),
            has_integrity: true,
        }]);
        let findings = integrity_findings(&lock);
        assert!(findings
            .iter()
            .any(|f| f.category == "off-registry-resolved" && f.severity == Severity::High));
    }

    #[test]
    fn official_registry_resolved_is_clean() {
        let lock = npm_lock(vec![LockedEntry {
            name: "express".into(),
            version: Some("4.18.2".into()),
            resolved: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".into()),
            has_integrity: true,
        }]);
        assert!(integrity_findings(&lock).is_empty());
    }

    #[test]
    fn missing_integrity_is_medium() {
        let lock = npm_lock(vec![LockedEntry {
            name: "no-hash".into(),
            version: Some("0.1.0".into()),
            resolved: Some("https://registry.npmjs.org/no-hash/-/no-hash-0.1.0.tgz".into()),
            has_integrity: false,
        }]);
        let findings = integrity_findings(&lock);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "missing-integrity");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn subdomain_of_registry_is_official() {
        assert!(host_is_official("cdn.registry.npmjs.org", &["registry.npmjs.org"]));
        assert!(host_is_official("registry.npmjs.org", &["registry.npmjs.org"]));
        assert!(!host_is_official("evilregistry.npmjs.org.attacker.com", &["registry.npmjs.org"]));
        assert!(!host_is_official("registry.npmjs.org.evil.com", &["registry.npmjs.org"]));
    }

    #[test]
    fn yarn_lock_parses_blocks() {
        let text = "\
# yarn lockfile v1

\"@scope/pkg@^1.0.0\":
  version \"1.2.3\"
  resolved \"https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz#abc\"
  integrity sha512-deadbeef

left-pad@^1.3.0, left-pad@1.3.0:
  version \"1.3.0\"
  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\"
  integrity sha512-cafe
";
        let entries = parse_yarn_lock(text);
        assert_eq!(entries.len(), 2);
        let scoped = entries.iter().find(|e| e.name == "@scope/pkg").unwrap();
        assert_eq!(scoped.version.as_deref(), Some("1.2.3"));
        assert!(scoped.has_integrity);
        let lp = entries.iter().find(|e| e.name == "left-pad").unwrap();
        assert!(lp.resolved.as_deref().unwrap().contains("registry.yarnpkg.com"));
    }

    #[test]
    fn yarn_off_registry_flags() {
        // registry.yarnpkg.com is a CDN alias, NOT registry.npmjs.org, so with
        // the npm official host list it is flagged: the check is host-exact.
        let text = "\
evil@1.0.0:
  version \"1.0.0\"
  resolved \"https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz\"
  integrity sha1-x
";
        let entries = parse_yarn_lock(text);
        let lock = npm_lock(entries);
        assert!(lock
            .entries
            .iter()
            .any(|e| e.name == "evil"));
        assert!(integrity_findings(&lock)
            .iter()
            .any(|f| f.category == "off-registry-resolved"));
    }

    #[test]
    fn pnpm_lock_parses_packages() {
        let text = "\
lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-abc, tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz}
    dev: false

  /@scope/pkg@2.0.0:
    resolution: {integrity: sha512-def}
    dev: false
";
        let entries = parse_pnpm_lock(text);
        let lp = entries.iter().find(|e| e.name == "left-pad").unwrap();
        assert_eq!(lp.version.as_deref(), Some("1.3.0"));
        assert!(lp.has_integrity);
        assert!(lp.resolved.as_deref().unwrap().contains("registry.npmjs.org"));
        let scoped = entries.iter().find(|e| e.name == "@scope/pkg").unwrap();
        assert_eq!(scoped.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn pnpm_multiline_integrity_form() {
        // Newer pnpm splits resolution across lines.
        let text = "\
packages:

  /evil@1.0.0:
    resolution:
      integrity: sha512-xyz
      tarball: https://evil.example.com/evil-1.0.0.tgz
";
        let entries = parse_pnpm_lock(text);
        let evil = entries.iter().find(|e| e.name == "evil").unwrap();
        assert!(evil.has_integrity);
        assert!(evil.resolved.as_deref().unwrap().contains("evil.example.com"));
    }

    #[test]
    fn cargo_lock_reads_source_and_checksum() {
        let text = r#"
version = 3

[[package]]
name = "my-workspace-crate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "sneaky"
version = "0.1.0"
source = "registry+https://crates.evil.example.com/index"
checksum = "cafe"
"#;
        let entries = parse_cargo_lock(text).unwrap();
        // The path crate (no source) is skipped.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "serde"));
        let lock = Lockfile {
            ecosystem: Ecosystem::Crates,
            entries,
        };
        // The crates.io-index host is github.com, which is NOT static.crates.io
        // / crates.io, so a strict host check would flag serde. Cargo.lock's
        // `source` is the index host, not a per-artifact tarball, so we accept
        // the canonical crates.io-index host as official too.
        let findings = integrity_findings(&lock);
        assert!(findings
            .iter()
            .any(|f| f.tool.as_deref() == Some("sneaky@0.1.0")
                && f.category == "off-registry-resolved"));
    }

    #[test]
    fn poetry_lock_reads_files_for_integrity() {
        let text = r#"
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "local-thing"
version = "0.1.0"
[package.source]
type = "directory"
url = "../local-thing"

[metadata.files]
requests = [{file = "requests-2.31.0.tar.gz", hash = "sha256:abc"}]
"#;
        let entries = parse_poetry_lock(text).unwrap();
        // The directory-source package is skipped.
        assert_eq!(entries.len(), 1);
        let req = &entries[0];
        assert_eq!(req.name, "requests");
        assert!(req.has_integrity);
    }

    #[test]
    fn poetry_missing_files_is_missing_integrity() {
        let text = r#"
[[package]]
name = "no-hashes"
version = "1.0.0"

[metadata.files]
"#;
        let entries = parse_poetry_lock(text).unwrap();
        let lock = Lockfile {
            ecosystem: Ecosystem::PyPI,
            entries,
        };
        // poetry.lock records no per-artifact URL, so there is no resolved host
        // and thus no missing-integrity finding (which requires a resolved URL).
        // The entry still parses with has_integrity == false.
        assert!(!lock.entries[0].has_integrity);
    }

    #[test]
    fn hashed_requirements_reads_pins_and_hashes() {
        let text = "\
# pip-compiled
requests==2.31.0 \\
    --hash=sha256:aaa \\
    --hash=sha256:bbb
flask==3.0.0
django>=4.0
-r other.txt
https://example.com/x.whl
";
        let entries = parse_hashed_requirements(text);
        let req = entries.iter().find(|e| e.name == "requests").unwrap();
        assert_eq!(req.version.as_deref(), Some("2.31.0"));
        assert!(req.has_integrity);
        let flask = entries.iter().find(|e| e.name == "flask").unwrap();
        assert!(!flask.has_integrity);
        // A range (`>=`) is not a lockfile pin and is skipped.
        assert!(!entries.iter().any(|e| e.name == "django"));
    }

    #[test]
    fn host_of_unwraps_cargo_and_sparse_sources() {
        assert_eq!(
            host_of("registry+https://github.com/rust-lang/crates.io-index").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            host_of("sparse+https://static.crates.io/").as_deref(),
            Some("static.crates.io")
        );
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn split_name_version_scope_aware() {
        assert_eq!(split_name_version("left-pad@1.3.0"), (Some("left-pad".into()), Some("1.3.0".into())));
        assert_eq!(
            split_name_version("@scope/name@2.0.0"),
            (Some("@scope/name".into()), Some("2.0.0".into()))
        );
        assert_eq!(split_name_version("bare"), (Some("bare".into()), None));
    }
}
