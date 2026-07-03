//! `inspect`: is this MCP server safe to add?
//!
//! Given an MCP server as a package name or an install command (`npx -y
//! @scope/pkg`, `uvx mcp-server-x`, `pipx run pkg`, `cargo install pkg`, ...),
//! inspect resolves the backing registry package, runs `verify` over it, and
//! (when a manifest is provided) runs `warden` over the advertised tools, then
//! collapses everything into a single GREEN / REVIEW / AVOID verdict.
//!
//! It is pure commodity composition of the shipped `verify` and `warden`
//! engines: no closed logic, no launching of the server, keyless.

use std::path::Path;

use anyhow::{Context, Result};

use vulkro_feeds::{Ecosystem, HttpClient};

use crate::trust::{fingerprint, FpKind, TrustStore};
use crate::verify::report::PackageReport;
use crate::verify::verdict::{Thresholds, Verdict};
use crate::verify::{PackageRef, Verifier};
use crate::warden::{self, report::Finding, report::Severity};

/// The three-state verdict inspect reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Real, established package and a clean manifest: safe to add.
    Green,
    /// Something to look at first (new/low-reputation package, medium finding,
    /// or a package that could not be resolved).
    Review,
    /// Do not add: missing/malicious package or a high-severity manifest finding.
    Avoid,
}

impl Trust {
    pub fn label(self) -> &'static str {
        match self {
            Trust::Green => "GREEN",
            Trust::Review => "REVIEW",
            Trust::Avoid => "AVOID",
        }
    }

    /// GREEN passes (exit 0); REVIEW and AVOID are flagged (exit 1).
    pub fn is_flagged(self) -> bool {
        !matches!(self, Trust::Green)
    }
}

/// The result of inspecting one MCP server.
pub struct InspectReport {
    pub spec: String,
    pub package: Option<PackageReport>,
    pub findings: Vec<Finding>,
    pub verdict: Trust,
    /// Set when the backing package could not be resolved from the spec.
    pub note: Option<String>,
}

/// Inspect an MCP server given by name or install command. `manifest`, if set,
/// is a JSON tool manifest scanned with `warden`.
pub fn inspect(
    http: &dyn HttpClient,
    spec: &str,
    manifest: Option<&Path>,
    thresholds: Thresholds,
    trust: Option<&TrustStore>,
) -> Result<InspectReport> {
    // A malformed spec (empty, or a runner with no package) is a usage error
    // and propagates (exit 2). A local script or VCS/URL install is a real but
    // unverifiable server: note it and REVIEW rather than erroring.
    let (package, note) = match resolve_spec(spec)? {
        Resolution::Package(pref) => {
            let mut report = Verifier::new(http)
                .with_thresholds(thresholds)
                .verify(&pref)?;
            if let Some(store) = trust {
                crate::verify::apply_package_trust(&mut report, store);
            }
            (Some(report), None)
        }
        Resolution::Unverifiable(reason) => (None, Some(reason)),
    };

    let findings = match manifest {
        Some(path) => scan_manifest_trusted(path, trust)?,
        None => Vec::new(),
    };

    let verdict = decide(package.as_ref().map(|p| p.verdict), &findings);
    Ok(InspectReport {
        spec: spec.to_string(),
        package,
        findings,
        verdict,
        note,
    })
}

/// Scan a tool manifest, short-circuiting to a trusted marker when the manifest
/// fingerprint has been cleared in the trust store.
fn scan_manifest_trusted(path: &Path, trust: Option<&TrustStore>) -> Result<Vec<Finding>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading manifest {}", path.display()))?;
    if let Some(store) = trust {
        if let Ok(fp) = fingerprint::manifest_fingerprint(&text) {
            if store.allows_fingerprint(FpKind::Manifest, &fp) {
                return Ok(vec![warden::report::trusted_finding()]);
            }
        }
    }
    warden::scan_manifest_text(&text)
}

/// Collapse the package verdict and the manifest findings into one trust level.
fn decide(package: Option<Verdict>, findings: &[Finding]) -> Trust {
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = findings.iter().any(|f| f.severity == Severity::Medium);

    if matches!(
        package,
        Some(Verdict::Malicious) | Some(Verdict::Missing) | Some(Verdict::Lookalike)
    ) || has_high
    {
        return Trust::Avoid;
    }
    // Suspicious, a known CVE (VULNERABLE), a MEDIUM finding, or a package we
    // could not resolve (None) are all "look before you trust it".
    if matches!(
        package,
        Some(Verdict::Suspicious) | Some(Verdict::Vulnerable) | None
    ) || has_medium
    {
        return Trust::Review;
    }
    Trust::Green
}

/// Render a compact human report: a verdict headline, the package line, and any
/// manifest findings.
pub fn render_human(report: &InspectReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}  {}\n", report.verdict.label(), report.spec));

    if let Some(pkg) = &report.package {
        out.push_str(&format!(
            "  package  {} ({})  {}  {}\n",
            pkg.name,
            pkg.ecosystem.label(),
            pkg.verdict.label(),
            pkg.reason,
        ));
    } else if let Some(note) = &report.note {
        out.push_str(&format!("  package  could not resolve: {note}\n"));
    }

    if !report.findings.is_empty() {
        out.push_str(&format!(
            "  manifest {} finding(s):\n",
            report.findings.len()
        ));
        for f in &report.findings {
            out.push_str(&format!(
                "    {:<6} {:<16} {}\n",
                f.severity.label(),
                f.category,
                f.message
            ));
        }
    }
    out
}

// --- spec resolution ---------------------------------------------------------

/// The outcome of resolving a server spec.
enum Resolution {
    /// A published package to verify.
    Package(PackageRef),
    /// A real server with no published package (a local script, or a VCS/URL
    /// install). The string explains why it cannot be auto-verified.
    Unverifiable(String),
}

/// A REVIEW report for a server whose backing package could not be resolved.
/// Used by `audit`, which must not abort on one odd server config.
pub fn unresolved_report(spec: &str, reason: String) -> InspectReport {
    InspectReport {
        spec: spec.to_string(),
        package: None,
        findings: Vec::new(),
        verdict: Trust::Review,
        note: Some(reason),
    }
}

/// Resolve an MCP server spec to its backing registry package, or an
/// `Unverifiable` outcome (a local script or a VCS/URL install). Returns an
/// error only for genuinely malformed input: an empty spec, or a runner with no
/// package token.
fn resolve_spec(spec: &str) -> Result<Resolution> {
    let spec = spec.trim();
    if spec.is_empty() {
        anyhow::bail!("empty server spec");
    }
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let first = tokens[0];

    // File runners execute a local script, not a published package: `node
    // build/index.js`, `python server.py`. The exception is `python -m
    // <module>`, which names an importable (usually published) module.
    if matches!(first, "node" | "deno") {
        return Ok(Resolution::Unverifiable(format!(
            "runs a local script with {first}; there is no published package to check, review it by hand"
        )));
    }
    if matches!(first, "python" | "python3") {
        return match module_after_dash_m(&tokens) {
            Some(module) => Ok(Resolution::Package(PackageRef::parse(module, Ecosystem::PyPI)?)),
            None => Ok(Resolution::Unverifiable(
                "runs a local Python script; there is no published package to check, review it by hand"
                    .to_string(),
            )),
        };
    }

    let Some(ecosystem) = runner_ecosystem(first) else {
        // No known runner: treat the first token as a bare package name.
        return classify_name(first, Ecosystem::Npm);
    };

    let name = pick_package(&tokens[1..])
        .with_context(|| format!("could not find a package name in '{spec}'"))?;
    classify_name(name, ecosystem)
}

/// Classify a resolved name: a registry package, or an unverifiable local /
/// VCS / URL install.
fn classify_name(name: &str, ecosystem: Ecosystem) -> Result<Resolution> {
    if is_non_registry(name) {
        return Ok(Resolution::Unverifiable(format!(
            "'{name}' is a local path or a VCS/URL install, not a published package, review it by hand"
        )));
    }
    Ok(Resolution::Package(PackageRef::parse(name, ecosystem)?))
}

/// Map a package runner to the ecosystem it installs from. (File runners like
/// `node`/`python` are handled separately, before this is called.)
fn runner_ecosystem(cmd: &str) -> Option<Ecosystem> {
    match cmd {
        "npx" | "bunx" | "pnpx" | "npm" | "pnpm" | "yarn" | "bun" => Some(Ecosystem::Npm),
        "uvx" | "uv" | "pipx" | "pip" | "pip3" | "pipenv" => Some(Ecosystem::PyPI),
        "cargo" => Some(Ecosystem::Crates),
        _ => None,
    }
}

/// The module named by `-m <module>`, if present.
fn module_after_dash_m<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    tokens
        .iter()
        .position(|&t| t == "-m")
        .and_then(|i| tokens.get(i + 1).copied())
}

/// Subcommand keywords that sit between a runner and the package
/// (`pnpm dlx pkg`, `pipx run pkg`, `pip install pkg`, `cargo install pkg`).
fn is_subcommand(token: &str) -> bool {
    matches!(
        token,
        "dlx" | "run" | "install" | "exec" | "tool" | "add" | "x"
    )
}

/// Find the package token after a runner, honoring explicit package flags
/// (`--from`, `--package`, `-p`, `--spec`, python `-m`) and skipping other
/// flags and subcommand keywords.
fn pick_package<'a>(tokens: &[&'a str]) -> Option<&'a str> {
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if matches!(token, "--from" | "--package" | "-p" | "--spec") {
            return tokens.get(i + 1).copied();
        }
        if token.starts_with('-') || is_subcommand(token) {
            i += 1;
            continue;
        }
        return Some(token);
    }
    None
}

/// Whether a name points at a local path or a VCS/URL install rather than a
/// published registry package. A bare name that ends in `.js` (like
/// `discordi.js`) is a valid package; only a path separator, a `./`/`/` prefix,
/// or a URL/git scheme marks it as non-registry. Scoped npm names
/// (`@scope/name`) legitimately contain one slash and are allowed.
fn is_non_registry(name: &str) -> bool {
    let is_scoped = name.starts_with('@');
    let looks_local =
        name.starts_with("./") || name.starts_with("../") || name.starts_with('/');
    let looks_remote = name.contains("://") || name.starts_with("git+");
    let is_path = name.contains('/') && !is_scoped;
    looks_remote || looks_local || is_path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(spec: &str) -> (Ecosystem, String) {
        match resolve_spec(spec).unwrap() {
            Resolution::Package(p) => (p.ecosystem, p.name),
            Resolution::Unverifiable(r) => panic!("expected a package, got unverifiable: {r}"),
        }
    }

    fn is_unverifiable(spec: &str) -> bool {
        matches!(resolve_spec(spec), Ok(Resolution::Unverifiable(_)))
    }

    #[test]
    fn bare_scoped_npm_name() {
        assert_eq!(
            resolved("@modelcontextprotocol/server-filesystem"),
            (Ecosystem::Npm, "@modelcontextprotocol/server-filesystem".into())
        );
    }

    #[test]
    fn npx_with_flag_and_args() {
        assert_eq!(
            resolved("npx -y @scope/server-x /some/path"),
            (Ecosystem::Npm, "@scope/server-x".into())
        );
    }

    #[test]
    fn uvx_python_package() {
        assert_eq!(resolved("uvx mcp-server-git"), (Ecosystem::PyPI, "mcp-server-git".into()));
    }

    #[test]
    fn uvx_from_flag_names_the_package() {
        assert_eq!(
            resolved("uvx --from some-tool run-server"),
            (Ecosystem::PyPI, "some-tool".into())
        );
    }

    #[test]
    fn pip_install_and_cargo_install() {
        assert_eq!(resolved("pip install flask-mcp"), (Ecosystem::PyPI, "flask-mcp".into()));
        assert_eq!(resolved("cargo install some-mcp"), (Ecosystem::Crates, "some-mcp".into()));
    }

    #[test]
    fn python_dash_m_module() {
        assert_eq!(resolved("python -m mcp_server_time"), (Ecosystem::PyPI, "mcp_server_time".into()));
    }

    #[test]
    fn local_and_vcs_specs_are_unverifiable_not_errors() {
        // A real but unverifiable server (local script, git install) is a
        // REVIEW, not a hard error, so `audit` can report it and move on.
        assert!(is_unverifiable("node /path/to/build/index.js"));
        assert!(is_unverifiable("./server.py"));
        assert!(is_unverifiable("python app.py"));
    }

    #[test]
    fn malformed_input_is_a_usage_error() {
        // These must exit 2 (error), not be reported as a soft REVIEW.
        assert!(resolve_spec("").is_err());
        assert!(resolve_spec("   ").is_err());
        assert!(resolve_spec("npx -y").is_err());
    }

    #[test]
    fn bare_dot_js_name_is_a_package_not_a_script() {
        // Regression: `discordi.js` ends in `.js` but is a real npm package
        // name (a typosquat), not a local file. It must resolve, not error.
        assert_eq!(resolved("npx discordi.js"), (Ecosystem::Npm, "discordi.js".into()));
        assert_eq!(resolved("discordi.js"), (Ecosystem::Npm, "discordi.js".into()));
    }

    #[test]
    fn git_install_is_unverifiable() {
        assert!(is_unverifiable("uvx --from git+https://example.com/x run"));
    }

    #[test]
    fn decide_avoids_on_missing_or_high() {
        assert_eq!(decide(Some(Verdict::Missing), &[]), Trust::Avoid);
        assert_eq!(decide(Some(Verdict::Malicious), &[]), Trust::Avoid);
        let high = vec![Finding {
            severity: Severity::High,
            category: "prompt-injection",
            tool: None,
            message: "x".into(),
            evidence: None,
        }];
        assert_eq!(decide(Some(Verdict::Ok), &high), Trust::Avoid);
    }

    #[test]
    fn decide_reviews_on_suspicious_or_unresolved() {
        assert_eq!(decide(Some(Verdict::Suspicious), &[]), Trust::Review);
        assert_eq!(decide(None, &[]), Trust::Review);
    }

    #[test]
    fn decide_green_when_clean() {
        assert_eq!(decide(Some(Verdict::Ok), &[]), Trust::Green);
    }
}
