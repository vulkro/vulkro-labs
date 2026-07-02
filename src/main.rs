//! `vulkro-live`: Vulkro's free, keyless developer security tools.
//!
//! - `verify` - the AI package bouncer (npm, PyPI, crates.io).
//! - `warden` - the MCP / agent-tool bouncer.
//! - `mcp` - one MCP server exposing both tools to an AI agent.
//!
//! Everything runs on the user's own machine and sends only public metadata
//! (package names, versions, tool manifests), never source code.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use vulkro_feeds::{CachingHttpClient, Ecosystem, HttpClient, UreqClient};

mod mcp;
mod verify;
mod warden;

use verify::verdict::Thresholds;
use verify::{manifest, report, PackageRef, Verifier};

/// Exit code returned when one or more packages or tools are flagged.
const EXIT_FLAGGED: u8 = 1;
/// Exit code returned on an operational error.
const EXIT_ERROR: u8 = 2;
/// Default lifetime of an on-disk cached response.
const CACHE_TTL_SECS: u64 = 6 * 60 * 60;

const VERIFY_LONG_ABOUT: &str = "\
Verify that the packages an AI agent suggested are safe to install.

For each package (given as 'name', 'name@version', or read from a manifest
with --manifest) verify reports one verdict:

  MISSING     not in the registry (a likely AI hallucination or slopsquat)
  MALICIOUS   flagged by OSV (an OpenSSF malicious-packages record)
  SUSPICIOUS  exists, but very new or with very few downloads
  OK          otherwise

Ecosystems: npm (default), pypi, crates. Use --ecosystem for positional
packages; --manifest infers the ecosystem from the file name (package.json,
requirements.txt, pyproject.toml, Cargo.toml).

It is keyless and local: no account, no API key, no backend. Only package
names leave your machine; your source code never does.

Data sources: the public npm registry (registry.npmjs.org), npm download
counts (api.npmjs.org), the PyPI JSON API (pypi.org), the crates.io index and
API (crates.io), and OSV.dev (osv.dev) for malicious-package data, which
originates from the OpenSSF malicious-packages project (Apache-2.0). Nothing
is cached or redistributed centrally. See ATTRIBUTION.md.

Exit codes: 0 when every package is OK, 1 when one or more are flagged, 2 on
an error.";

const WARDEN_LONG_ABOUT: &str = "\
Scan an MCP server's tool manifest before an agent trusts its tools.

Given a JSON manifest (a tools/list result, a bare array of tools, or a
single tool object), warden runs static, commodity heuristics and reports
findings by severity:

  prompt-injection / tool-poisoning   instruction-injection or steering text
  hidden-unicode                      invisible characters hiding instructions
  tool-shadowing                      duplicate or builtin-colliding names
  sensitive-parameter                 asks the model to pass secrets
  capability / annotation             powerful or self-declared risky behavior

It reads only tool metadata; it never inspects or runs code. Exit codes: 0
when nothing actionable is found, 1 when a HIGH or MEDIUM finding is present,
2 on an error.";

#[derive(Parser)]
#[command(
    name = "vulkro-live",
    version,
    about = "Vulkro's free, keyless developer security tools.",
    long_about = "Vulkro's free, keyless developer security tools. All checks run on your \
own machine and send only public metadata (package names, versions, tool manifests), never \
your source code."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check that packages are real, not malicious, and not low-reputation.
    #[command(long_about = VERIFY_LONG_ABOUT)]
    Verify(VerifyArgs),

    /// Scan an MCP server's tool manifest for poisoning and risky tools.
    #[command(long_about = WARDEN_LONG_ABOUT)]
    Warden(WardenArgs),

    /// Run the MCP server exposing verify and warden over stdio.
    Mcp,
}

#[derive(Args)]
struct VerifyArgs {
    /// Packages to check, each as `name` or `name@version`.
    #[arg(value_name = "PACKAGE")]
    packages: Vec<String>,

    /// Ecosystem for the positional packages: npm (default), pypi, or crates.
    #[arg(long, value_name = "ECOSYSTEM")]
    ecosystem: Option<String>,

    /// Read package names from a manifest (package.json, requirements.txt,
    /// pyproject.toml, or Cargo.toml); the ecosystem is inferred from the name.
    #[arg(long, value_name = "FILE")]
    manifest: Option<PathBuf>,

    /// Flag packages created within this many days as SUSPICIOUS (default 30).
    #[arg(long, value_name = "DAYS")]
    min_age_days: Option<i64>,

    /// Flag packages with fewer than this many downloads as SUSPICIOUS
    /// (default 100).
    #[arg(long, value_name = "N")]
    min_downloads: Option<u64>,

    /// Bypass the local response cache and always query live.
    #[arg(long)]
    no_cache: bool,

    /// Emit machine-readable JSON instead of a text table.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct WardenArgs {
    /// JSON manifest files to scan (each a tools/list result, array, or tool).
    #[arg(value_name = "MANIFEST")]
    manifests: Vec<PathBuf>,

    /// Emit machine-readable JSON instead of a text table.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            // `{:#}` includes the full `.context(...)` chain.
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Verify(args) => run_verify(args),
        Command::Warden(args) => run_warden(args),
        Command::Mcp => {
            mcp::serve()?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_verify(args: VerifyArgs) -> Result<ExitCode> {
    let positional_eco = match &args.ecosystem {
        Some(raw) => Ecosystem::parse(raw)
            .with_context(|| format!("unknown ecosystem '{raw}' (use npm, pypi, or crates)"))?,
        None => Ecosystem::Npm,
    };

    let mut packages: Vec<PackageRef> = Vec::new();
    for input in &args.packages {
        packages.push(PackageRef::parse(input, positional_eco)?);
    }
    if let Some(path) = &args.manifest {
        let (eco, names) = manifest::read_manifest(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        packages.extend(names.into_iter().map(|name| PackageRef {
            ecosystem: eco,
            name,
            version: None,
        }));
    }
    if packages.is_empty() {
        anyhow::bail!("no packages to check: pass one or more package names, or --manifest <file>");
    }

    let mut thresholds = Thresholds::default();
    if let Some(days) = args.min_age_days {
        thresholds.min_age_days = days;
    }
    if let Some(downloads) = args.min_downloads {
        thresholds.min_downloads = downloads;
    }

    // Query live, caching responses locally unless --no-cache is set.
    let ureq = UreqClient::new();
    let reports = if args.no_cache {
        verify_all(&ureq, &packages, thresholds)?
    } else {
        let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
        verify_all(&cached, &packages, thresholds)?
    };

    if args.json {
        println!("{}", report::render_json(&reports)?);
    } else {
        print!("{}", report::render_human(&reports));
        println!("\n{}", report::summary_line(&reports));
        println!("\n{}", report::funnel_note());
    }

    let flagged = reports.iter().any(|r| r.verdict.is_flagged());
    Ok(exit_code(flagged))
}

fn verify_all(
    http: &dyn HttpClient,
    packages: &[PackageRef],
    thresholds: Thresholds,
) -> Result<Vec<report::PackageReport>> {
    let verifier = Verifier::new(http).with_thresholds(thresholds);
    let mut reports = Vec::with_capacity(packages.len());
    for package in packages {
        reports.push(verifier.verify(package)?);
    }
    Ok(reports)
}

fn run_warden(args: WardenArgs) -> Result<ExitCode> {
    if args.manifests.is_empty() {
        anyhow::bail!("no manifest to scan: pass one or more MCP tool manifest JSON files");
    }

    let mut findings = Vec::new();
    for path in &args.manifests {
        findings.extend(warden::scan_file(path)?);
    }

    if args.json {
        println!("{}", warden::report::render_json(&findings)?);
    } else {
        print!("{}", warden::report::render_human(&findings));
        println!("\n{}", warden::report::summary_line(&findings));
        println!("\n{}", warden::report::funnel_note());
    }

    let flagged = warden::report::any_actionable(&findings);
    Ok(exit_code(flagged))
}

fn exit_code(flagged: bool) -> ExitCode {
    if flagged {
        ExitCode::from(EXIT_FLAGGED)
    } else {
        ExitCode::SUCCESS
    }
}
