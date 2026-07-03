//! `vulkro-live`: Vulkro's free, keyless developer security tools.
//!
//! - `verify` - the AI package bouncer (npm, PyPI, crates.io).
//! - `warden` - the MCP / agent-tool bouncer.
//! - `mcp` - one MCP server exposing both tools to an AI agent.
//!
//! Everything runs on the user's own machine and sends only public metadata
//! (package names, versions, tool manifests), never source code.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use vulkro_feeds::{CachingHttpClient, Ecosystem, HttpClient, UreqClient};

mod audit;
mod cardcheck;
mod foresee;
mod inspect;
mod lock;
mod mcp;
mod memcheck;
mod sarif;
mod skillscan;
mod trust;
mod upsell;
mod verify;
mod warden;

use sarif::OutputFormat;
use trust::TrustStore;
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
  LOOKALIKE   a homoglyph or one-edit typo of a very popular package
  VULNERABLE  the installed version has a known CVE / advisory (from OSV)
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

const INSPECT_LONG_ABOUT: &str = "\
Is this MCP server safe to add? Give inspect the server as a package name or
its install command:

  vulkro-live inspect @scope/server-x
  vulkro-live inspect 'npx -y @scope/server-x'
  vulkro-live inspect 'uvx mcp-server-git'

inspect resolves the backing registry package (npm / PyPI / crates), runs
verify over it (is it real, not malicious, not suspiciously new), and, when a
tool manifest is provided with --manifest, runs warden over the advertised
tools. It reports one verdict:

  GREEN   real, established package and a clean manifest
  REVIEW  new / low-reputation package, a medium finding, or unresolved
  AVOID   missing or malicious package, or a high-severity manifest finding

v1 does not launch the server: it will not run untrusted code. It is keyless
and local. Exit codes: 0 for GREEN, 1 for REVIEW or AVOID, 2 on an error.";

const AUDIT_LONG_ABOUT: &str = "\
Audit your whole agent surface in one command. audit walks the well-known
config locations for Claude Code, Claude Desktop, Cursor, Windsurf, and Cline
(project and home), and:

  - inventories every MCP server and verifies its backing package (like inspect)
  - scans every rules / skill / instructions file for prompt-injection and
    hidden unicode (like warden)
  - flags hooks whose command shells out to the network
  - flags config values (server env / headers / args) that look like a plaintext
    secret, and dangerous settings (auto-approve, permission bypass, a hook that
    fetches and executes remote code)

It reads only local config and public package metadata (never your source code).
It never launches a server and never runs a hook. Keyless and local.

Machine output: --format json or --format sarif (for CI code-scanning).
Baselines: --write-baseline <file> records a committable snapshot of the surface;
--diff <file> reports only what changed since that baseline (a new server, a
setting flipped to auto-approve, a new network hook, a new secret).

Exit codes: 0 when nothing is flagged, 1 when a server is REVIEW/AVOID, an
instruction file has an actionable finding, a hook reaches the network, a config
secret is found, or a dangerous setting is set, 2 on an error.";

const FORESEE_LONG_ABOUT: &str = "\
Predict the slopsquat traps planted for this project, before your AI ever names
one.

Every other supply-chain check is reactive: a name appears, then it is checked.
foresee is predictive. It reads your project's real dependency stack and
deterministically enumerates the plausible-but-absent package names an LLM is
likely to invent for a project like this, then checks each against the registry
(reusing verify). A predicted name that is already registered, recently and with
near-zero reputation, is a trap lying in wait for your agent. Names that do not
exist yet are written to a committable guardrail file (.vulkro-foresee.json)
that you can point your agent at: 'never install any of these'.

It is keyless and local: deterministic string combinatorics plus the same public
registry checks verify already makes. No model, no backend. It queries the
registry once per predicted name, so a run takes a little time.

Exit codes: 0 when no planted trap is found, 1 when one or more predicted names
are already registered as a trap, 2 on an error.";

const SKILLSCAN_LONG_ABOUT: &str = "\
Scan the executable BODY of your agent's skills, not just their prose.

audit reads a skill's SKILL.md text but never opens the scripts it will actually
run, which is exactly where a stealer hides while the description looks clean.
skillscan walks every Claude Code skill (.claude/skills/*), slash command
(.claude/commands/*.md), and subagent (.claude/agents/*.md), project and home,
and for each:

  - parses the frontmatter for dangerous declared powers (broad tool access, a
    permission bypass / auto-approve)
  - static-scans every bundled script for stealer tells: download-pipe-to-shell
    (curl|sh), base64-decode-and-execute, reads of ~/.ssh / ~/.aws /
    ~/.claude.json / .env, environment dumps, and outbound network egress
  - runs warden's text engine over the prose

It reports GREEN / REVIEW / AVOID per skill and NEVER executes anything. Keyless
and local.

Exit codes: 0 when nothing is flagged, 1 when a skill is REVIEW/AVOID, 2 on an
error.";

const MEMCHECK_LONG_ABOUT: &str = "\
Scan an AI agent's stored long-term memory for poisoning.

An agent treats its saved memory as trusted long-term context, so a single
injected 'fact' can steer every future session (OWASP Agentic Top 10 2026,
ASI06 Memory / Context Poisoning). memcheck auto-discovers the common text
memory stores (MEMORY.md, memory/*.md, *.jsonl memory logs), runs warden's
hardened text engine over each stored record (prompt injection, hidden unicode,
ANSI-escape tricks, exfil sinks), and adds a memory-specific check: a memory is
supposed to be a passive fact, so one that carries a runnable command or steers
the agent to act is flagged as poisoned.

Purely offline and keyless: it reads local files and sends nothing.

Exit codes: 0 when nothing is flagged, 1 when a poisoned memory is found, 2 on
an error.";

const TRUSTDB_LONG_ABOUT: &str = "\
Clear an artifact once, and every free tool trusts that EXACT version or content.

The trust store is a committed, diff-friendly file at .vulkro/trust.toml: the
repo is the backend and PR review is the approval. When you clear an artifact,
verify / inspect / audit / warden / skillscan / memcheck stop flagging that exact
artifact, and go loud again the moment it mutates (a different version, one
changed manifest or file byte).

  trustdb add express@4.18.2                clear a package (a version is required)
  trustdb add --ecosystem pypi flask@3.0.0  clear a PyPI package
  trustdb add --manifest ./tools.json       clear an MCP tool manifest by content
  trustdb add --skill ./.claude/skills/x    clear a skill (SKILL.md and scripts)
  trustdb add --memory ./MEMORY.md          clear a memory file by content
  trustdb list                              show every cleared artifact
  trustdb remove <key>                      remove one entry (keys from list)
  trustdb clear                             remove every entry

Trust is ALWAYS version-pinned or fingerprint-pinned, never name-only, so a new
(possibly malicious) version is never auto-trusted. A cleared artifact is shown
with a visible 'trusted (cleared in .vulkro/trust.toml)' marker, not a silent
pass, so it is always auditable in the diff. Keyless and offline.

Exit codes: 0 on success, 2 on a bad argument or IO error.";

const LOCK_LONG_ABOUT: &str = "\
Fingerprint the current MCP tool manifest(s) into a committable lock file.

lock parses each manifest (the same tools/list shapes warden and inspect take),
canonicalizes every tool, and writes them to a deterministic .vulkro/mcp.lock
(override with --lock). Commit the lock. Later, `drift` compares the current
manifest against it to catch a tool that was silently swapped after you approved
it (a rug pull).

It is keyless and fully offline: it only reads the manifest files you name and
writes the lock. Exit codes: 0 on success, 2 on a bad argument or IO error.";

const DRIFT_LONG_ABOUT: &str = "\
Detect an MCP rug pull: diff the current manifest(s) against the lock.

drift re-reads the manifest(s) and reports a field-level diff against
.vulkro/mcp.lock (override with --lock), classifying each change by what it
introduces: a tool dropping readOnlyHint or gaining destructiveHint, or a
description that now contains an injection / hidden-text / exfil signal, is HIGH;
an added or removed tool, or a changed input schema, is MEDIUM; a benign reword
is LOW (shown for review, never over-claimed as malice).

drift diffs a manifest already on disk. It does NOT launch the server to poll
tools/list (that would run untrusted code), so re-capture the current manifest
before running drift. Pass the same paths you passed to lock. Keyless and
offline.

Exit codes: 0 when nothing changed, 1 when drift is found, 2 on an error (including
no lock file yet: run `vulkro-live lock` first).";

const CARDCHECK_LONG_ABOUT: &str = "\
Vet an A2A (Agent2Agent) agent card before your agent trusts a peer.

Give cardcheck a host, an https URL, or a full well-known card URL (or a local
card with --file / stdin). It fetches the public /.well-known/agent-card.json
(with an agent.json fallback) and runs five keyless, commodity checks:

  - identity: does the host it was served from match the origin the card claims
    to speak for? A different registrable domain is a HIGH impersonation signal.
  - injection: warden's engine over every text field (name, description, skills)
  - confusables: a homoglyph / mixed-script check on the agent and provider name
  - capability over-reach and provider trust (informational)

On signatures cardcheck is HONEST: this version reports whether a JWS signature
is PRESENT and well-formed, and does NOT cryptographically verify it. It never
claims a signature is valid or verified. Full JWS verification is a tracked
future addition.

Only public metadata leaves your machine (the card fetch); with --file / stdin
nothing leaves at all. Keyless. Exit codes: 0 GREEN, 1 REVIEW/AVOID, 2 error.";

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

    /// Is this MCP server safe to add? One GREEN / REVIEW / AVOID verdict.
    #[command(long_about = INSPECT_LONG_ABOUT)]
    Inspect(InspectArgs),

    /// Audit your whole agent surface: every MCP server, rule, skill, and hook.
    #[command(long_about = AUDIT_LONG_ABOUT)]
    Audit(AuditArgs),

    /// Predict the slopsquat traps planted for this project before your AI names one.
    #[command(long_about = FORESEE_LONG_ABOUT)]
    Foresee(ForeseeArgs),

    /// Scan the executable body of skills, slash commands, and subagents.
    #[command(long_about = SKILLSCAN_LONG_ABOUT)]
    Skillscan(SkillscanArgs),

    /// Scan an AI agent's stored long-term memory for poisoning.
    #[command(long_about = MEMCHECK_LONG_ABOUT)]
    Memcheck(MemcheckArgs),

    /// Clear an artifact once (.vulkro/trust.toml); tools trust that exact version.
    #[command(long_about = TRUSTDB_LONG_ABOUT)]
    Trustdb(trust::command::TrustdbArgs),

    /// Fingerprint the current MCP tool manifest(s) into a committable lock.
    #[command(long_about = LOCK_LONG_ABOUT)]
    Lock(LockArgs),

    /// Detect an MCP rug pull: diff the current manifest(s) against the lock.
    #[command(long_about = DRIFT_LONG_ABOUT)]
    Drift(DriftArgs),

    /// Vet an A2A agent card before your agent trusts it: identity, injection, confusables.
    #[command(long_about = CARDCHECK_LONG_ABOUT)]
    Cardcheck(CardcheckArgs),

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

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Deprecated: use --format json. Kept for one release.
    #[arg(long, hide = true)]
    json: bool,
}

#[derive(Args)]
struct WardenArgs {
    /// JSON manifest files to scan (each a tools/list result, array, or tool).
    /// With --result, these are instead plain files of untrusted content; pass
    /// no files (or `-`) to read that content from stdin.
    #[arg(value_name = "MANIFEST")]
    manifests: Vec<PathBuf>,

    /// Scan untrusted TEXT (a tool result, a fetched page, a file the agent
    /// read) for injection and hidden-unicode, instead of parsing it as a JSON
    /// tool manifest. Reads from stdin when no file is given.
    #[arg(long)]
    result: bool,

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Deprecated: use --format json. Kept for one release.
    #[arg(long, hide = true)]
    json: bool,
}

#[derive(Args)]
struct InspectArgs {
    /// The MCP server: a package name (`@scope/server`) or an install command
    /// (`npx -y @scope/server`, `uvx mcp-server-x`, `pip install x`, ...).
    #[arg(value_name = "SERVER")]
    server: String,

    /// A JSON tool manifest for the server (a tools/list result, array, or tool)
    /// to scan with warden as part of the verdict.
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

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Args)]
struct AuditArgs {
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

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Write a committable baseline snapshot of the agent surface to this file.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// Report only what changed since this baseline (from --write-baseline).
    #[arg(long, value_name = "FILE")]
    diff: Option<PathBuf>,
}

#[derive(Args)]
struct ForeseeArgs {
    /// Project directory to read the dependency manifest from (default: current).
    #[arg(value_name = "DIR", default_value = ".")]
    dir: PathBuf,

    /// How many predicted names to check against the registry.
    #[arg(long, value_name = "N", default_value_t = foresee::DEFAULT_LIMIT)]
    limit: usize,

    /// Do not write the .vulkro-foresee.json guardrail file.
    #[arg(long)]
    no_write: bool,

    /// Bypass the local response cache and always query live.
    #[arg(long)]
    no_cache: bool,

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Args)]
struct SkillscanArgs {
    /// Project directory to scan (default: current). The home directory's
    /// skills / commands / agents are also scanned.
    #[arg(value_name = "DIR", default_value = ".")]
    dir: PathBuf,

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Args)]
struct MemcheckArgs {
    /// Project directory whose memory stores to scan (default: current).
    #[arg(value_name = "DIR", default_value = ".")]
    dir: PathBuf,

    /// Additional memory files to scan explicitly (any text or JSONL file).
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Args)]
struct CardcheckArgs {
    /// The agent to fetch: a host (example.com), an https URL, or a full
    /// .well-known card URL. Omit when reading a local card with --file / stdin.
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Read the card from a local JSON file instead of fetching (nothing leaves
    /// the machine). Use `-` for stdin.
    #[arg(long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Bypass the local response cache and always fetch live.
    #[arg(long)]
    no_cache: bool,
}

#[derive(Args)]
struct LockArgs {
    /// MCP tool manifest JSON file(s) to fingerprint (a tools/list result,
    /// array, or single tool).
    #[arg(value_name = "MANIFEST")]
    manifests: Vec<PathBuf>,

    /// Where to write the lock (default: .vulkro/mcp.lock).
    #[arg(long, value_name = "FILE")]
    lock: Option<PathBuf>,
}

#[derive(Args)]
struct DriftArgs {
    /// The current MCP tool manifest JSON file(s) to compare against the lock.
    #[arg(value_name = "MANIFEST")]
    manifests: Vec<PathBuf>,

    /// The lock to compare against (default: .vulkro/mcp.lock).
    #[arg(long, value_name = "FILE")]
    lock: Option<PathBuf>,

    /// Output format: text (default), json, or sarif (for CI code-scanning).
    #[arg(long, value_enum, value_name = "FORMAT", default_value_t = OutputFormat::Text)]
    format: OutputFormat,
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
        Command::Inspect(args) => run_inspect(args),
        Command::Audit(args) => run_audit(args),
        Command::Foresee(args) => run_foresee(args),
        Command::Skillscan(args) => run_skillscan(args),
        Command::Memcheck(args) => run_memcheck(args),
        Command::Trustdb(args) => trust::command::run(args),
        Command::Lock(args) => run_lock(args),
        Command::Drift(args) => run_drift(args),
        Command::Cardcheck(args) => run_cardcheck(args),
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
    let mut reports = if args.no_cache {
        verify_all(&ureq, &packages, thresholds)?
    } else {
        let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
        verify_all(&cached, &packages, thresholds)?
    };

    // Fold in any local trust clears (a package cleared once in .vulkro/trust.toml).
    let trust = TrustStore::load(Path::new("."))?;
    for report in &mut reports {
        verify::apply_package_trust(report, &trust);
    }

    match resolve_format(args.format, args.json)? {
        OutputFormat::Text => {
            print!("{}", report::render_human(&reports));
            println!("\n{}", report::summary_line(&reports));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => println!("{}", report::render_json(&reports)?),
        OutputFormat::Sarif => println!(
            "{}",
            sarif::render(sarif::results_from_verify(&reports, args.manifest.as_deref()))?
        ),
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
    let findings = if args.result {
        scan_result_inputs(&args.manifests)?
    } else {
        if args.manifests.is_empty() {
            anyhow::bail!(
                "no manifest to scan: pass one or more MCP tool manifest JSON files, \
                 or use --result to scan untrusted text"
            );
        }
        let trust = TrustStore::load(Path::new("."))?;
        let mut findings = Vec::new();
        for path in &args.manifests {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let cleared = trust::fingerprint::manifest_fingerprint(&text)
                .ok()
                .map(|fp| trust.allows_fingerprint(trust::FpKind::Manifest, &fp))
                .unwrap_or(false);
            if cleared {
                findings.push(warden::report::trusted_finding());
            } else {
                findings.extend(warden::scan_manifest_text(&text)?);
            }
        }
        findings
    };

    match resolve_format(args.format, args.json)? {
        OutputFormat::Text => {
            print!("{}", warden::report::render_human(&findings));
            println!("\n{}", warden::report::summary_line(&findings));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => println!("{}", warden::report::render_json(&findings)?),
        OutputFormat::Sarif => {
            let source = warden_source_label(&args);
            println!(
                "{}",
                sarif::render(sarif::results_from_warden(&findings, &source))?
            );
        }
    }

    let flagged = warden::report::any_actionable(&findings);
    Ok(exit_code(flagged))
}

/// Scan untrusted content (`warden --result`): read each file as raw text, or
/// read from stdin when no file is given (or a single `-`).
fn scan_result_inputs(paths: &[PathBuf]) -> Result<Vec<warden::report::Finding>> {
    let use_stdin = paths.is_empty() || (paths.len() == 1 && paths[0].as_os_str() == "-");
    if use_stdin {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading untrusted content from stdin")?;
        Ok(warden::scan_content(&text, "stdin"))
    } else {
        let mut findings = Vec::new();
        for path in paths {
            findings.extend(warden::scan_result_file(path)?);
        }
        Ok(findings)
    }
}

/// A representative source label for warden's SARIF locations: the first input
/// file, or "stdin" when content is read from the pipe.
fn warden_source_label(args: &WardenArgs) -> String {
    let use_stdin = args.manifests.is_empty()
        || (args.manifests.len() == 1 && args.manifests[0].as_os_str() == "-");
    if use_stdin {
        return "stdin".to_string();
    }
    match args.manifests.first() {
        Some(path) => path.display().to_string(),
        None => "input".to_string(),
    }
}

fn run_inspect(args: InspectArgs) -> Result<ExitCode> {
    let mut thresholds = Thresholds::default();
    if let Some(days) = args.min_age_days {
        thresholds.min_age_days = days;
    }
    if let Some(downloads) = args.min_downloads {
        thresholds.min_downloads = downloads;
    }

    let trust = TrustStore::load(Path::new("."))?;
    let ureq = UreqClient::new();
    let report = if args.no_cache {
        inspect::inspect(&ureq, &args.server, args.manifest.as_deref(), thresholds, Some(&trust))?
    } else {
        let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
        inspect::inspect(
            &cached,
            &args.server,
            args.manifest.as_deref(),
            thresholds,
            Some(&trust),
        )?
    };

    match args.format {
        OutputFormat::Text => {
            print!("{}", inspect::render_human(&report));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => {
            println!("{}", sarif::render_json(&sarif::results_from_inspect(&report))?)
        }
        OutputFormat::Sarif => {
            println!("{}", sarif::render(sarif::results_from_inspect(&report))?)
        }
    }
    Ok(exit_code(report.verdict.is_flagged()))
}

fn run_audit(args: AuditArgs) -> Result<ExitCode> {
    let mut thresholds = Thresholds::default();
    if let Some(days) = args.min_age_days {
        thresholds.min_age_days = days;
    }
    if let Some(downloads) = args.min_downloads {
        thresholds.min_downloads = downloads;
    }

    let trust = TrustStore::load(Path::new("."))?;
    let ureq = UreqClient::new();
    let report = if args.no_cache {
        audit::audit(&ureq, thresholds, Some(&trust))?
    } else {
        let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
        audit::audit(&cached, thresholds, Some(&trust))?
    };

    // --write-baseline: record the current surface as a committable snapshot.
    if let Some(path) = &args.write_baseline {
        let written = audit::snapshot::write_baseline(path, &report.snapshot())?;
        println!("Wrote agent-surface baseline to {}", written.display());
        return Ok(ExitCode::SUCCESS);
    }

    // --diff: report only what appeared since the baseline.
    if let Some(path) = &args.diff {
        let baseline = audit::snapshot::load_baseline(path)?;
        let findings = audit::snapshot::diff(&baseline, &report.snapshot());
        match args.format {
            OutputFormat::Text => {
                print!("{}", warden::report::render_human(&findings));
                println!("\n{}", upsell::section());
            }
            OutputFormat::Json => println!(
                "{}",
                sarif::render_json(&sarif::results_from_warden(&findings, "audit-diff"))?
            ),
            OutputFormat::Sarif => println!(
                "{}",
                sarif::render(sarif::results_from_warden(&findings, "audit-diff"))?
            ),
        }
        return Ok(exit_code(warden::report::any_actionable(&findings)));
    }

    match args.format {
        OutputFormat::Text => {
            print!("{}", audit::render_human(&report));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => {
            println!("{}", sarif::render_json(&sarif::results_from_audit(&report))?)
        }
        OutputFormat::Sarif => {
            println!("{}", sarif::render(sarif::results_from_audit(&report))?)
        }
    }
    Ok(exit_code(report.is_flagged()))
}

fn run_skillscan(args: SkillscanArgs) -> Result<ExitCode> {
    let trust = TrustStore::load(&args.dir)?;
    let report = skillscan::skillscan(&args.dir, Some(&trust))?;
    match args.format {
        OutputFormat::Text => {
            print!("{}", skillscan::render_human(&report));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => {
            println!("{}", sarif::render_json(&sarif::results_from_skillscan(&report))?)
        }
        OutputFormat::Sarif => {
            println!("{}", sarif::render(sarif::results_from_skillscan(&report))?)
        }
    }
    Ok(exit_code(report.is_flagged()))
}

fn run_memcheck(args: MemcheckArgs) -> Result<ExitCode> {
    let trust = TrustStore::load(&args.dir)?;
    let report = memcheck::memcheck(&args.dir, &args.files, Some(&trust))?;
    match args.format {
        OutputFormat::Text => {
            print!("{}", memcheck::render_human(&report));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => {
            println!("{}", sarif::render_json(&sarif::results_from_memcheck(&report))?)
        }
        OutputFormat::Sarif => {
            println!("{}", sarif::render(sarif::results_from_memcheck(&report))?)
        }
    }
    Ok(exit_code(report.is_flagged()))
}

fn run_foresee(args: ForeseeArgs) -> Result<ExitCode> {
    eprintln!(
        "Predicting names your AI might invent and checking up to {} against the registry...",
        args.limit
    );
    let trust = TrustStore::load(&args.dir)?;
    let ureq = UreqClient::new();
    let report = if args.no_cache {
        foresee::foresee(&ureq, &args.dir, args.limit, Thresholds::default(), Some(&trust))?
    } else {
        let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
        foresee::foresee(
            &cached,
            &args.dir,
            args.limit,
            Thresholds::default(),
            Some(&trust),
        )?
    };

    // The committable guardrail file is written regardless of stdout format.
    let guardrail_path = if args.no_write {
        None
    } else {
        Some(foresee::write_guardrail(&args.dir, &report)?)
    };

    match args.format {
        OutputFormat::Text => {
            print!("{}", foresee::render_human(&report));
            if let Some(path) = &guardrail_path {
                println!(
                    "\nWrote {} name(s) to {} (point your agent at it: never install any of these).",
                    report.guardrail.len(),
                    path.display()
                );
            }
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => {
            println!("{}", sarif::render_json(&sarif::results_from_foresee(&report))?)
        }
        OutputFormat::Sarif => {
            println!("{}", sarif::render(sarif::results_from_foresee(&report))?)
        }
    }
    Ok(exit_code(report.is_flagged()))
}

fn run_cardcheck(args: CardcheckArgs) -> Result<ExitCode> {
    if args.target.is_some() && args.file.is_some() {
        anyhow::bail!("give only one source: a TARGET host/URL, or --file, not both");
    }

    // A local card from --file (or stdin via `-`).
    let local: Option<String> = match &args.file {
        Some(path) if path.as_os_str() == "-" => {
            let mut text = String::new();
            std::io::stdin()
                .read_to_string(&mut text)
                .context("reading the agent card from stdin")?;
            Some(text)
        }
        Some(path) => {
            Some(std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
        }
        None => None,
    };

    let report = if let Some(target) = &args.target {
        let ureq = UreqClient::new();
        if args.no_cache {
            cardcheck::cardcheck(&ureq, Some(target), None)?
        } else {
            let cached = CachingHttpClient::new(ureq, Duration::from_secs(CACHE_TTL_SECS))?;
            cardcheck::cardcheck(&cached, Some(target), None)?
        }
    } else if let Some(text) = &local {
        // A local card needs no network; the client is passed but never called.
        let ureq = UreqClient::new();
        cardcheck::cardcheck(&ureq, None, Some(text))?
    } else {
        anyhow::bail!(
            "no card to check: give a TARGET host/URL, --file <card.json>, or pipe a card on stdin"
        );
    };

    print!("{}", cardcheck::render_human(&report));
    println!("\n{}", upsell::section());
    Ok(exit_code(report.is_flagged()))
}

fn run_lock(args: LockArgs) -> Result<ExitCode> {
    if args.manifests.is_empty() {
        anyhow::bail!("no manifest to lock: pass one or more MCP tool manifest JSON files");
    }
    let lock_path = args
        .lock
        .unwrap_or_else(|| lock::default_lock_path(Path::new(".")));
    let report = lock::lock(&args.manifests, &lock_path)?;
    print!("{}", lock::render_lock_human(&report));
    println!("\n{}", upsell::section());
    Ok(ExitCode::SUCCESS)
}

fn run_drift(args: DriftArgs) -> Result<ExitCode> {
    if args.manifests.is_empty() {
        anyhow::bail!("no manifest to check: pass the current MCP tool manifest JSON file(s)");
    }
    let lock_path = args
        .lock
        .unwrap_or_else(|| lock::default_lock_path(Path::new(".")));
    let report = lock::drift(&args.manifests, &lock_path)?;
    match args.format {
        OutputFormat::Text => {
            print!("{}", lock::render_drift_human(&report));
            println!("\n{}", upsell::section());
        }
        OutputFormat::Json => println!("{}", lock::render_drift_json(&report)?),
        OutputFormat::Sarif => println!("{}", sarif::render(sarif::results_from_drift(&report))?),
    }
    Ok(exit_code(report.is_flagged()))
}

fn exit_code(flagged: bool) -> ExitCode {
    if flagged {
        ExitCode::from(EXIT_FLAGGED)
    } else {
        ExitCode::SUCCESS
    }
}

/// Resolve the effective output format, honoring the deprecated `--json` alias.
/// The deprecation warning goes to stderr so it never corrupts piped output.
fn resolve_format(format: OutputFormat, legacy_json: bool) -> Result<OutputFormat> {
    if legacy_json {
        if format == OutputFormat::Sarif {
            anyhow::bail!(
                "--json and --format sarif conflict: pass only one of --format json or --format sarif"
            );
        }
        eprintln!("warning: --json is deprecated and will be removed; use --format json instead");
        return Ok(OutputFormat::Json);
    }
    Ok(format)
}
