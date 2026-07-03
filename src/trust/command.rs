//! The `trustdb` subcommand: clear an artifact once, list, remove, clear.
//!
//! Administrative, so the exit code is 0 on success and 2 on a bad argument or
//! IO error (never 1: it does not scan for findings).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use vulkro_feeds::Ecosystem;

use super::fingerprint;
use super::{FpKind, TrustStore};
use crate::upsell;
use crate::verify::PackageRef;

#[derive(Args)]
pub struct TrustdbArgs {
    #[command(subcommand)]
    action: TrustdbAction,
}

#[derive(Subcommand)]
enum TrustdbAction {
    /// Clear one artifact so every tool trusts that exact version / fingerprint.
    Add(AddArgs),
    /// List every cleared artifact.
    List(DirArg),
    /// Remove one entry by its key (see `trustdb list`).
    Remove(RemoveArgs),
    /// Remove every entry.
    Clear(DirArg),
}

#[derive(Args)]
struct DirArg {
    /// Project directory holding .vulkro/trust.toml (default: current).
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: PathBuf,
}

#[derive(Args)]
struct RemoveArgs {
    /// The entry key to remove (from `trustdb list`).
    #[arg(value_name = "KEY")]
    key: String,

    /// Project directory holding .vulkro/trust.toml (default: current).
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: PathBuf,
}

#[derive(Args)]
struct AddArgs {
    /// A package to clear, as name@version (a version is required). The
    /// ecosystem defaults to npm; use --ecosystem for pypi or crates.
    #[arg(value_name = "PACKAGE")]
    package: Option<String>,

    /// Ecosystem for the package: npm (default), pypi, or crates.
    #[arg(long, value_name = "ECOSYSTEM", default_value = "npm")]
    ecosystem: String,

    /// Clear an MCP tool manifest (a JSON file) by its content fingerprint.
    #[arg(long, value_name = "FILE")]
    manifest: Option<PathBuf>,

    /// Clear a skill / command / instruction file by its content fingerprint.
    #[arg(long, value_name = "FILE")]
    skill: Option<PathBuf>,

    /// Clear a memory file by its content fingerprint.
    #[arg(long, value_name = "FILE")]
    memory: Option<PathBuf>,

    /// An optional note recorded with the entry (why it was cleared).
    #[arg(long, value_name = "TEXT")]
    note: Option<String>,

    /// Project directory holding .vulkro/trust.toml (default: current).
    #[arg(long, value_name = "DIR", default_value = ".")]
    dir: PathBuf,
}

pub fn run(args: TrustdbArgs) -> Result<ExitCode> {
    match args.action {
        TrustdbAction::Add(a) => add(a),
        TrustdbAction::List(d) => list(d),
        TrustdbAction::Remove(r) => remove(r),
        TrustdbAction::Clear(d) => clear(d),
    }
}

fn add(a: AddArgs) -> Result<ExitCode> {
    let kinds = [
        a.package.is_some(),
        a.manifest.is_some(),
        a.skill.is_some(),
        a.memory.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if kinds != 1 {
        anyhow::bail!(
            "clear exactly one artifact: a PACKAGE (name@version), or one of --manifest / --skill / --memory <file>"
        );
    }

    let mut store = TrustStore::load(&a.dir)?;
    let note = a.note.as_deref();

    if let Some(pkg) = &a.package {
        let eco = Ecosystem::parse(&a.ecosystem).with_context(|| {
            format!("unknown ecosystem '{}' (use npm, pypi, or crates)", a.ecosystem)
        })?;
        let pref = PackageRef::parse(pkg, eco)?;
        let version = pref.version.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "a package clear must pin a version: use name@version so a new (possibly bad) version is never auto-trusted"
            )
        })?;
        store.add_package(eco, &pref.name, version, note);
        store.save()?;
        println!(
            "Cleared {} ({}) {} in {}",
            pref.name,
            eco.key(),
            version,
            store.path().display()
        );
    } else if let Some(path) = &a.manifest {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let fp = fingerprint::manifest_fingerprint(&text)?;
        let id = path.display().to_string();
        store.add_fingerprint(FpKind::Manifest, &id, &fp, note);
        store.save()?;
        println!(
            "Cleared manifest {id} (fingerprint {fp}) in {}",
            store.path().display()
        );
    } else if let Some(path) = &a.skill {
        let fp = crate::skillscan::skill_fingerprint(path)?;
        let id = path.display().to_string();
        store.add_fingerprint(FpKind::Skill, &id, &fp, note);
        store.save()?;
        println!(
            "Cleared skill {id} (fingerprint {fp}) in {}",
            store.path().display()
        );
    } else if let Some(path) = &a.memory {
        let fp = crate::memcheck::memory_fingerprint(path)?;
        let id = path.display().to_string();
        store.add_fingerprint(FpKind::Memory, &id, &fp, note);
        store.save()?;
        println!(
            "Cleared memory {id} (fingerprint {fp}) in {}",
            store.path().display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn list(d: DirArg) -> Result<ExitCode> {
    let store = TrustStore::load(&d.dir)?;
    if store.is_empty() {
        println!("No cleared artifacts in {}.", store.path().display());
        println!("\n{}", upsell::section());
        return Ok(ExitCode::SUCCESS);
    }
    let rows = store.entries();
    {
        let kind_width = rows.iter().map(|r| r.kind.len()).max().unwrap_or(0);
        let key_width = rows.iter().map(|r| r.key.chars().count()).max().unwrap_or(0);
        for row in &rows {
            let note = match &row.note {
                Some(n) => format!("  # {n}"),
                None => String::new(),
            };
            println!(
                "{:<kind_width$}  {:<key_width$}  {}{note}",
                row.kind, row.key, row.detail
            );
        }
    }
    println!("\n{}", upsell::section());
    Ok(ExitCode::SUCCESS)
}

fn remove(r: RemoveArgs) -> Result<ExitCode> {
    let mut store = TrustStore::load(&r.dir)?;
    if store.remove(&r.key) {
        store.save()?;
        println!("Removed {} from {}", r.key, store.path().display());
        Ok(ExitCode::SUCCESS)
    } else {
        anyhow::bail!(
            "no entry with key '{}' (run `trustdb list` to see the keys)",
            r.key
        );
    }
}

fn clear(d: DirArg) -> Result<ExitCode> {
    let mut store = TrustStore::load(&d.dir)?;
    store.clear();
    store.save()?;
    println!("Cleared all entries from {}", store.path().display());
    Ok(ExitCode::SUCCESS)
}
