//! Ecosystem-dispatching front door for the registry clients.
//!
//! Callers work in terms of an [`Ecosystem`] and a package name; this module
//! routes to the right client so verdict logic never has to branch per
//! ecosystem. It is the single source of truth for which registries are
//! supported.

use anyhow::Result;

use crate::crates_io::CratesIo;
use crate::ecosystem::{Ecosystem, PackageMetadata, Reputation};
use crate::http::HttpClient;
use crate::npm::Npm;
use crate::pypi::PyPi;

/// Existence and core metadata for `name` in `ecosystem`. `Ok(None)` when the
/// package does not exist.
pub fn lookup(
    http: &dyn HttpClient,
    ecosystem: Ecosystem,
    name: &str,
) -> Result<Option<PackageMetadata>> {
    match ecosystem {
        Ecosystem::Npm => Npm::new(http).lookup(name),
        Ecosystem::PyPI => PyPi::new(http).lookup(name),
        Ecosystem::Crates => CratesIo::new(http).lookup(name),
    }
}

/// Reputation enrichment for `name` in `ecosystem`. Call only when it can
/// change a verdict; some ecosystems perform an extra request here.
pub fn reputation(http: &dyn HttpClient, ecosystem: Ecosystem, name: &str) -> Result<Reputation> {
    match ecosystem {
        Ecosystem::Npm => Npm::new(http).reputation(name),
        Ecosystem::PyPI => PyPi::new(http).reputation(name),
        Ecosystem::Crates => CratesIo::new(http).reputation(name),
    }
}
