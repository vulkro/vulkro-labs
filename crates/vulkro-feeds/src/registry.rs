//! Ecosystem-dispatching front door for the registry clients.
//!
//! Callers work in terms of an [`Ecosystem`] and a package name; this module
//! routes to the right client so verdict logic never has to branch per
//! ecosystem. It is the single source of truth for which registries are
//! supported.

use anyhow::Result;

use crate::crates_io::CratesIo;
use crate::ecosystem::{Ecosystem, PackageMetadata, ProvenanceInfo, Reputation};
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

/// Published build-provenance / attestation PRESENCE for `name` (optionally at
/// `version`) in `ecosystem`. `Ok(None)` when the package does not exist.
///
/// This is a commodity presence read of public registry metadata, never a
/// cryptographic verification. crates.io does not advertise per-version
/// provenance keyless, so it reports no attestation rather than querying.
pub fn provenance(
    http: &dyn HttpClient,
    ecosystem: Ecosystem,
    name: &str,
    version: Option<&str>,
) -> Result<Option<ProvenanceInfo>> {
    match ecosystem {
        Ecosystem::Npm => Npm::new(http).provenance(name, version),
        Ecosystem::PyPI => PyPi::new(http).provenance(name, version),
        // crates.io publishes no keyless per-version provenance metadata; report
        // "not supported" via an existence-checked Absent so the tool can say so
        // honestly rather than implying the crate lacks provenance.
        Ecosystem::Crates => Ok(CratesIo::new(http).lookup(name)?.map(|meta| ProvenanceInfo {
            version: version.map(str::to_string).or(meta.latest_version),
            ..ProvenanceInfo::default()
        })),
    }
}

/// Whether an ecosystem exposes keyless per-version provenance / attestation
/// metadata at all. crates.io does not, so a missing attestation there is "not
/// available", not a signal.
pub fn provenance_supported(ecosystem: Ecosystem) -> bool {
    matches!(ecosystem, Ecosystem::Npm | Ecosystem::PyPI)
}
