//! The package ecosystems `verify` supports, and the shared metadata types
//! every registry client returns.
//!
//! Only ecosystems whose keyless per-user querying is confirmed clean live
//! here (npm, PyPI, crates.io). Go, Maven, and deps.dev are intentionally
//! absent until their terms are confirmed directly.

/// A supported package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// The npm registry (JavaScript / Node).
    Npm,
    /// The Python Package Index.
    PyPI,
    /// crates.io (Rust).
    Crates,
}

impl Ecosystem {
    /// Every supported ecosystem.
    pub const ALL: [Ecosystem; 3] = [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Crates];

    /// The exact OSV ecosystem string (case-sensitive).
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Crates => "crates.io",
        }
    }

    /// The short key used on the command line and in JSON output.
    pub fn key(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::Crates => "crates",
        }
    }

    /// A human-readable label for display.
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Crates => "crates.io",
        }
    }

    /// The window a download count covers for this ecosystem, if it exposes one
    /// keyless. `None` means no keyless download signal (PyPI).
    pub fn downloads_window(self) -> Option<&'static str> {
        match self {
            Ecosystem::Npm => Some("weekly"),
            Ecosystem::Crates => Some("90-day"),
            Ecosystem::PyPI => None,
        }
    }

    /// Parse an ecosystem from a user-supplied string. Accepts common aliases.
    pub fn parse(input: &str) -> Option<Ecosystem> {
        match input.trim().to_ascii_lowercase().as_str() {
            "npm" | "node" | "javascript" | "js" => Some(Ecosystem::Npm),
            "pypi" | "pip" | "python" | "py" => Some(Ecosystem::PyPI),
            "crates" | "crates.io" | "cargo" | "rust" => Some(Ecosystem::Crates),
            _ => None,
        }
    }
}

/// Core public metadata about a package: enough to decide existence and check a
/// requested version. `latest_version` and `created` are populated when the
/// existence lookup returns them cheaply (npm, PyPI); for crates.io they arrive
/// with the [`Reputation`] enrichment instead.
#[derive(Debug, Clone, Default)]
pub struct PackageMetadata {
    pub name: String,
    pub latest_version: Option<String>,
    pub created: Option<String>,
    pub versions: Vec<String>,
}

impl PackageMetadata {
    /// Whether `version` is among the published versions.
    pub fn has_version(&self, version: &str) -> bool {
        self.versions.iter().any(|v| v == version)
    }
}

/// Reputation enrichment fetched only when it can change a verdict. Fields are
/// `None` when the ecosystem does not expose them keyless (e.g. PyPI downloads)
/// or when they were already provided by the existence lookup.
#[derive(Debug, Clone, Default)]
pub struct Reputation {
    pub created: Option<String>,
    pub latest_version: Option<String>,
    pub downloads: Option<u64>,
}

/// Structural presence of a published build-provenance / attestation record for
/// one package version, read from public registry metadata.
///
/// There is deliberately NO `Verified` state: reading this metadata is a
/// PRESENCE check, not a cryptographic verification, so it can never represent
/// (and can never claim) a verified attestation. Whether the linked source
/// repository is well-formed is orthogonal and lives in [`ProvenanceInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPresence {
    /// The registry advertises no provenance / attestation for this version.
    Absent,
    /// A provenance / attestation record is present and structurally complete.
    PresentWellFormed,
    /// A provenance / attestation record is present but missing expected parts.
    PresentMalformed,
}

/// Commodity build-provenance metadata for one package version, read live from
/// public registry metadata. It records only what the registry advertises: it
/// performs no cryptographic verification and has no "verified" state.
#[derive(Debug, Clone)]
pub struct ProvenanceInfo {
    /// The version this metadata was read for (the latest, unless pinned).
    pub version: Option<String>,
    /// Structural presence of the provenance / attestation record.
    pub presence: AttestationPresence,
    /// The kinds of attestation the registry advertises (e.g. `provenance`,
    /// `publish`), best-effort, for display only.
    pub kinds: Vec<String>,
    /// The source repository URL the package metadata links to, if any. Used
    /// only to note a mismatch as a REVIEW signal, never as a hard fail.
    pub source_repo: Option<String>,
}

impl Default for ProvenanceInfo {
    fn default() -> Self {
        Self {
            version: None,
            presence: AttestationPresence::Absent,
            kinds: Vec::new(),
            source_repo: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_aliases() {
        assert_eq!(Ecosystem::parse("NPM"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::parse("pip"), Some(Ecosystem::PyPI));
        assert_eq!(Ecosystem::parse("cargo"), Some(Ecosystem::Crates));
        assert_eq!(Ecosystem::parse("maven"), None);
    }

    #[test]
    fn osv_names_are_exact() {
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
        assert_eq!(Ecosystem::Crates.osv_name(), "crates.io");
    }
}
