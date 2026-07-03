//! `trustdb`: a committed, diff-friendly `.vulkro/trust.toml` the free tools
//! consult.
//!
//! When a developer clears a specific artifact once (a package name@version, or
//! an MCP tool-manifest content fingerprint), every tool short-circuits to a
//! clean verdict for that EXACT artifact, and goes loud again the moment it
//! mutates (a different version, one changed manifest byte). The repo is the
//! backend and PR review is the approval flow: there is no server and no key.
//!
//! Trust is ALWAYS version-pinned or fingerprint-pinned, never name-only, so a
//! new (possibly malicious) version is never auto-cleared. A cleared artifact is
//! rendered with a visible "trusted (cleared in .vulkro/trust.toml)" marker, not
//! a bare pass, so the clear is always auditable in the diff.

pub mod command;
pub mod fingerprint;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use vulkro_feeds::Ecosystem;

/// The location of the store, relative to a project root.
const REL_PATH: &str = ".vulkro/trust.toml";

/// Which kind of content a fingerprint pin covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpKind {
    Manifest,
    Skill,
    Memory,
}

impl FpKind {
    pub fn key(self) -> &'static str {
        match self {
            FpKind::Manifest => "manifest",
            FpKind::Skill => "skill",
            FpKind::Memory => "memory",
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct TrustDoc {
    #[serde(default)]
    packages: BTreeMap<String, PackageEntry>,
    #[serde(default)]
    fingerprints: BTreeMap<String, FingerprintEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackageEntry {
    ecosystem: String,
    name: String,
    /// Kept sorted and deduped on write; NEVER a wildcard.
    versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FingerprintEntry {
    kind: String,
    id: String,
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// One row for `trustdb list`.
pub struct TrustRow {
    pub key: String,
    pub kind: &'static str,
    pub detail: String,
    pub note: Option<String>,
}

/// The committed trust store backing `.vulkro/trust.toml`.
pub struct TrustStore {
    path: PathBuf,
    doc: TrustDoc,
}

impl TrustStore {
    /// Load the store under `root`. A missing file is an empty store (not an
    /// error); a malformed file is an actionable error.
    pub fn load(root: &Path) -> Result<TrustStore> {
        let path = root.join(REL_PATH);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let doc: TrustDoc = toml::from_str(&text).with_context(|| {
                    format!(
                        "{} is not valid trust.toml. Fix the TOML syntax, or delete the file to reset the store",
                        path.display()
                    )
                })?;
                Ok(TrustStore { path, doc })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustStore {
                path,
                doc: TrustDoc::default(),
            }),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn package_key(eco: Ecosystem, name: &str) -> String {
        format!("{}:{}", eco.key(), name)
    }

    /// Fingerprint entries are keyed by their CONTENT (kind + fingerprint), not
    /// by path, so a clear is portable (it matches the reviewed content wherever
    /// the file lives, and however it is referenced). The stored `id` is only a
    /// human-readable label.
    fn fp_key(kind: FpKind, fp: &str) -> String {
        format!("{}:{}", kind.key(), fp)
    }

    /// True only when a package entry for (eco, name) lists exactly `version`.
    pub fn allows_package(&self, eco: Ecosystem, name: &str, version: &str) -> bool {
        self.doc
            .packages
            .get(&Self::package_key(eco, name))
            .map(|e| e.versions.iter().any(|v| v == version))
            .unwrap_or(false)
    }

    /// True when content with this exact fingerprint has been cleared for this
    /// kind. Content-based, so it is location-independent: a mutated artifact
    /// (a different fingerprint) never matches.
    pub fn allows_fingerprint(&self, kind: FpKind, fp: &str) -> bool {
        self.doc
            .fingerprints
            .get(&Self::fp_key(kind, fp))
            .map(|e| e.fingerprint == fp)
            .unwrap_or(false)
    }

    pub fn add_package(&mut self, eco: Ecosystem, name: &str, version: &str, note: Option<&str>) {
        let entry = self
            .doc
            .packages
            .entry(Self::package_key(eco, name))
            .or_insert_with(|| PackageEntry {
                ecosystem: eco.key().to_string(),
                name: name.to_string(),
                versions: Vec::new(),
                note: None,
            });
        entry.versions.push(version.to_string());
        entry.versions.sort();
        entry.versions.dedup();
        if let Some(n) = note {
            entry.note = Some(n.to_string());
        }
    }

    pub fn add_fingerprint(&mut self, kind: FpKind, id: &str, fp: &str, note: Option<&str>) {
        self.doc.fingerprints.insert(
            Self::fp_key(kind, fp),
            FingerprintEntry {
                kind: kind.key().to_string(),
                id: id.to_string(),
                fingerprint: fp.to_string(),
                note: note.map(str::to_string),
            },
        );
    }

    /// Remove one entry by its key (from either table). True if something went.
    pub fn remove(&mut self, key: &str) -> bool {
        self.doc.packages.remove(key).is_some() || self.doc.fingerprints.remove(key).is_some()
    }

    pub fn clear(&mut self) {
        self.doc.packages.clear();
        self.doc.fingerprints.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.doc.packages.is_empty() && self.doc.fingerprints.is_empty()
    }

    /// The rows for `trustdb list`, sorted by key.
    pub fn entries(&self) -> Vec<TrustRow> {
        let mut rows = Vec::new();
        for (key, e) in &self.doc.packages {
            rows.push(TrustRow {
                key: key.clone(),
                kind: "package",
                detail: format!("{} ({}) {}", e.name, e.ecosystem, e.versions.join(", ")),
                note: e.note.clone(),
            });
        }
        for (key, e) in &self.doc.fingerprints {
            rows.push(TrustRow {
                key: key.clone(),
                kind: "fingerprint",
                detail: format!("{} {} {}", e.kind, e.id, e.fingerprint),
                note: e.note.clone(),
            });
        }
        rows.sort_by(|a, b| a.key.cmp(&b.key));
        rows
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the store deterministically (BTreeMap keys sort, no timestamps).
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(&self.doc).context("serializing trust.toml")?;
        std::fs::write(&self.path, text)
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TrustStore {
        TrustStore {
            path: PathBuf::from("/tmp/does-not-matter/.vulkro/trust.toml"),
            doc: TrustDoc::default(),
        }
    }

    #[test]
    fn missing_file_is_an_empty_store() {
        let s = TrustStore::load(Path::new("/tmp/vulkro-nonexistent-xyz")).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn allows_only_the_exact_pinned_version() {
        let mut s = store();
        s.add_package(Ecosystem::Npm, "express", "4.18.2", None);
        assert!(s.allows_package(Ecosystem::Npm, "express", "4.18.2"));
        // a DIFFERENT version of the same name is NOT trusted (the anti-silent
        // -greenlight guarantee)
        assert!(!s.allows_package(Ecosystem::Npm, "express", "4.19.0"));
        // a different ecosystem is a different key
        assert!(!s.allows_package(Ecosystem::PyPI, "express", "4.18.2"));
    }

    #[test]
    fn fingerprint_must_match_exactly() {
        let mut s = store();
        s.add_fingerprint(FpKind::Manifest, "server.json", "deadbeefdeadbeef", None);
        // content match is location-independent (the id is only a label)
        assert!(s.allows_fingerprint(FpKind::Manifest, "deadbeefdeadbeef"));
        // a mutated artifact (a different fingerprint) re-flags
        assert!(!s.allows_fingerprint(FpKind::Manifest, "0000000000000000"));
        // the same fingerprint under a different kind is not a match
        assert!(!s.allows_fingerprint(FpKind::Skill, "deadbeefdeadbeef"));
    }

    #[test]
    fn versions_are_sorted_and_deduped() {
        let mut s = store();
        s.add_package(Ecosystem::Npm, "a", "2.0.0", None);
        s.add_package(Ecosystem::Npm, "a", "1.0.0", None);
        s.add_package(Ecosystem::Npm, "a", "2.0.0", None); // dup
        let rows = s.entries();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].detail.contains("1.0.0, 2.0.0"));
    }

    #[test]
    fn save_then_reserialize_is_byte_identical() {
        // Determinism: the same logical store serializes identically each time.
        let mut a = store();
        a.add_package(Ecosystem::Npm, "b", "1.0.0", Some("reviewed"));
        a.add_fingerprint(FpKind::Manifest, "m.json", "abc123abc123abc1", None);
        let first = toml::to_string_pretty(&a.doc).unwrap();
        let second = toml::to_string_pretty(&a.doc).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn remove_reports_whether_it_removed() {
        let mut s = store();
        s.add_package(Ecosystem::Npm, "a", "1.0.0", None);
        assert!(s.remove("npm:a"));
        assert!(!s.remove("npm:a"));
        assert!(s.is_empty());
    }
}
