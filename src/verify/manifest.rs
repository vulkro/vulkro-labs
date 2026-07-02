//! Extract dependency names from a project manifest, inferring the ecosystem
//! from the file name.
//!
//! Supported: `package.json` (npm), `requirements.txt` and `pyproject.toml`
//! (PyPI), and `Cargo.toml` (crates.io). Only names are read; version ranges
//! and specifiers are ignored because a range is not a concrete published
//! version. Results are sorted and de-duplicated. For Cargo, path and git
//! dependencies are skipped since they are not crates.io packages.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};

use vulkro_feeds::Ecosystem;

/// Read dependency names from a manifest file, returning the inferred ecosystem
/// and the names.
pub fn read_manifest(path: &Path) -> Result<(Ecosystem, Vec<String>)> {
    let ecosystem = infer_ecosystem(path)?;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let names = match ecosystem {
        Ecosystem::Npm => parse_package_json(&text)?,
        Ecosystem::PyPI => parse_python_manifest(path, &text)?,
        Ecosystem::Crates => parse_cargo_toml(&text)?,
    };
    Ok((ecosystem, names))
}

/// Infer the ecosystem from a manifest's file name.
fn infer_ecosystem(path: &Path) -> Result<Ecosystem> {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default();
    let lower = file.to_ascii_lowercase();
    if lower == "package.json" {
        Ok(Ecosystem::Npm)
    } else if lower == "pyproject.toml"
        || (lower.starts_with("requirements") && lower.ends_with(".txt"))
    {
        Ok(Ecosystem::PyPI)
    } else if lower == "cargo.toml" {
        Ok(Ecosystem::Crates)
    } else {
        anyhow::bail!(
            "cannot tell which ecosystem '{file}' is for; supported manifests are \
             package.json, requirements.txt, pyproject.toml, and Cargo.toml"
        )
    }
}

// --- npm: package.json --------------------------------------------------------

/// Parse all dependency names from `package.json` text.
///
/// Skips dependencies whose version specifier does not point at the public npm
/// registry (local `file:`/`link:`/`portal:` paths, `git`/`http` URLs,
/// `workspace:`/`catalog:` protocols, and `owner/repo` GitHub shorthands), and
/// resolves `npm:<target>@<range>` aliases to the target package. Reporting a
/// local or git dependency by its key name would produce a false MISSING, or
/// even a false MALICIOUS when the key collides with a real flagged package.
pub fn parse_package_json(text: &str) -> Result<Vec<String>> {
    use serde::Deserialize;
    use std::collections::BTreeMap;

    // Values are version specifiers; keep them as raw JSON so a malformed
    // non-string value never fails the whole parse.
    type Deps = BTreeMap<String, serde_json::Value>;

    #[derive(Deserialize)]
    struct Manifest {
        #[serde(default)]
        dependencies: Deps,
        #[serde(default, rename = "devDependencies")]
        dev_dependencies: Deps,
        #[serde(default, rename = "optionalDependencies")]
        optional_dependencies: Deps,
        #[serde(default, rename = "peerDependencies")]
        peer_dependencies: Deps,
    }

    let manifest: Manifest =
        serde_json::from_str(text).context("parsing package.json (is it valid JSON?)")?;
    let mut names = BTreeSet::new();
    for block in [
        &manifest.dependencies,
        &manifest.dev_dependencies,
        &manifest.optional_dependencies,
        &manifest.peer_dependencies,
    ] {
        for (name, spec) in block {
            if let Some(resolved) = npm_registry_name(name, spec.as_str().unwrap_or("")) {
                names.insert(resolved);
            }
        }
    }
    Ok(names.into_iter().collect())
}

/// The npm registry name to check for a `package.json` dependency, or `None`
/// when the version spec points somewhere other than the public registry.
fn npm_registry_name(name: &str, spec: &str) -> Option<String> {
    let spec = spec.trim();

    // `npm:<target>@<range>` alias: check what actually installs, not the key.
    if let Some(target) = spec.strip_prefix("npm:") {
        return npm_alias_target(target);
    }

    // Non-registry protocols: local paths, VCS, URLs, workspace / catalog.
    const NON_REGISTRY: [&str; 12] = [
        "file:", "link:", "portal:", "workspace:", "catalog:", "git:", "git+",
        "github:", "gitlab:", "bitbucket:", "http:", "https:",
    ];
    if NON_REGISTRY.iter().any(|p| spec.starts_with(p)) {
        return None;
    }

    // `owner/repo` (optionally `#ref`) GitHub shorthand: a semver range never
    // contains a slash, so a slash means a shorthand, not a version.
    if spec.contains('/') {
        return None;
    }

    // Otherwise a semver range, dist-tag, or empty spec: the key is the name.
    Some(name.to_string())
}

/// Resolve an `npm:` alias body (`<target>@<range>` or a bare `<target>`) to the
/// target package name, preserving a leading `@scope/`.
fn npm_alias_target(rest: &str) -> Option<String> {
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    let name = if let Some(after) = rest.strip_prefix('@') {
        // `@scope/name@range`: keep the scope, cut at the version `@`.
        match after.find('@') {
            Some(at) => format!("@{}", &after[..at]),
            None => rest.to_string(),
        }
    } else {
        match rest.find('@') {
            Some(at) => rest[..at].to_string(),
            None => rest.to_string(),
        }
    };
    (!name.is_empty()).then_some(name)
}

// --- PyPI: requirements.txt and pyproject.toml -------------------------------

fn parse_python_manifest(path: &Path, text: &str) -> Result<Vec<String>> {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if file == "pyproject.toml" {
        parse_pyproject(text)
    } else {
        Ok(parse_requirements(text))
    }
}

/// Parse dependency names from a `requirements.txt`.
pub fn parse_requirements(text: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for raw in text.lines() {
        // Strip an inline comment (a `#` preceded by whitespace, or at start).
        let line = strip_requirements_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        // Skip pip options (-r, -e, --hash, -c) and direct URLs / VCS installs.
        if line.starts_with('-') || line.contains("://") {
            continue;
        }
        if let Some(name) = pep508_name(line) {
            names.insert(name);
        }
    }
    names.into_iter().collect()
}

fn strip_requirements_comment(line: &str) -> &str {
    if let Some(stripped) = line.strip_prefix('#') {
        // Whole-line comment.
        let _ = stripped;
        return "";
    }
    match line.find(" #") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Parse dependency names from a `pyproject.toml` (PEP 621 `[project]` and
/// Poetry `[tool.poetry...]`).
pub fn parse_pyproject(text: &str) -> Result<Vec<String>> {
    let value: toml::Value = toml::from_str(text).context("parsing pyproject.toml")?;
    let mut names = BTreeSet::new();

    // PEP 621: [project].dependencies is an array of PEP 508 strings.
    if let Some(deps) = value
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        collect_pep508_array(deps, &mut names);
    }
    // PEP 621: [project.optional-dependencies] is a table of arrays.
    if let Some(groups) = value
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for arr in groups.values().filter_map(|v| v.as_array()) {
            collect_pep508_array(arr, &mut names);
        }
    }
    // Poetry: [tool.poetry.dependencies] and dev / group tables map name -> spec.
    if let Some(poetry) = value
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.as_table())
    {
        collect_poetry_table(poetry.get("dependencies"), &mut names);
        collect_poetry_table(poetry.get("dev-dependencies"), &mut names);
        if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
            for group in groups.values() {
                collect_poetry_table(group.get("dependencies"), &mut names);
            }
        }
    }

    Ok(names.into_iter().collect())
}

fn collect_pep508_array(array: &[toml::Value], names: &mut BTreeSet<String>) {
    for spec in array.iter().filter_map(|v| v.as_str()) {
        if let Some(name) = pep508_name(spec) {
            names.insert(name);
        }
    }
}

fn collect_poetry_table(table: Option<&toml::Value>, names: &mut BTreeSet<String>) {
    let Some(table) = table.and_then(|t| t.as_table()) else {
        return;
    };
    for (key, value) in table {
        // Poetry pins the interpreter as a "python" dependency; skip it.
        if key == "python" {
            continue;
        }
        // Skip path / git / url dependencies: they are not PyPI packages.
        if let Some(spec) = value.as_table() {
            if spec.contains_key("path") || spec.contains_key("git") || spec.contains_key("url") {
                continue;
            }
        }
        names.insert(key.clone());
    }
}

/// Extract the distribution name from a PEP 508 requirement string, e.g.
/// `requests[security]>=2.0; python_version<'3.8'` -> `requests`.
fn pep508_name(spec: &str) -> Option<String> {
    let spec = spec.trim();
    let end = spec
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .unwrap_or(spec.len());
    let name = &spec[..end];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// --- crates.io: Cargo.toml ----------------------------------------------------

/// Parse crate dependency names from a `Cargo.toml`, skipping path and git
/// dependencies and honoring `package = "..."` renames.
pub fn parse_cargo_toml(text: &str) -> Result<Vec<String>> {
    let value: toml::Value = toml::from_str(text).context("parsing Cargo.toml")?;
    let mut names = BTreeSet::new();

    collect_cargo_sections(&value, &mut names);
    // Platform-specific dependencies live under [target.<cfg>.<section>].
    if let Some(targets) = value.get("target").and_then(|t| t.as_table()) {
        for target in targets.values() {
            collect_cargo_sections(target, &mut names);
        }
    }

    Ok(names.into_iter().collect())
}

fn collect_cargo_sections(table: &toml::Value, names: &mut BTreeSet<String>) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(deps) = table.get(section).and_then(|d| d.as_table()) {
            for (key, spec) in deps {
                if let Some(name) = cargo_dep_name(key, spec) {
                    names.insert(name);
                }
            }
        }
    }
}

/// The crates.io name for a Cargo dependency entry, or `None` if it is a path
/// or git dependency (not a crates.io package).
fn cargo_dep_name(key: &str, spec: &toml::Value) -> Option<String> {
    if let Some(table) = spec.as_table() {
        if table.contains_key("path") || table.contains_key("git") {
            return None;
        }
        if let Some(renamed) = table.get("package").and_then(|p| p.as_str()) {
            return Some(renamed.to_string());
        }
    }
    Some(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_json_collects_all_blocks_sorted_deduped() {
        let text = r#"{
            "dependencies": {"express": "^4", "lodash": "^4"},
            "devDependencies": {"vitest": "^1", "express": "^4"},
            "optionalDependencies": {"fsevents": "*"},
            "peerDependencies": {"react": ">=18"}
        }"#;
        assert_eq!(
            parse_package_json(text).unwrap(),
            vec!["express", "fsevents", "lodash", "react", "vitest"]
        );
    }

    #[test]
    fn package_json_skips_non_registry_specifiers() {
        // Regression: local / git / url / workspace / catalog / shorthand deps
        // are not registry packages and must not be reported (a `file:` key that
        // collides with a flagged package name was a false MALICIOUS). `npm:`
        // aliases resolve to the target that actually installs.
        let text = r#"{
            "dependencies": {
                "express": "^4.18.2",
                "@babel/core": "^7.0.0",
                "local-dep": "file:../local",
                "git-dep": "git+https://github.com/foo/bar.git",
                "url-dep": "https://example.com/x.tgz",
                "workspace-dep": "workspace:*",
                "catalog-dep": "catalog:",
                "shorthand": "expressjs/express#1.2.3",
                "aliased": "npm:string-width@4",
                "scoped-alias": "npm:@scope/real@1.0"
            },
            "devDependencies": {
                "gh-short": "github:user/repo"
            }
        }"#;
        assert_eq!(
            parse_package_json(text).unwrap(),
            vec!["@babel/core", "@scope/real", "express", "string-width"]
        );
    }

    #[test]
    fn requirements_extracts_names_and_skips_options() {
        let text = "\
# a comment\n\
requests==2.31.0\n\
Django>=4.0  # inline comment\n\
flask[async]~=3.0; python_version<'3.11'\n\
-r other.txt\n\
--hash=sha256:abc\n\
https://example.com/pkg.whl\n\
\n\
numpy\n";
        assert_eq!(
            parse_requirements(text),
            vec!["Django", "flask", "numpy", "requests"]
        );
    }

    #[test]
    fn pyproject_reads_pep621_and_poetry() {
        let text = r#"
[project]
dependencies = ["requests>=2", "flask"]

[project.optional-dependencies]
test = ["pytest>=7"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
internal = { path = "../internal" }
forked = { git = "https://example.com/forked.git" }

[tool.poetry.group.dev.dependencies]
black = "^24"
"#;
        // `internal` (path) and `forked` (git) are not PyPI packages and must
        // be skipped, like the Cargo parser does.
        assert_eq!(
            parse_pyproject(text).unwrap(),
            vec!["black", "flask", "httpx", "pytest", "requests"]
        );
    }

    #[test]
    fn cargo_reads_sections_skips_path_git_and_honors_rename() {
        let text = r#"
[dependencies]
serde = "1"
renamed = { package = "real-crate", version = "1" }
local = { path = "../local" }
forked = { git = "https://example.com/x" }

[dev-dependencies]
tokio = { version = "1", features = ["full"] }

[build-dependencies]
cc = "1"

[target.'cfg(unix)'.dependencies]
nix = "0.27"
"#;
        assert_eq!(
            parse_cargo_toml(text).unwrap(),
            vec!["cc", "nix", "real-crate", "serde", "tokio"]
        );
    }

    #[test]
    fn unknown_manifest_name_errors() {
        let err = infer_ecosystem(Path::new("/tmp/mystery.lock")).unwrap_err();
        assert!(err.to_string().contains("supported manifests"));
    }
}
