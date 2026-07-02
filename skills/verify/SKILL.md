---
name: verify
description: Check that packages an AI agent suggested are real (not hallucinated or slopsquatted), not known-malicious, and not suspiciously new or low-reputation, before installing them. Use before adding or installing an npm, PyPI, or crates.io dependency, or to vet all dependencies in a package.json, requirements.txt, pyproject.toml, or Cargo.toml.
---

# verify - the AI package bouncer

`verify` confirms a dependency is safe to install before it lands in a
project. It is keyless and local: only package names are sent to public
services (the npm registry, PyPI, crates.io, and OSV.dev), never your source
code.

## When to use

- Right before you install or add a dependency an agent suggested.
- To vet every dependency in a manifest.
- Whenever a package name looks unfamiliar or was invented on the fly.

## How to run

Single packages (default ecosystem is npm):

```
vulkro-live verify express left-pad@1.3.0
```

Other ecosystems with `--ecosystem` (npm, pypi, crates):

```
vulkro-live verify --ecosystem pypi requests flask
vulkro-live verify --ecosystem crates serde tokio
```

Vet a whole manifest (the ecosystem is inferred from the file name:
package.json, requirements.txt, pyproject.toml, Cargo.toml):

```
vulkro-live verify --manifest ./package.json
```

Machine-readable output for further processing:

```
vulkro-live verify --json express some-fake-pkg
```

## Reading the result

Each package gets one verdict:

- `MISSING` - not in the registry. Treat as a likely hallucination or
  slopsquat. Do not install.
- `MALICIOUS` - flagged by OSV (an OpenSSF malicious-packages record). Do not
  install.
- `SUSPICIOUS` - exists, but very new or with very few downloads. Pause and
  confirm it is the package you intended.
- `OK` - real, not flagged, reasonable reputation.

Exit codes: `0` when every package is OK, `1` when one or more are flagged,
`2` on an error. If anything is MISSING or MALICIOUS, do not install it;
surface the finding to the user.
