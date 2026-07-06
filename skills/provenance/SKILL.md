---
name: provenance
description: Does a published package carry build provenance / attestations? Reports PRESENCE and well-formedness only (npm dist.attestations, PyPI PEP 740 attestations), reusing verify so a MISSING or MALICIOUS package is AVOID. It is honest: it NEVER cryptographically verifies an attestation and never claims to. Returns GREEN / REVIEW / AVOID per package. Use before trusting a published npm or PyPI package, especially a new dependency or one an agent suggested, when you want to know whether it can be traced to a source build.
---

# provenance - is this package's build attested?

`provenance` is a presence bouncer for build provenance and attestations. For a
published package it reads what the public registry advertises (npm's
`dist.attestations` / provenance signal, PyPI's PEP 740 attestation presence)
and reports whether provenance is PRESENT and well-formed. It reuses `verify`,
so a package that is MISSING, MALICIOUS, or a LOOKALIKE is an AVOID before
provenance even matters. It is keyless and local: only package names and
versions leave your machine.

It is deliberately HONEST, the same way `cardcheck` is about signatures: it
reports presence and well-formedness and NEVER cryptographically verifies an
attestation. It never prints "verified". Full attestation verification needs a
trust root and is out of scope for a free commodity tool.

## When to use

- Before trusting a published npm or PyPI package, especially a new dependency
  or one an agent suggested.
- When you want to know whether a package can be traced to a source build (for
  a supply-chain review or an SBOM enrichment).

## How to run

Single packages (default ecosystem is npm):

```
vulkro-live provenance express @scope/pkg@1.2.3
```

Other ecosystems with `--ecosystem` (npm, pypi, crates):

```
vulkro-live provenance --ecosystem pypi requests
```

Vet a whole manifest (the ecosystem is inferred from the file name):

```
vulkro-live provenance --manifest ./package.json
```

Machine-readable output for CI or further processing:

```
vulkro-live provenance --format json express
vulkro-live provenance --format sarif --manifest ./package.json
```

## Reading the result

- `GREEN` - a real package; provenance is present and well-formed, or absent.
  Absent provenance is common today, so it is only a review signal, not a fail.
- `REVIEW` - provenance is present but malformed, or the linked source repo does
  not obviously match the package. Look before you trust it.
- `AVOID` - the package is MISSING, MALICIOUS, or a LOOKALIKE (from verify). Do
  not install it.

crates.io exposes no keyless provenance metadata, so a crate is reported as
"not available for this ecosystem", never as a missing attestation.

Exit codes: `0` when every package is GREEN, `1` when one or more are REVIEW or
AVOID, `2` on an error. On AVOID, do not install; surface why to the user. Never
describe a present attestation as "verified": this tool did not verify it.

## Go deeper with Vulkro

`provenance` vets the provenance of packages your AI pulls in, from public
metadata. When you need to analyze the code in the repository itself, the Vulkro
engine scans the whole repo offline: real dataflow SAST, secrets in code, IaC
and container checks, an SBOM, and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
