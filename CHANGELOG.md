# Changelog

All notable, user-facing changes to Vulkro Labs tools are recorded here: new
tools, new checks, and fixes. The format follows Keep a Changelog, and the
project aims to follow Semantic Versioning.

## [Unreleased]

## [0.1.1]

### Fixed

- `verify --manifest package.json`: dependencies that do not come from the npm
  registry (local `file:` / `link:` / `portal:` paths, `git` and `http` URLs,
  the `workspace:` and `catalog:` protocols, and `owner/repo` GitHub shorthands)
  are no longer treated as package names. Previously they produced false
  verdicts, including a false `MALICIOUS` when a local dependency's name
  collided with a flagged registry package. `npm:` aliases now resolve to the
  package that actually installs, so it is the one that gets checked.

## [0.1.0]

### Changed

- The installer is served from `dist.vulkro.com/install-live.sh`, matching the
  CDN and scheme of the other Vulkro CLIs: SHA-256-verified
  `vulkro-live-<version>-<platform>` archives and a `latest-live.json` version
  feed.

### Added

- Cargo workspace scaffold: the `vulkro-live` binary plus the shared,
  keyless `vulkro-feeds` crate.
- `vulkro-live verify` - the AI package bouncer, for **npm, PyPI, and
  crates.io**. Given packages as `name`, `name@version`, `--ecosystem`, or via
  `--manifest` (package.json, requirements.txt, pyproject.toml, or Cargo.toml,
  with the ecosystem inferred from the file name), it reports one verdict per
  package:
  - `MISSING` - not in the registry (a likely AI hallucination or slopsquat),
    or the requested version was never published.
  - `MALICIOUS` - flagged by OSV.dev (an OpenSSF malicious-packages record).
  - `SUSPICIOUS` - exists, but very new or with very few downloads.
  - `OK` - otherwise.
  Keyless and local: no account, no API key, no backend. Only package names
  are sent to public services; source code never leaves the machine. Supports
  `--json`. Exit codes: `0` all OK, `1` one or more flagged, `2` error.
- `vulkro-live warden` - the MCP / agent-tool bouncer. Statically scans an MCP
  server's tool manifest (a `tools/list` result, array, or single tool) for
  prompt-injection and tool-poisoning text, hidden or invisible unicode,
  tool-shadowing (duplicate or builtin-colliding names), sensitive-data
  parameters, and risky capabilities or annotations. Reads only tool metadata;
  never inspects or runs code. Supports `--json`. Exit codes: `0` clean, `1`
  when a HIGH or MEDIUM finding is present, `2` error.
- `vulkro-live mcp` - one MCP server (stdio, JSON-RPC 2.0) exposing both
  `verify` and `warden` as tools to an AI agent.
- Claude Code skills for `verify` and `warden` under `skills/`.
- `vulkro-feeds`: keyless clients for npm, PyPI, and crates.io (existence,
  metadata, reputation), OSV.dev malicious-package lookups, and MCP
  tool-manifest parsing, behind an injectable HTTP layer so tools and tests
  can supply their own transport.
- `verify` tuning flags: `--min-age-days` and `--min-downloads` to adjust the
  SUSPICIOUS heuristic.
- A local, per-user on-disk response cache for `verify` (never a shared
  server-side mirror). `--no-cache` bypasses it.
- Dual-license files (`LICENSE-MIT`, `LICENSE-APACHE`), a `vulkro-feeds` crate
  README, and a Claude Code plugin manifest with an `.mcp.json` for the
  `vulkro-live` MCP server.
- `install.sh`: a `curl | sh` installer that downloads a prebuilt,
  checksum-verified `vulkro-live` binary for your platform. Distribution is
  the single CLI (no npm, PyPI, or Homebrew packages), built and deployed
  manually via `scripts/build-release.sh`.
- Open-source project files: `README`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue and pull-request templates, and
  an `.editorconfig`.

### Fixed

- `warden` no longer panics on manifest text containing certain multi-byte
  characters (the evidence-snippet search now runs on the original string).
- `warden` catches injection phrases hidden in a tool name, and Poetry
  `path`/`git` dependencies are no longer reported as MISSING.
- The MCP server answers malformed requests with a JSON-RPC `-32600` error and
  negotiates an unsupported protocol version down to a supported one.
- Large npm packuments (over 10 MiB, e.g. `typescript`) verify instead of
  erroring.
