# Changelog

All notable, user-facing changes to Vulkro Labs tools are recorded here: new
tools, new checks, and fixes. The format follows Keep a Changelog, and the
project aims to follow Semantic Versioning.

## [Unreleased]

### Added

- `vulkro-live verify --lockfile <file>` - vet a pinned dependency LOCKFILE
  (package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, poetry.lock, or a
  hashed requirements.txt; the ecosystem is inferred from the file name). It
  verifies every locked package like the manifest mode AND adds commodity
  `LOCKFILE-INTEGRITY` findings that only a pinned lockfile makes detectable: an
  `off-registry-resolved` URL that points off the official registry host (a
  repointed dependency source, HIGH) and a `missing-integrity` entry with no
  integrity hash where one is normally recorded (MEDIUM). Supports
  `--format text|json|sarif`.
- `vulkro-live provenance` - a build-provenance / attestation PRESENCE bouncer
  for npm and PyPI. It reads what the public registry advertises (npm
  `dist.attestations` / provenance, PyPI PEP 740 attestations) and reports one
  GREEN / REVIEW / AVOID verdict per package: provenance present and well-formed
  or absent is GREEN (absence is common today, only a review signal), malformed
  provenance or a source-repo mismatch is REVIEW, and a MISSING / MALICIOUS /
  LOOKALIKE package (reusing verify) is AVOID. It is deliberately honest: it
  never cryptographically verifies an attestation and never claims to.
  crates.io exposes no keyless provenance, so a crate is reported as "not
  available" rather than as a missing attestation. Supports
  `--format text|json|sarif`, and ships as a Claude Code skill.
- The built-in MCP server (`vulkro-live mcp`) now exposes the whole free bouncer
  suite, not just verify and warden: `verify_lockfile`, `provenance`, `inspect`,
  `audit`, `foresee`, `skillscan`, `memcheck`, `cardcheck`, `lock`, and `drift`
  are all callable by an agent over the single server.

## [0.2.1]

### Fixed

- warden findings now describe "the text" rather than "tool metadata", so the
  wording is correct when the same engine scans a fetched page (`warden
  --result`), an agent-card field (`cardcheck`), a memory record (`memcheck`),
  or a skill's prose (`skillscan` / `audit`), not only an MCP tool manifest.

## [0.2.0]

### Added

- Unified machine output: a shared `--format text|json|sarif` flag on every
  finding-producing command (verify, warden, inspect, audit, foresee, skillscan,
  memcheck, drift), backed by one `src/sarif` mapping layer that emits SARIF
  2.1.0 for CI code-scanning (GitHub, etc.). Rule ids use the reserved free
  namespace `vulkro-live/<command>/<slug>` so they never collide with the paid
  engine's `vulkro/...` ids. The old `--json` on verify and warden is kept as a
  deprecated alias (a stderr warning; rule 11) for one release.
- `vulkro-live trustdb` and `.vulkro/trust.toml` - clear an artifact once and
  every free tool trusts that EXACT version or content, going loud again the
  moment it mutates. `trustdb add` clears a package (name@version), an MCP tool
  manifest (`--manifest`), a skill (`--skill`, covers SKILL.md plus its
  scripts), or a memory file (`--memory`); `list` / `remove` / `clear` manage
  the store. Trust is always version- or fingerprint-pinned, never name-only, so
  a new (possibly bad) version is never auto-cleared. Fingerprints are a
  hand-rolled FNV-1a over canonical content (no crypto dep). verify / inspect /
  audit / warden / skillscan / memcheck / foresee consult the store and render a
  visible "trusted (cleared in .vulkro/trust.toml)" marker, never a silent pass
  (`src/trust`).
- `vulkro-live lock` and `vulkro-live drift` - MCP-manifest rug-pull detection.
  `lock` fingerprints the current manifest(s) into a committable, deterministic
  `.vulkro/mcp.lock`; `drift` reports a field-level diff against it, classifying
  each change by what it introduces (a readOnlyHint drop or a newly-injected
  description is HIGH; an added/removed tool or a schema change is MEDIUM; a
  benign reword is LOW). Reuses `parse_tools` and warden's engine; structural
  canonical-JSON diff, no crypto dep (`src/lock`).
- `vulkro-live cardcheck` - an A2A (Agent2Agent) agent-card bouncer. Fetches a
  public `/.well-known/agent-card.json` (agent.json fallback), or reads a local
  card with `--file` / stdin, and runs five keyless checks: identity / domain
  match, prompt-injection over every text field (warden), confusable /
  mixed-script names, capability over-reach, and provider trust. Signatures are
  reported for PRESENCE and well-formedness ONLY: this version does not
  cryptographically verify them and never claims it does (the type has no
  "verified" state; a test asserts the output never says so). No crypto
  dependency added (`src/cardcheck`).
- `audit` hardening: config-file plaintext-secret detection (server env /
  headers / args, via a hand-rolled prefix + Shannon-entropy classifier with a
  tight allowlist), dangerous-settings detection (auto-approve / alwaysAllow,
  permission-bypass modes, bypass flags, fetch-and-exec hooks), and
  `--write-baseline` / `--diff <file>` for a committable surface snapshot and a
  since-baseline delta (`src/audit/{secrets,settings,snapshot}.rs`).
- `vulkro-live inspect <spec>` - the "is this MCP server safe to add?" check.
  Resolves an MCP server spec (an npm / PyPI package, or a `npx`/`uvx` command),
  verifies the backing package with the same feeds `verify` uses, and returns a
  GREEN / REVIEW / AVOID verdict. Local scripts, git, and other unverifiable
  specs return REVIEW rather than a false pass. Malformed input exits `2`.
- `vulkro-live audit` - audits the whole agent surface at once: every configured
  MCP server (verified via `inspect`), the rules / skills / instruction files an
  agent reads (scanned with warden's engine), and network-reaching hooks. Dedups
  by canonical path and by hook command.
- `vulkro-live foresee` - the predictive slopsquat map. Reads a project's real
  dependency stack, deterministically enumerates the plausible-but-absent names
  an LLM is likely to invent for a project like this, and checks each against the
  registry. A predicted name already registered as a fresh, low-reputation squat
  is reported as a `TRAP`. Writes a committable `.vulkro-foresee.json`
  do-not-install guardrail. Keyless and local.
- `vulkro-live skillscan` - scans the executable BODY of Claude Code skills,
  slash commands, and subagents, not just their prose. Parses each frontmatter
  for dangerous declared powers (broad tool access, permission bypass) and
  static-scans every bundled script for stealer tells: download-pipe-to-shell,
  base64-decode-and-execute, reads of `~/.ssh` / `~/.aws` / `~/.claude.json` /
  `.env`, environment dumps, and outbound network egress. GREEN / REVIEW / AVOID
  per skill. It never executes anything.
- `vulkro-live memcheck` - scans an AI agent's stored long-term memory for
  poisoning (OWASP Agentic Top 10 2026, ASI06). Auto-discovers the common text
  memory stores (MEMORY.md, memory/*.md, *.jsonl logs), runs warden's hardened
  text engine over each record, and flags any memory that carries a runnable
  command or steers the agent to act. Purely offline.
- `verify` now also flags `LOOKALIKE` (a homoglyph or one-edit typosquat of a
  very popular npm / PyPI / crates package) and `VULNERABLE` (the installed
  version has a known CVE / advisory in OSV), in addition to MISSING, MALICIOUS,
  SUSPICIOUS, and OK. The verdict ladder is MISSING > MALICIOUS > LOOKALIKE >
  VULNERABLE > SUSPICIOUS > OK.
- `warden --result <file>` (and `-` for stdin) scans a tool result the agent
  received, not just a tool manifest, so injection delivered in returned content
  is caught. New checks across both modes: ANSI-escape sequences, exfiltration
  sinks (punycode, markdown-image URLs, long encoded runs), and manifest-level
  cross-tool triggers ("always call X first").
- The built-in MCP server advertises the agent-surface tools and delegates deep
  repo scans to the Vulkro engine when it is on PATH.

### Fixed

- npm feed: a package whose registry `time` object carries an `unpublished` key
  (an object, not a string) no longer fails to parse. This previously broke
  `verify` for any package with unpublished versions.

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
