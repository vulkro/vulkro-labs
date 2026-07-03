# Vulkro Labs

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Free, open-source developer security tools from [Vulkro](https://vulkro.com).
Catch supply-chain problems while you build, before you deploy.

> Our free tools are open source. The Vulkro detection engine is a separate,
> closed product. Only the tools in this repository are open.

`vulkro-live` is a single, keyless command-line binary. It runs entirely on
your machine, needs no account and no API key, and sends only public metadata
(package names, versions, tool manifests) to public services. Your source code
never leaves your machine.

## Tools

- **verify** - the AI package bouncer. The moment your AI agent suggests or
  installs a dependency, `verify` confirms it exists (not hallucinated or
  "slopsquatted"), is not known-malicious, is not a look-alike typosquat of a
  popular package, has no known CVE in the installed version, and is not
  suspiciously new or low-reputation, before it lands in your project. Covers
  **npm, PyPI, and crates.io**.
- **foresee** - the predictive slopsquat map. Reads your project's real
  dependency stack, enumerates the plausible-but-absent names an LLM is likely
  to invent for a project like this, and checks the registry: a predicted name
  already registered as a fresh, low-reputation squat is a trap lying in wait.
  Writes a committable do-not-install guardrail.
- **warden** - the MCP / agent-tool bouncer. Before your agent trusts a
  third-party MCP server, `warden` scans its tool metadata (or a returned tool
  result) for prompt-injection, tool-poisoning, tool-shadowing, cross-tool
  triggers, hidden unicode, ANSI-escape tricks, exfiltration sinks,
  sensitive-data parameters, and risky capabilities.
- **inspect** - the "is this MCP server safe to add?" check. Resolves an MCP
  server spec (an npm / PyPI package, a `npx`/`uvx` command), verifies the
  backing package, and gives a GREEN / REVIEW / AVOID verdict before you add it.
- **audit** - audits your whole agent surface at once: every configured MCP
  server, plus the rules, skills, and instruction files an agent reads, plus
  network-reaching hooks.
- **skillscan** - scans the executable BODY of your skills, slash commands, and
  subagents, not just their prose: it opens the scripts a skill bundles and
  flags stealer tells the description hides.
- **memcheck** - scans an AI agent's stored long-term memory for poisoning: an
  injected "fact" that carries a runnable command or steers every future
  session (OWASP Agentic Top 10 2026, ASI06).
- **trustdb** - clear an artifact once (a package version, an MCP manifest, a
  skill, a memory) into a committable `.vulkro/trust.toml`, and every tool trusts
  that exact version or content, going loud again the moment it mutates.
- **lock** / **drift** - catch an MCP rug pull: `lock` fingerprints the current
  tool manifest into a committable `.vulkro/mcp.lock`, and `drift` reports a
  field-level diff (a tool that dropped readOnlyHint, a description that gained
  an injection phrase, an added or removed tool).
- **cardcheck** - vet an A2A (Agent2Agent) agent card before your agent trusts a
  peer: identity / domain match, injection over every text field, confusable
  names, and an honest signature-presence report (it does not cryptographically
  verify signatures and never claims to).

All are subcommands of one binary, and the core ones are exposed to AI agents by
a single built-in MCP server (`vulkro-live mcp`). Every finding-producing command
supports `--format text|json|sarif`; the SARIF output is ready for CI
code-scanning (GitHub, etc.).

## Install

One command installs the CLI. No package manager, account, or API key:

```
curl -fsSL https://dist.vulkro.com/install-live.sh | bash
```

It downloads a prebuilt binary for your platform, verifies its SHA-256
checksum, and installs it (to `/usr/local/bin` if writable, otherwise
`~/.local/bin`; override with `VULKRO_LIVE_BIN_DIR`). This is the same CDN and
installer scheme the `vulkro` and `vulkro-sf` binaries use. See
[install.sh](install.sh) for all options.

Or build from source with a recent stable Rust toolchain:

```
cargo build --release   # produces ./target/release/vulkro-live
```

## Usage

Verify packages. The default ecosystem is npm; use `--ecosystem pypi|crates`,
or `--manifest` to read a `package.json`, `requirements.txt`, `pyproject.toml`,
or `Cargo.toml` (the ecosystem is inferred from the file name):

```
vulkro-live verify express left-pad@1.3.0
vulkro-live verify --ecosystem pypi requests flask
vulkro-live verify --manifest ./Cargo.toml
vulkro-live verify --format json express some-fake-pkg
```

Map the slopsquat traps already planted for your project, and write a
do-not-install guardrail:

```
vulkro-live foresee
```

Scan an MCP server's tool manifest (a `tools/list` result saved as JSON), or a
tool result the agent got back (`--result`, or `-` for stdin):

```
vulkro-live warden ./tools.json
vulkro-live warden --result ./tool-output.txt
```

Decide whether an MCP server is safe to add before you add it:

```
vulkro-live inspect "npx -y @acme/mcp-server"
```

Audit your whole agent surface (MCP servers, rules, skills, hooks) at once:

```
vulkro-live audit
```

Scan the scripts your skills, commands, and subagents actually run, and the
memory your agent has stored:

```
vulkro-live skillscan
vulkro-live memcheck
```

Clear an artifact once so every tool trusts that exact version or content (and
re-flags it the moment it changes):

```
vulkro-live trustdb add express@4.18.2
vulkro-live trustdb add --manifest ./tools.json
vulkro-live trustdb list
```

Catch an MCP rug pull: record the current tool manifest, then detect drift after
you re-capture it:

```
vulkro-live lock ./tools.json
vulkro-live drift ./tools.json
```

Vet an A2A agent card before trusting a peer agent (or `--file` for a local
card):

```
vulkro-live cardcheck example.com
vulkro-live cardcheck --file ./agent-card.json
```

Emit machine output for CI (SARIF is ready for GitHub code-scanning):

```
vulkro-live verify --manifest package.json --format sarif
vulkro-live audit --format json
vulkro-live audit --write-baseline .vulkro/audit-baseline.json
vulkro-live audit --diff .vulkro/audit-baseline.json
```

Run the MCP server over stdio so an agent can call these tools:

```
vulkro-live mcp
```

### Verdicts and exit codes

`verify` reports one verdict per package:

| Verdict | Meaning |
| --- | --- |
| `MISSING` | Not in the registry: a likely AI hallucination or slopsquat. |
| `MALICIOUS` | Flagged by OSV (an OpenSSF malicious-packages record). |
| `LOOKALIKE` | A homoglyph or one-edit typo of a very popular package (a likely typosquat). |
| `VULNERABLE` | The installed version has a known CVE / advisory (from OSV). |
| `SUSPICIOUS` | Exists, but very new or with very few downloads. |
| `OK` | Real, not flagged, no known advisory, reasonable reputation. |

`warden` reports findings ranked by severity (HIGH, MEDIUM, LOW, INFO).

Every command exits `0` when clean, `1` when something is flagged, and `2` on
an error. Run `vulkro-live <command> --help` for the full options and the
data-source attributions.

## How it works

- **Keyless and local.** No account, no API key, no backend. Only package
  names and tool manifests leave your machine; your source code never does.
- **Public feeds only.** `verify` reads the npm registry (registry.npmjs.org)
  and download counts (api.npmjs.org), the PyPI JSON API (pypi.org), the
  crates.io index and API (crates.io), and OSV.dev (osv.dev) for
  malicious-package data. `warden` runs static heuristics on tool metadata and
  makes no network calls.
- **Query live, cache locally.** Responses are cached under your own cache
  directory (never a shared server-side mirror); `verify --no-cache` bypasses
  it.

See [ATTRIBUTION.md](ATTRIBUTION.md) for per-source credits.

## Use it with an AI agent

`vulkro-live mcp` is a Model Context Protocol server that exposes `verify` and
`warden` as tools, so an agent can vet a package or an MCP server inline. Point
your MCP client at it with the bundled config:

```json
{
  "mcpServers": {
    "vulkro-live": { "command": "vulkro-live", "args": ["mcp"] }
  }
}
```

Claude Code skills for both tools live under [skills/](skills/), and a plugin
manifest is in [.claude-plugin/](.claude-plugin/).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
the development loop and guidelines, and note that these tools are keyless by
design: they query only public metadata and never require an account or API
key. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution you
submit for inclusion is dual-licensed as above, with no additional terms.
