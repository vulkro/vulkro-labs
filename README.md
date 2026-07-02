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
  "slopsquatted"), is not known-malicious, and is not suspiciously new or
  low-reputation, before it lands in your project. Covers **npm, PyPI, and
  crates.io**.
- **warden** - the MCP / agent-tool bouncer. Before your agent trusts a
  third-party MCP server, `warden` scans its tool metadata for
  prompt-injection, tool-poisoning, tool-shadowing, hidden unicode,
  sensitive-data parameters, and risky capabilities.

Both are subcommands of one binary, and both are exposed to AI agents by a
single built-in MCP server (`vulkro-live mcp`).

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
vulkro-live verify --json express some-fake-pkg
```

Scan an MCP server's tool manifest (a `tools/list` result saved as JSON):

```
vulkro-live warden ./tools.json
```

Run the MCP server over stdio so an agent can call both tools:

```
vulkro-live mcp
```

### Verdicts and exit codes

`verify` reports one verdict per package:

| Verdict | Meaning |
| --- | --- |
| `MISSING` | Not in the registry: a likely AI hallucination or slopsquat. |
| `MALICIOUS` | Flagged by OSV (an OpenSSF malicious-packages record). |
| `SUSPICIOUS` | Exists, but very new or with very few downloads. |
| `OK` | Real, not flagged, reasonable reputation. |

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
