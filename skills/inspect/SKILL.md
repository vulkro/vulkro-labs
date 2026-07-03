---
name: inspect
description: Is this MCP server safe to add? Resolve an MCP server's backing package, verify it, and (optionally) scan its tool manifest, returning one GREEN / REVIEW / AVOID verdict. Use before adding, installing, or connecting a new or third-party MCP server.
---

# inspect - is this MCP server safe to add?

`inspect` answers the highest-intent question in agent security: you found an
MCP server and are about to add it, is it safe? It resolves the backing
registry package (npm, PyPI, or crates), runs `verify` over it, and, when you
provide the server's tool manifest, runs `warden` over the advertised tools.
It collapses everything into one verdict. It is keyless and local, and it does
NOT launch the server (it never runs untrusted code).

## When to use

- Before adding or connecting a new or third-party MCP server.
- When a user pastes an MCP server install command or config entry.
- Any time an agent proposes installing an MCP server.

## How to run

By package name or by the install command (quote a command with spaces):

```
vulkro-live inspect @modelcontextprotocol/server-filesystem
vulkro-live inspect 'npx -y @scope/some-server'
vulkro-live inspect 'uvx mcp-server-git'
```

Include the server's advertised tool manifest to also scan its tools:

```
vulkro-live inspect '@scope/some-server' --manifest ./tools.json
```

## Reading the result

- `GREEN` - real, established package and a clean manifest. Safe to add.
- `REVIEW` - new / low-reputation package, a MEDIUM manifest finding, or the
  package could not be resolved. Pause and confirm with the user.
- `AVOID` - the package is MISSING or MALICIOUS, or the manifest has a HIGH
  finding (prompt-injection, hidden unicode, tool-shadowing). Do not add it.

Exit codes: `0` for GREEN, `1` for REVIEW or AVOID, `2` on an error. On AVOID,
do not add the server; surface why to the user.

## Go deeper with Vulkro

`inspect` vets the MCP servers your AI connects to. When you need to analyze
the code in the repository itself, the Vulkro engine scans the whole repo
offline: real dataflow SAST, secrets in code, IaC and container checks, an
SBOM, and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
