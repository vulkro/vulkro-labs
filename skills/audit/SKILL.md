---
name: audit
description: Audit the whole agent surface in one command: inventory every MCP server and verify its backing package, scan every rules / skill / instructions file for prompt-injection, and flag hooks that shell out to the network. Use to review the security of the current machine's and project's agent configuration.
---

# audit - audit your whole agent surface

`audit` inventories and checks everything that steers an AI agent on this
machine and in this project. It walks the well-known config locations for
Claude Code, Claude Desktop, Cursor, Windsurf, and Cline (project and home)
and:

- inventories every MCP server and verifies its backing package (like
  `inspect`),
- scans every rules / skill / instructions file for prompt-injection and
  hidden unicode (like `warden`),
- flags hooks whose command shells out to the network.

It reads only local config and public package metadata. It never launches a
server and never runs a hook. Keyless and local.

## When to use

- To review the security of an agent setup (a new machine, a cloned repo, or a
  periodic check).
- After adding MCP servers, rules, skills, or hooks.
- When a user asks "is my agent configuration safe?"

## How to run

Zero arguments; run it from the project root:

```
vulkro-live audit
```

## Reading the result

It lists each MCP server with a GREEN / REVIEW / AVOID verdict (most severe
first), each instruction file with any findings, and any network hooks. Exit
codes: `0` when nothing is flagged, `1` when a server is REVIEW/AVOID, an
instruction file has an actionable finding, or a hook reaches the network, `2`
on an error. Surface AVOID servers, HIGH instruction findings, and network
hooks to the user.

## Go deeper with Vulkro

`audit` vets the agent configuration around your code. When you need to analyze
the code in the repository itself, the Vulkro engine scans the whole repo
offline: real dataflow SAST, secrets in code, IaC and container checks, an
SBOM, and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
