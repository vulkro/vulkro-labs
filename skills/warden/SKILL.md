---
name: warden
description: Scan an MCP server's tool manifest for prompt-injection, tool-poisoning, tool-shadowing, hidden unicode, sensitive-data parameters, and risky capabilities, before trusting or connecting those tools. Use when evaluating a new or third-party MCP server, or when a tool's description or schema looks suspicious.
---

# warden - the MCP / agent-tool bouncer

`warden` statically scans the tool metadata an MCP server advertises (its
`tools/list` output) and reports risky patterns before an agent trusts the
tools. It reads only metadata (names, descriptions, JSON schemas,
annotations); it never inspects or runs code, and nothing leaves your machine.

## When to use

- Before connecting or enabling a new or third-party MCP server.
- When a tool's description or input schema looks off.
- As a quick review step when auditing an agent's available tools.

## How to run

Capture the server's tool list as JSON (a `tools/list` result, a bare array
of tool objects, or a single tool object) into a file, then:

```
vulkro-live warden ./tools.json
```

Machine-readable output:

```
vulkro-live warden --json ./tools.json
```

## What it flags

- `prompt-injection` / `tool-poisoning` - instruction-injection or
  model-steering text in a description or schema.
- `hidden-unicode` - invisible or bidi characters that hide instructions.
- `tool-shadowing` - duplicate names, or names colliding with common builtins.
- `sensitive-parameter` - a parameter that asks the model to pass a secret.
- `capability` / `annotation` - powerful side effects, or self-declared
  destructive / open-world behavior.

## Reading the result

Findings are ranked most-severe first. Exit codes: `0` when nothing actionable
is found, `1` when a HIGH or MEDIUM finding is present, `2` on an error. Treat
HIGH findings (injection phrases, hidden unicode, duplicate names) as reasons
not to trust the server until a human has reviewed it. These are heuristics, so
they are signals for review, not proof of malice.
