---
name: drift
description: Catch an MCP rug pull - a tool manifest that was trusted once and then silently swapped, so the tool the user approved is not the tool that now runs. `vulkro-live lock` fingerprints the current MCP tool manifest into a committable .vulkro/mcp.lock; `vulkro-live drift` re-reads the current manifest and reports a field-level diff against the lock, classifying each change by what it introduces (a tool that dropped readOnlyHint or a description that gained an injection phrase is HIGH; an added or removed tool is MEDIUM; a benign reword is LOW). Keyless and offline. Use to detect that an MCP server changed its advertised tools since you approved them.
---

# lock and drift - detect an MCP rug pull

Every other check vets a manifest at a point in time. `lock` and `drift` catch
what happens next: a server that was trusted once and then silently changes its
advertised tools. `lock` records the current manifest into a committable
`.vulkro/mcp.lock`. `drift` compares the current manifest against that lock and
reports exactly what changed, scored by what the change introduces (using the
same warden engine over any changed text). Both are keyless and fully offline.

`drift` diffs a manifest already on disk. It does not launch the server to poll
its tools, so re-capture the current manifest (the same way you first saved it)
before running `drift`.

## When to use

- After approving an MCP server, run `lock` once and commit the lock.
- Periodically (or in CI) re-capture the manifest and run `drift` to catch a
  tool that was swapped after approval.

## How to run

```
vulkro-live lock ./tools.json
vulkro-live drift ./tools.json
```

`drift` supports `--format text|json|sarif` for CI.

## Reading the result

- `HIGH` - a tool dropped `readOnlyHint` or gained `destructiveHint`, or a
  description now contains an injection / hidden-text / exfil signal.
- `MEDIUM` - a tool was added or removed, or an input schema changed.
- `LOW` - a benign reword (shown for review, not treated as malice).

Exit codes: `drift` returns `0` when nothing changed, `1` when drift is found,
`2` on an error (including no lock yet: run `lock` first).

## Go deeper with Vulkro

`drift` guards the tools your agent calls. When you need to analyze the
application code in your repository, the Vulkro engine scans the whole repo
offline: real dataflow SAST, secrets in code, IaC and container checks, an SBOM,
and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
