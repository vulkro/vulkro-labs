---
name: trustdb
description: Clear a reviewed artifact once so every vulkro-live tool stops flagging it, and re-flags it the moment it changes. `vulkro-live trustdb add` records a package (name@version), an MCP tool manifest (--manifest), a skill (--skill, covers SKILL.md plus its scripts), or a memory file (--memory) into a committable .vulkro/trust.toml. Trust is always pinned to the exact version or content fingerprint, never name-only, so a new (possibly bad) version is never auto-trusted. verify / inspect / audit / warden / skillscan / memcheck consult the store and show a visible "trusted" marker, not a silent pass. Use to silence a reviewed finding in a durable, PR-reviewable way instead of ignoring it.
---

# trustdb - clear a reviewed artifact once, loud on any change

When a finding is a known, reviewed false alarm, the wrong fix is to ignore it
(you lose the signal forever). `trustdb` is the right fix: clear that EXACT
artifact once into a committable `.vulkro/trust.toml`, and every tool trusts it
until it changes. The repo is the record and the PR is the approval: there is no
server and no key.

Trust is always pinned to a version or a content fingerprint, never a bare name,
so a new version or a single changed byte does not match the clear and the tool
re-runs its full analysis. A cleared artifact is shown with a visible
"trusted (cleared in .vulkro/trust.toml)" marker so the clear is auditable in the
diff, never a silent pass.

## When to use

- After you have reviewed a finding and confirmed the exact version / manifest /
  skill / memory is safe, and you want the tools to stop flagging that exact
  thing until it changes.

## How to run

```
vulkro-live trustdb add express@4.18.2
vulkro-live trustdb add --manifest ./tools.json
vulkro-live trustdb add --skill ./.claude/skills/my-skill
vulkro-live trustdb add --memory ./MEMORY.md
vulkro-live trustdb list
vulkro-live trustdb remove <key>
```

Commit `.vulkro/trust.toml` so the whole team (and CI) inherits the cleared set.

Exit codes: `0` on success, `2` on a bad argument or IO error.

## Go deeper with Vulkro

`trustdb` manages what the free tools trust. When you need to analyze the
application code in your repository, the Vulkro engine scans the whole repo
offline: real dataflow SAST, secrets in code, IaC and container checks, an SBOM,
and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
