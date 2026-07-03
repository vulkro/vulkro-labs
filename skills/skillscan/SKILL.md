---
name: skillscan
description: Scan the executable BODY of Claude Code skills, slash commands, and subagents, not just their prose. A skill's SKILL.md description can look clean while the scripts/ it bundles quietly steal ~/.ssh, ~/.aws, or ~/.claude.json and pipe a remote stage-2 into a shell. skillscan opens those scripts, parses each frontmatter for dangerous declared powers (broad tool access, permission bypass), static-scans every bundled script for stealer tells, and reports GREEN / REVIEW / AVOID per skill. Keyless, local, and it never runs anything. Use before installing or trusting a third-party skill, command, or subagent.
---

# skillscan - scan what a skill actually runs, not what it says

An agent skill is a description plus, often, scripts it runs on your machine. The
description is the part a human reads and the part an attacker keeps clean. The
`scripts/` directory is where the stealer lives. `skillscan` is the only check
here that opens those scripts. For every Claude Code skill (`.claude/skills/*`),
slash command (`.claude/commands/*.md`), and subagent (`.claude/agents/*.md`),
project and home, it:

- parses the frontmatter for dangerous declared powers: broad tool access
  (`allowed-tools: Bash` or `*`), a permission bypass / auto-approve
- static-scans every bundled script for stealer tells: download-pipe-to-shell
  (`curl | sh`), base64-decode-and-execute, reads of `~/.ssh` / `~/.aws` /
  `~/.claude.json` / `.env`, environment dumps, and outbound network egress
- runs the same hardened text engine `warden` uses over the prose

It is keyless and fully local, and it never executes anything.

## When to use

- Before installing or enabling a third-party skill, slash command, or subagent.
- Periodically over your whole `.claude/` surface, to catch a skill whose script
  was quietly swapped after you first trusted it.

## How to run

From the project root:

```
vulkro-live skillscan
```

An optional directory argument scans a different project (the home directory's
skills, commands, and agents are always included).

## Reading the result

- `AVOID` - a HIGH finding: a bundled script reads secrets, pipes a download into
  a shell, executes obfuscated content, or the frontmatter declares a permission
  bypass. Do not enable it.
- `REVIEW` - a MEDIUM finding: broad tool access, an environment dump, or an
  outbound request. Read the script before trusting it.
- `GREEN` - nothing stood out. Still your call, but no known tell fired.

Exit codes: `0` when nothing is flagged, `1` when a skill is REVIEW or AVOID, `2`
on an error.

## Go deeper with Vulkro

`skillscan` inspects the skills and commands that drive your agent. When you need
to analyze the application code in the repository itself, the Vulkro engine scans
the whole repo offline: real dataflow SAST, secrets in code, IaC and container
checks, an SBOM, and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
