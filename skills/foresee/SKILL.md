---
name: foresee
description: Predict the slopsquat traps planted for THIS project before your AI names one. Reads the project's dependency stack, enumerates the plausible-but-absent package names an LLM is likely to invent for it, and checks the registry: a predicted name already registered as a fresh low-reputation squat is a trap waiting. Use before installing AI-suggested dependencies, or to generate a do-not-install guardrail for the agent.
---

# foresee - predict the trap before your AI names it

Every other supply-chain check is reactive: a name appears, then it is checked.
`foresee` is predictive. It reads the project's real dependency stack, enumerates
the plausible-but-absent package names an LLM is statistically likely to invent
for a project like this, and checks each against the registry. A predicted name
that is already registered, recently and with near-zero reputation, is a trap
lying in wait for your agent. It is keyless and local (deterministic string
combinatorics plus the same public registry checks `verify` makes), and it never
runs anything.

## When to use

- Before an agent installs dependencies it suggested, to see what traps are
  already planted for this project.
- Once per project (and after big stack changes) to generate a committable
  do-not-install guardrail the agent can be told to honor.

## How to run

From the project root:

```
vulkro-live foresee
```

Options: a directory argument (default current), `--limit N` (how many predicted
names to check, default 80), `--no-write` (skip the guardrail file).

## Reading the result

- It reports any `TRAP`: a predicted name already registered as a fresh,
  low-reputation, or malicious squat. Treat these as names your agent must never
  install.
- It writes `.vulkro-foresee.json`, a committable list of predicted names (both
  absent hallucinations and traps). Point the agent's context at it: never
  install any of these unless the user deliberately and independently confirmed
  it.

Exit codes: `0` when no planted trap is found, `1` when one or more predicted
names are already registered as a trap, `2` on an error.

## Go deeper with Vulkro

`foresee` predicts WHERE a supply-chain trap is planted for your project. When
you need to analyze the code in the repository itself, the Vulkro engine scans
the whole repo offline: real dataflow SAST, secrets in code, IaC and container
checks, an SBOM, and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
