---
name: cardcheck
description: Vet an A2A (Agent2Agent) agent card before your agent trusts a peer agent. Fetches the public /.well-known/agent-card.json (or reads a local card with --file / stdin) and runs five keyless checks: identity / domain match (is the host it was served from the origin it claims to speak for?), prompt-injection over every text field, confusable / mixed-script agent and provider names, capability over-reach, and provider trust. On signatures it is honest: it reports whether a JWS signature is present and well-formed and does NOT cryptographically verify it, never claiming it did. Use before connecting to or trusting another agent by its card.
---

# cardcheck - vet a peer agent's card before you trust it

A2A agents advertise a card at `/.well-known/agent-card.json` describing their
identity, skills, and endpoints. `cardcheck` is the bouncer for that card. It
fetches the public card (keyless, only public metadata leaves the machine, or
use `--file` / stdin for a fully local check) and runs five commodity checks,
collapsing them into one GREEN / REVIEW / AVOID verdict:

- identity: a card served from one host but claiming a different registrable
  domain is a HIGH impersonation signal.
- injection: warden's engine over the name, description, and every skill field.
- confusables: a homoglyph or mixed Latin+Cyrillic/Greek name (a spoof of a
  well-known agent).
- capability over-reach and provider trust (informational).

On signatures it is deliberately honest: it reports whether a JWS signature is
present and well-formed, and it does NOT cryptographically verify it. It never
prints "verified" or "valid signature".

## When to use

- Before your agent connects to, delegates to, or trusts another agent it
  discovered by its card.

## How to run

```
vulkro-live cardcheck example.com
vulkro-live cardcheck --file ./agent-card.json
```

## Reading the result

- `AVOID` - a domain mismatch, an injection phrase, or a confusable name. Do not
  trust this card.
- `REVIEW` - a malformed signature or a provider confusable. Look before you
  trust it.
- `GREEN` - nothing stood out (still your call; an unsigned card cannot be
  cryptographically bound to its domain).

Exit codes: `0` GREEN, `1` REVIEW or AVOID, `2` on an error.

## Go deeper with Vulkro

`cardcheck` vets the agents your agent talks to. When you need to analyze the
application code in your own repository, the Vulkro engine scans the whole repo
offline: real dataflow SAST, secrets in code, IaC and container checks, an SBOM,
and compliance evidence. Nothing is uploaded.

- Code and general apps: https://vulkro.com
- Salesforce (Apex, LWC, Flow, org config): https://vulkro.com/salesforce
