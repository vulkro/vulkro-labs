# Security Policy

These are security tools, so we take problems in them seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue.

- Email: security@vulkro.com
- Or use GitHub's private vulnerability reporting ("Report a vulnerability"
  under the Security tab).

Please include what you found, how to reproduce it, and the impact you expect.
We will acknowledge your report, keep you updated, and credit you if you would
like. Give us a reasonable window to ship a fix before public disclosure.

## Scope

In scope: defects in the tools in this repository (`verify`, `warden`, the
`vulkro-live` MCP server, and the `vulkro-feeds` crate) that could mislead a
user (for example, reporting a malicious package as OK), leak data off the
machine, or allow code execution.

Out of scope: the closed Vulkro detection engine, which is a separate product
and not in this repository; and issues in the third-party feeds themselves
(npm, PyPI, crates.io, OSV.dev).

## Supported versions

The project is in early development. Security fixes land on the `main` branch.
