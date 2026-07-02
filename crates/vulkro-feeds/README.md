# vulkro-feeds

Keyless, commodity clients for public package and security feeds, used by
[Vulkro](https://vulkro.com)'s free developer tools.

`vulkro-feeds` provides small, self-contained clients that query only public
metadata (package names, versions, tool manifests) live from the end user's
own machine. There is no vendor backend, no API key, and no account. It
defines its own types and depends on no closed code.

## What it covers

- Package existence, metadata, and reputation for **npm**, **PyPI**, and
  **crates.io**, behind an ecosystem-dispatching `registry` front door.
- Malicious-package lookups via **OSV.dev** (OpenSSF `MAL-` records).
- Parsing of **MCP** server tool manifests (`tools/list` output).

The HTTP transport is behind the `HttpClient` trait so callers and tests can
inject their own. The real client (`UreqClient`) is behind the default `net`
feature; an in-memory mock (`MockHttp`) is behind the `testing` feature.

## Attribution

Data sources are queried live and never cached centrally or redistributed.
See [ATTRIBUTION.md](../../ATTRIBUTION.md) in the repository root for the
per-source credits (npm, PyPI, crates.io, OSV.dev, and OpenSSF
malicious-packages).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
