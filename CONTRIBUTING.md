# Contributing to Vulkro Labs

Thanks for your interest in improving Vulkro's free developer security tools.
Issues, ideas, and pull requests are all welcome.

## What belongs here

This repository holds the free, keyless tools (`verify`, `warden`, the
`vulkro-live` MCP server) and the shared `vulkro-feeds` crate: commodity
clients for public package and security feeds.

Good contributions: new checks that work from public metadata, support for a
new public feed, bug fixes, tests, and docs.

Out of scope: anything that requires a hosted backend, an API key, or a user
account. These tools are keyless by design and query only public metadata from
the user's own machine. The paid Vulkro detection engine is a separate, closed
product and does not live here.

## Development

You need a recent stable Rust toolchain.

```
cargo build --workspace
cargo test --workspace                 # unit tests, no network
cargo test --workspace -- --ignored    # the few live-network tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

There is no CI: please run build, test, clippy, and fmt locally before
opening a pull request, and keep the tree warning-free and formatted.

## Guidelines

- No `unwrap()`, `expect()`, or `panic!` outside `#[cfg(test)]`. Return
  `anyhow::Result` and propagate with `?` and `.context("...")`.
- Slice strings on char boundaries (UTF-8 safe): use `is_char_boundary`,
  `char_indices`, or `str::get`.
- Prefer borrowed types (`&str`, `&[T]`) in function signatures.
- Add a test with every bug fix and every feature.
- Keep the tools keyless and local: only public metadata (package names,
  versions, tool manifests) may leave the machine, never source code.
- Write actionable error messages (what went wrong, and what to do next).

## Pull requests

- Keep commits small and focused.
- Describe what changed and why; link a related issue if there is one.
- Update `CHANGELOG.md` for user-facing changes.

## License of contributions

By contributing, you agree that your contributions are dual-licensed under the
MIT license and the Apache License 2.0, the same terms as this project.
