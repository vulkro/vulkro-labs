//! `vulkro-feeds`: keyless, commodity clients for public package and security
//! feeds.
//!
//! This crate is COMMODITY logic only: registry existence checks, package
//! metadata, malicious-package lookups, and MCP tool-manifest parsing that any
//! competitor could reimplement from public information. It defines its own
//! types, never imports closed engine code, and holds no vendor backend. Every
//! request originates from the end user's own machine and carries only public
//! metadata (package names, versions, tool manifests), never source code.
//!
//! The HTTP transport is abstracted behind [`HttpClient`] so callers (and
//! tests) can inject their own. The real transport ([`UreqClient`]) lives
//! behind the default `net` feature; an in-memory mock ([`MockHttp`]) lives
//! behind the `testing` feature.

pub mod crates_io;
pub mod ecosystem;
pub mod http;
pub mod mcp_manifest;
pub mod npm;
pub mod osv;
pub mod pypi;
pub mod registry;

pub use crates_io::CratesIo;
pub use ecosystem::{
    AttestationPresence, Ecosystem, PackageMetadata, ProvenanceInfo, Reputation,
};
pub use http::{CachingHttpClient, HttpClient, HttpResponse};
pub use mcp_manifest::{parse_tools, McpTool};
pub use npm::Npm;
pub use osv::{Advisory, AdvisoryReport, MaliciousReport, Osv};
pub use pypi::PyPi;

#[cfg(feature = "net")]
pub use http::UreqClient;

#[cfg(any(test, feature = "testing"))]
pub use http::MockHttp;
