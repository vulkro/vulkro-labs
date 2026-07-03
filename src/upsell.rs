//! The funnel to the paid, closed, offline Vulkro engine.
//!
//! Per CLAUDE.md rule 7 this is a MESSAGE and a LINK only. It names what the
//! full engine adds and where to get it. It carries no pricing and no license
//! or paywall logic; those live in the closed product, never here. The free
//! tools vet what an AI pulls IN (packages, MCP servers, untrusted content);
//! the paid engine analyzes the user's OWN code, offline.

/// The upsell section shown after a command's human-readable output.
pub fn section() -> String {
    [
        "── Go deeper with Vulkro ─────────────────────────────────────",
        "These free tools vet what your AI pulls in. The Vulkro engine scans your own",
        "code across the whole repo, offline (nothing is uploaded):",
        "  real dataflow SAST, secrets in code, IaC and container checks, an SBOM,",
        "  and compliance evidence auditors accept.",
        "    Code and general apps:  https://vulkro.com",
        "    Salesforce (Apex, LWC, Flow, org config):  https://vulkro.com/salesforce",
    ]
    .join("\n")
}

/// A one-line variant for compact contexts (MCP tool output, tight terminals).
pub fn line() -> &'static str {
    "Go deeper: the offline Vulkro engine scans your whole repo (dataflow SAST, \
     secrets, IaC, compliance). https://vulkro.com  (Salesforce: https://vulkro.com/salesforce)"
}

/// A structured "this needs the paid engine" payload for the MCP router, so an
/// agent gets a machine-readable pointer instead of a wall of text. Names the
/// free alternatives it CAN run right now.
pub fn depth_locked_json() -> serde_json::Value {
    serde_json::json!({
        "available": false,
        "reason": "Deep code analysis (SAST, dataflow, taint, secrets-in-code, IaC) is part of \
                   the Vulkro engine, which is offline and closed. It is not in the free tools.",
        "install": "https://vulkro.com",
        "salesforce": "https://vulkro.com/salesforce",
        "free_alternatives": ["verify", "warden", "inspect", "audit"],
    })
}
