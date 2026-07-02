//! Commodity parsing of MCP server tool manifests.
//!
//! This reads the tool metadata an MCP server advertises (the shape returned by
//! a `tools/list` call) into plain structs. It is pure metadata parsing, no
//! analysis: the `warden` tool applies its heuristics on top of these types.

use anyhow::{Context, Result};
use serde::Deserialize;

/// One tool as advertised by an MCP server.
#[derive(Debug, Clone, Deserialize)]
pub struct McpTool {
    /// The tool name the model calls.
    pub name: String,
    /// The natural-language description shown to the model.
    #[serde(default)]
    pub description: Option<String>,
    /// The JSON Schema for the tool's arguments.
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<serde_json::Value>,
    /// Optional MCP tool annotations (readOnlyHint, destructiveHint, etc.).
    #[serde(default)]
    pub annotations: Option<serde_json::Value>,
}

/// Parse a tool manifest from JSON text, accepting the common shapes:
///
/// - `{"tools": [ ... ]}` (a `tools/list` result)
/// - `{"result": {"tools": [ ... ]}}` (a full JSON-RPC response)
/// - `[ ... ]` (a bare array of tools)
/// - `{ "name": ..., ... }` (a single tool object)
pub fn parse_tools(json_text: &str) -> Result<Vec<McpTool>> {
    let value: serde_json::Value =
        serde_json::from_str(json_text).context("parsing the MCP manifest (is it valid JSON?)")?;
    tools_from_value(value)
}

fn tools_from_value(value: serde_json::Value) -> Result<Vec<McpTool>> {
    // Unwrap a JSON-RPC envelope if present (result may hold `{"tools":[...]}`
    // or a bare array of tools).
    if let Some(result) = value.get("result") {
        if result.is_array() || result.get("tools").is_some() {
            return tools_from_value(result.clone());
        }
    }
    // `{"tools": [...]}`
    if let Some(tools) = value.get("tools") {
        return from_array(tools.clone());
    }
    // A bare array of tools.
    if value.is_array() {
        return from_array(value);
    }
    // A single tool object.
    if value.get("name").is_some() {
        let tool: McpTool =
            serde_json::from_value(value).context("parsing a single MCP tool object")?;
        return Ok(vec![tool]);
    }
    anyhow::bail!(
        "could not find any tools in the manifest; expected a `tools` array, a bare array, or a single tool object"
    )
}

fn from_array(value: serde_json::Value) -> Result<Vec<McpTool>> {
    serde_json::from_value(value).context("parsing the MCP tools array")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tools_list_shape() {
        let text = r#"{"tools":[{"name":"a","description":"does a"},{"name":"b"}]}"#;
        let tools = parse_tools(text).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "a");
        assert_eq!(tools[0].description.as_deref(), Some("does a"));
    }

    #[test]
    fn parses_jsonrpc_envelope() {
        let text = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"only"}]}}"#;
        let tools = parse_tools(text).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "only");
    }

    #[test]
    fn parses_jsonrpc_envelope_with_bare_array_result() {
        let text = r#"{"jsonrpc":"2.0","id":1,"result":[{"name":"a"},{"name":"b"}]}"#;
        assert_eq!(parse_tools(text).unwrap().len(), 2);
    }

    #[test]
    fn parses_bare_array_and_single_object() {
        assert_eq!(parse_tools(r#"[{"name":"x"}]"#).unwrap().len(), 1);
        assert_eq!(parse_tools(r#"{"name":"solo"}"#).unwrap().len(), 1);
    }

    #[test]
    fn rejects_manifest_without_tools() {
        assert!(parse_tools(r#"{"mcpServers":{}}"#).is_err());
    }
}
