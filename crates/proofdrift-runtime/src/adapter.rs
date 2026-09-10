use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterBoundary {
    Broker,
    ProcessWrapper,
    HookConditional,
    ObserveOnly,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCapabilities {
    pub can_observe: bool,
    pub can_block: bool,
    pub can_modify: bool,
    pub can_capture_result: bool,
    pub boundary: AdapterBoundary,
    pub verified_on: String,
    pub source_url: String,
    pub coverage_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessAdapter {
    pub id: String,
    pub display_name: String,
    pub capabilities: AdapterCapabilities,
}

/// Conservative capability matrix for public/documented adapter surfaces verified 2026-09-10.
///
/// `HookConditional` is intentionally not equivalent to ProofDrift L1 coverage for an entire
/// session: some harness modes or tool paths can bypass/disable hooks, and fail-open
/// behavior may exist unless configured otherwise.
pub fn adapter_capability_matrix() -> Vec<HarnessAdapter> {
    vec![
        HarnessAdapter {
            id: "claude-code-hooks".into(),
            display_name: "Claude Code hooks".into(),
            capabilities: AdapterCapabilities {
                can_observe: true,
                can_block: true,
                can_modify: true,
                can_capture_result: true,
                boundary: AdapterBoundary::HookConditional,
                verified_on: "2026-09-10".into(),
                source_url: "https://claude.com/blog/how-to-configure-hooks".into(),
                coverage_note: "PreToolUse can block/modify matched calls and PostToolUse can observe results; hook coverage is not claimed as OS isolation.".into(),
            },
        },
        HarnessAdapter {
            id: "codex-hooks".into(),
            display_name: "Codex hooks".into(),
            capabilities: AdapterCapabilities {
                can_observe: true,
                can_block: true,
                can_modify: true,
                can_capture_result: true,
                boundary: AdapterBoundary::HookConditional,
                verified_on: "2026-09-10".into(),
                source_url: "https://developers.openai.com/codex/hooks".into(),
                coverage_note: "PreToolUse/PostToolUse are harness hooks; supported tool coverage must be checked against the installed Codex version and managed configuration.".into(),
            },
        },
        HarnessAdapter {
            id: "gemini-cli-hooks".into(),
            display_name: "Gemini CLI hooks".into(),
            capabilities: AdapterCapabilities {
                can_observe: true,
                can_block: true,
                can_modify: true,
                can_capture_result: true,
                boundary: AdapterBoundary::HookConditional,
                verified_on: "2026-09-10".into(),
                source_url: "https://geminicli.com/docs/hooks/reference/".into(),
                coverage_note: "BeforeTool can block/rewrite matched tool calls; AfterTool observes results. This is a hook boundary, not process/network isolation.".into(),
            },
        },
        HarnessAdapter {
            id: "cursor-hooks".into(),
            display_name: "Cursor hooks".into(),
            capabilities: AdapterCapabilities {
                can_observe: true,
                can_block: true,
                can_modify: true,
                can_capture_result: true,
                boundary: AdapterBoundary::HookConditional,
                verified_on: "2026-09-10".into(),
                source_url: "https://cursor.com/docs/hooks".into(),
                coverage_note: "beforeShellExecution/beforeMCPExecution and generic hooks can control calls; security use should opt into failClosed where supported. Early cloud read-only turns can omit hooks.".into(),
            },
        },
        HarnessAdapter {
            id: "opencode-plugin-hooks".into(),
            display_name: "OpenCode plugin hooks".into(),
            capabilities: AdapterCapabilities {
                can_observe: true,
                can_block: true,
                can_modify: true,
                can_capture_result: true,
                boundary: AdapterBoundary::HookConditional,
                verified_on: "2026-09-10".into(),
                source_url: "https://opencode.ai/v2/docs/build/plugins/".into(),
                coverage_note: "execute.before can inspect/replace input or fail the call and execute.after can inspect results; plugin scope/version still bounds coverage.".into(),
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_harness_hook_is_mislabeled_as_os_isolation() {
        for adapter in adapter_capability_matrix() {
            assert_ne!(adapter.capabilities.boundary, AdapterBoundary::Broker);
            assert!(
                adapter.capabilities.coverage_note.contains("hook")
                    || adapter.id.contains("opencode")
            );
        }
    }
}
