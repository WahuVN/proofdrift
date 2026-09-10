//! Passive, bounded discovery of coding-agent harness components.
//!
//! Security invariant: discovery never executes configured commands or starts MCP servers.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path};
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "0.1.0";
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES: usize = 20_000;
pub const DEFAULT_MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConfidence {
    ActiveRuntime,
    ProjectLocalOptional,
    UserScope,
    TemplateExample,
    DocsExample,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Harness {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    OpenCode,
    CrossAgent,
    MicrosoftApm,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    Instruction,
    Settings,
    Skill,
    Agent,
    Command,
    HookConfig,
    McpConfig,
    McpServer,
    Rule,
    PluginConfig,
    Manifest,
    Lockfile,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRef {
    pub kind: String,
    pub location: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredArtifact {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_type: String,
    pub name: String,
    pub harness: Harness,
    pub component_type: ComponentType,
    pub runtime_confidence: RuntimeConfidence,
    pub local_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_revision: Option<String>,
    pub content_digest: String,
    pub provenance_status: String,
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    #[serde(default)]
    pub inferred_capabilities: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DiscoveryStats {
    pub entries_visited: usize,
    pub files_hashed: usize,
    pub files_skipped_too_large: usize,
    pub symlinks_skipped: usize,
    pub parse_warnings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub schema_version: String,
    pub root: String,
    pub artifacts: Vec<DiscoveredArtifact>,
    pub diagnostics: Vec<String>,
    pub stats: DiscoveryStats,
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    pub max_file_bytes: u64,
    pub max_entries: usize,
    pub include_user_scope: bool,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            include_user_scope: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("discovery root does not exist: {0}")]
    MissingRoot(String),
    #[error("discovery root is not a directory: {0}")]
    NotDirectory(String),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy)]
struct Surface {
    harness: Harness,
    component_type: ComponentType,
    confidence: RuntimeConfidence,
}

pub fn discover_project(root: impl AsRef<Path>) -> Result<DiscoveryResult, DiscoverError> {
    discover_project_with_options(root, &DiscoverOptions::default())
}

pub fn discover_project_with_options(
    root: impl AsRef<Path>,
    options: &DiscoverOptions,
) -> Result<DiscoveryResult, DiscoverError> {
    let root = root.as_ref();
    if !root.exists() {
        return Err(DiscoverError::MissingRoot(root.display().to_string()));
    }
    if !root.is_dir() {
        return Err(DiscoverError::NotDirectory(root.display().to_string()));
    }

    let root_abs = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut stats = DiscoveryStats::default();
    let mut diagnostics = Vec::new();
    let mut artifacts = Vec::new();
    let mut visited = BTreeSet::new();

    let mut directories = VecDeque::from([(root.to_path_buf(), 0usize)]);
    'walk: while let Some((directory, depth)) = directories.pop_front() {
        let mut entries = match fs::read_dir(&directory) {
            Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
            Err(err) => {
                diagnostics.push(format!(
                    "cannot read directory {}: {err}",
                    directory.display()
                ));
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase());

        for entry in entries {
            if stats.entries_visited >= options.max_entries {
                diagnostics.push(format!(
                    "entry limit {} reached; discovery is partial",
                    options.max_entries
                ));
                break 'walk;
            }
            stats.entries_visited += 1;

            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    diagnostics.push(format!(
                        "cannot inspect file type {}: {err}",
                        entry.path().display()
                    ));
                    continue;
                }
            };
            if is_link_like(&entry.path(), &file_type) {
                stats.symlinks_skipped += 1;
                continue;
            }
            if file_type.is_dir() {
                if depth < DEFAULT_MAX_DEPTH && should_descend_dir(&entry.path()) {
                    directories.push_back((entry.path(), depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            let path = entry.path();
            let rel = match path.strip_prefix(root) {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            let Some(surface) = classify_surface(rel) else {
                continue;
            };

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(err) => {
                    diagnostics.push(format!("metadata failed for {}: {err}", rel.display()));
                    continue;
                }
            };
            if metadata.len() > options.max_file_bytes {
                stats.files_skipped_too_large += 1;
                diagnostics.push(format!(
                    "skipped oversized candidate {} ({} bytes)",
                    rel.display(),
                    metadata.len()
                ));
                continue;
            }

            let confidence = apply_example_confidence(rel, surface.confidence);
            if confidence == RuntimeConfidence::UserScope && !options.include_user_scope {
                continue;
            }

            let rel_norm = normalize_rel(rel);
            if !visited.insert(rel_norm.clone()) {
                continue;
            }
            let bytes = match read_bounded(&path, options.max_file_bytes) {
                Ok(bytes) => bytes,
                Err(source) => {
                    diagnostics.push(format!("cannot read {}: {source}", path.display()));
                    continue;
                }
            };
            stats.files_hashed += 1;
            let digest = sha256_hex(&bytes);
            let content = String::from_utf8_lossy(&bytes);
            let artifact =
                artifact_from_file(&root_abs, rel, surface, confidence, digest, &content);
            artifacts.push(artifact.clone());

            if is_claude_settings_component_source(surface, rel) {
                match discover_claude_settings_components(rel, &content, confidence, &artifact) {
                    Ok(mut components) => artifacts.append(&mut components),
                    Err(message) => {
                        stats.parse_warnings += 1;
                        diagnostics.push(format!("{}: {message}", rel.display()));
                    }
                }
            }

            if surface_can_contain_mcp(surface, rel) {
                match discover_mcp_servers(rel, &content, surface.harness, confidence, &artifact) {
                    Ok(mut servers) => artifacts.append(&mut servers),
                    Err(message) => {
                        stats.parse_warnings += 1;
                        diagnostics.push(format!("{}: {message}", rel.display()));
                    }
                }
            }
        }
    }

    artifacts.sort_by(|a, b| {
        (&a.local_path, &a.artifact_type, &a.name, &a.artifact_id).cmp(&(
            &b.local_path,
            &b.artifact_type,
            &b.name,
            &b.artifact_id,
        ))
    });
    artifacts.dedup_by(|a, b| a.artifact_id == b.artifact_id);
    diagnostics.sort();
    diagnostics.dedup();

    Ok(DiscoveryResult {
        schema_version: SCHEMA_VERSION.to_string(),
        root: root_abs.to_string_lossy().replace('\\', "/"),
        artifacts,
        diagnostics,
        stats,
    })
}

fn is_link_like(path: &Path, file_type: &fs::FileType) -> bool {
    if file_type.is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        fs::symlink_metadata(path)
            .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            .unwrap_or(true)
    }

    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

fn should_descend_dir(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    !matches!(
        name.as_str(),
        ".git"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | ".next"
            | "coverage"
    )
}

fn classify_surface(rel: &Path) -> Option<Surface> {
    let lower = normalize_rel(rel).to_ascii_lowercase();
    let file = rel.file_name()?.to_string_lossy().to_ascii_lowercase();

    let exact = match lower.as_str() {
        "claude.md" => Some((
            Harness::ClaudeCode,
            ComponentType::Instruction,
            RuntimeConfidence::ActiveRuntime,
        )),
        "agents.md" => Some((
            Harness::Codex,
            ComponentType::Instruction,
            RuntimeConfidence::ActiveRuntime,
        )),
        "gemini.md" => Some((
            Harness::GeminiCli,
            ComponentType::Instruction,
            RuntimeConfidence::ActiveRuntime,
        )),
        ".mcp.json" => Some((
            Harness::ClaudeCode,
            ComponentType::McpConfig,
            RuntimeConfidence::ProjectLocalOptional,
        )),
        ".claude.json" => Some((
            Harness::ClaudeCode,
            ComponentType::Settings,
            RuntimeConfidence::UserScope,
        )),
        ".claude/settings.json" | ".claude/settings.local.json" => Some((
            Harness::ClaudeCode,
            ComponentType::Settings,
            RuntimeConfidence::ActiveRuntime,
        )),
        ".codex/config.toml" => Some((
            Harness::Codex,
            ComponentType::Settings,
            RuntimeConfidence::ProjectLocalOptional,
        )),
        ".gemini/settings.json" => Some((
            Harness::GeminiCli,
            ComponentType::Settings,
            RuntimeConfidence::ActiveRuntime,
        )),
        ".cursor/mcp.json" => Some((
            Harness::Cursor,
            ComponentType::McpConfig,
            RuntimeConfidence::ActiveRuntime,
        )),
        "opencode.json"
        | "opencode.jsonc"
        | ".opencode/opencode.json"
        | ".opencode/opencode.jsonc"
        | ".config/opencode/opencode.json"
        | ".config/opencode/opencode.jsonc" => Some((
            Harness::OpenCode,
            ComponentType::Settings,
            RuntimeConfidence::ProjectLocalOptional,
        )),
        "apm.yml" | "apm.yaml" => Some((
            Harness::MicrosoftApm,
            ComponentType::Manifest,
            RuntimeConfidence::ProjectLocalOptional,
        )),
        "apm.lock.yml" | "apm.lock.yaml" => Some((
            Harness::MicrosoftApm,
            ComponentType::Lockfile,
            RuntimeConfidence::ProjectLocalOptional,
        )),
        _ => None,
    };
    if let Some((harness, component_type, confidence)) = exact {
        return Some(Surface {
            harness,
            component_type,
            confidence,
        });
    }

    if lower == ".claude-plugin/plugin.json" || lower.ends_with("/.claude-plugin/plugin.json") {
        return Some(Surface {
            harness: Harness::ClaudeCode,
            component_type: ComponentType::PluginConfig,
            confidence: RuntimeConfidence::ProjectLocalOptional,
        });
    }

    let parts: Vec<_> = lower.split('/').collect();
    let under = |prefix: &str| lower.starts_with(prefix);
    let md = matches!(
        rel.extension().and_then(|x| x.to_str()),
        Some("md") | Some("mdx")
    );

    if under(".claude/skills/") && (file == "skill.md" || md) {
        return Some(Surface {
            harness: Harness::ClaudeCode,
            component_type: ComponentType::Skill,
            confidence: RuntimeConfidence::ActiveRuntime,
        });
    }
    if under(".claude/agents/") && md {
        return Some(Surface {
            harness: Harness::ClaudeCode,
            component_type: ComponentType::Agent,
            confidence: RuntimeConfidence::ActiveRuntime,
        });
    }
    if under(".claude/commands/") && md {
        return Some(Surface {
            harness: Harness::ClaudeCode,
            component_type: ComponentType::Command,
            confidence: RuntimeConfidence::ActiveRuntime,
        });
    }
    if under(".codex/skills/") && (file == "skill.md" || md) {
        return Some(Surface {
            harness: Harness::Codex,
            component_type: ComponentType::Skill,
            confidence: RuntimeConfidence::ProjectLocalOptional,
        });
    }
    if under(".gemini/skills/") && (file == "skill.md" || md) {
        return Some(Surface {
            harness: Harness::GeminiCli,
            component_type: ComponentType::Skill,
            confidence: RuntimeConfidence::ProjectLocalOptional,
        });
    }
    if under(".cursor/rules/") && (md || file.ends_with(".mdc")) {
        return Some(Surface {
            harness: Harness::Cursor,
            component_type: ComponentType::Rule,
            confidence: RuntimeConfidence::ActiveRuntime,
        });
    }
    if under(".cursor/skills/") && (file == "skill.md" || md) {
        return Some(Surface {
            harness: Harness::Cursor,
            component_type: ComponentType::Skill,
            confidence: RuntimeConfidence::ActiveRuntime,
        });
    }
    if under(".agents/skills/") && (file == "skill.md" || md) {
        return Some(Surface {
            harness: Harness::CrossAgent,
            component_type: ComponentType::Skill,
            confidence: RuntimeConfidence::ProjectLocalOptional,
        });
    }
    if under(".opencode/") && (file == "agents.md" || file == "agent.md") {
        return Some(Surface {
            harness: Harness::OpenCode,
            component_type: ComponentType::Agent,
            confidence: RuntimeConfidence::ProjectLocalOptional,
        });
    }

    // Instruction files nested under docs/examples are intentionally visible but never active.
    if matches!(file.as_str(), "claude.md" | "agents.md" | "gemini.md") && parts.len() > 1 {
        let harness = match file.as_str() {
            "claude.md" => Harness::ClaudeCode,
            "agents.md" => Harness::Codex,
            _ => Harness::GeminiCli,
        };
        return Some(Surface {
            harness,
            component_type: ComponentType::Instruction,
            confidence: RuntimeConfidence::Unknown,
        });
    }
    None
}

fn is_claude_settings_component_source(surface: Surface, rel: &Path) -> bool {
    if surface.harness != Harness::ClaudeCode || surface.component_type != ComponentType::Settings {
        return false;
    }
    matches!(
        normalize_rel(rel).to_ascii_lowercase().as_str(),
        ".claude/settings.json" | ".claude/settings.local.json"
    )
}

fn discover_claude_settings_components(
    rel: &Path,
    content: &str,
    confidence: RuntimeConfidence,
    parent: &DiscoveredArtifact,
) -> Result<Vec<DiscoveredArtifact>, String> {
    let value: JsonValue =
        serde_json::from_str(content).map_err(|err| format!("JSON parse failed: {err}"))?;
    let Some(root) = value.as_object() else {
        return Ok(Vec::new());
    };

    let mut components = Vec::new();
    if let Some(hooks) = root.get("hooks") {
        let has_entries = hooks.as_object().is_some_and(|entries| !entries.is_empty())
            || hooks.as_array().is_some_and(|entries| !entries.is_empty());
        if has_entries {
            let canonical = canonical_json(hooks);
            let digest = sha256_hex(canonical.as_bytes());
            let mut metadata = BTreeMap::new();
            metadata.insert("parent_artifact_id".into(), parent.artifact_id.clone());
            metadata.insert("derived_config_entry".into(), "true".into());
            metadata.insert("passive_discovery".into(), "true".into());
            if let Some(root_relative) = parent.metadata.get("root_relative") {
                metadata.insert("root_relative".into(), root_relative.clone());
            }
            components.push(DiscoveredArtifact {
                schema_version: SCHEMA_VERSION.into(),
                artifact_id: stable_id(&format!(
                    "{}|hook_config|{}|hooks",
                    SCHEMA_VERSION, parent.artifact_id
                )),
                artifact_type: "hook".into(),
                name: "hooks".into(),
                harness: Harness::ClaudeCode,
                component_type: ComponentType::HookConfig,
                runtime_confidence: confidence,
                local_path: parent.local_path.clone(),
                source_uri: None,
                resolved_revision: None,
                content_digest: format!("sha256:{digest}"),
                provenance_status: "declared".into(),
                declared_capabilities: Vec::new(),
                inferred_capabilities: infer_capabilities(&canonical, ComponentType::HookConfig),
                evidence: vec![EvidenceRef {
                    kind: "config_entry".into(),
                    location: format!("{}#hooks", normalize_rel(rel)),
                    detail: "hook configuration parsed statically; commands were not executed"
                        .into(),
                }],
                metadata,
            });
        }
    }

    if let Some(enabled_plugins) = root.get("enabledPlugins").and_then(JsonValue::as_object) {
        for (plugin_name, enabled) in enabled_plugins {
            if enabled.as_bool() != Some(true) {
                continue;
            }
            let digest = sha256_hex(format!("{plugin_name}=true").as_bytes());
            let mut metadata = BTreeMap::new();
            metadata.insert("parent_artifact_id".into(), parent.artifact_id.clone());
            metadata.insert("derived_config_entry".into(), "true".into());
            metadata.insert("passive_discovery".into(), "true".into());
            metadata.insert("enabled".into(), "true".into());
            if let Some(root_relative) = parent.metadata.get("root_relative") {
                metadata.insert("root_relative".into(), root_relative.clone());
            }
            components.push(DiscoveredArtifact {
                schema_version: SCHEMA_VERSION.into(),
                artifact_id: stable_id(&format!(
                    "{}|plugin_config|{}|{}",
                    SCHEMA_VERSION, parent.artifact_id, plugin_name
                )),
                artifact_type: "plugin".into(),
                name: plugin_name.chars().take(200).collect(),
                harness: Harness::ClaudeCode,
                component_type: ComponentType::PluginConfig,
                runtime_confidence: confidence,
                local_path: parent.local_path.clone(),
                source_uri: None,
                resolved_revision: None,
                content_digest: format!("sha256:{digest}"),
                provenance_status: "declared".into(),
                declared_capabilities: Vec::new(),
                inferred_capabilities: Vec::new(),
                evidence: vec![EvidenceRef {
                    kind: "config_entry".into(),
                    location: format!("{}#enabledPlugins:{}", normalize_rel(rel), plugin_name),
                    detail: "enabled plugin declared by Claude Code settings".into(),
                }],
                metadata,
            });
        }
    }

    Ok(components)
}

fn surface_can_contain_mcp(surface: Surface, rel: &Path) -> bool {
    if surface.component_type == ComponentType::McpConfig {
        return true;
    }
    if surface.component_type != ComponentType::Settings {
        return false;
    }
    let lower = normalize_rel(rel).to_ascii_lowercase();
    matches!(
        surface.harness,
        Harness::Codex | Harness::GeminiCli | Harness::OpenCode
    ) || (surface.harness == Harness::ClaudeCode && lower == ".claude.json")
}

fn apply_example_confidence(rel: &Path, default: RuntimeConfidence) -> RuntimeConfidence {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    if parts
        .iter()
        .any(|p| matches!(p.as_str(), "docs" | "doc" | "documentation"))
    {
        return RuntimeConfidence::DocsExample;
    }
    if parts.iter().any(|p| {
        matches!(
            p.as_str(),
            "example"
                | "examples"
                | "sample"
                | "samples"
                | "template"
                | "templates"
                | "fixtures"
                | "testdata"
                | "test-data"
        )
    }) {
        return RuntimeConfidence::TemplateExample;
    }
    default
}

fn artifact_from_file(
    root_abs: &Path,
    rel: &Path,
    surface: Surface,
    confidence: RuntimeConfidence,
    digest: String,
    content: &str,
) -> DiscoveredArtifact {
    let rel_norm = normalize_rel(rel);
    let mut name = rel
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_norm.clone());
    let artifact_type = contract_artifact_type(surface.component_type).to_string();
    let artifact_id = stable_id(&format!(
        "{}|{}|{}|{}",
        SCHEMA_VERSION,
        harness_name(surface.harness),
        component_type_name(surface.component_type),
        rel_norm
    ));
    let inferred_capabilities = infer_capabilities(content, surface.component_type);
    let mut metadata = BTreeMap::new();
    metadata.insert("root_relative".into(), rel_norm.clone());
    metadata.insert("passive_discovery".into(), "true".into());
    metadata.insert("root_digest_scope".into(), "file_content".into());
    if surface.component_type == ComponentType::PluginConfig {
        if let Ok(manifest) = serde_json::from_str::<JsonValue>(content) {
            if let Some(manifest_name) = manifest.get("name").and_then(JsonValue::as_str) {
                if !manifest_name.trim().is_empty() {
                    name = manifest_name.chars().take(200).collect();
                }
            }
            if let Some(version) = manifest.get("version").and_then(JsonValue::as_str) {
                metadata.insert(
                    "declared_version".into(),
                    version.chars().take(100).collect(),
                );
            }
            if manifest.get("repository").is_some() {
                metadata.insert("declared_repository_present".into(), "true".into());
            }
        }
    }
    if surface.harness == Harness::MicrosoftApm {
        metadata.insert("provenance_input".into(), "apm_manifest_or_lock".into());
    }
    DiscoveredArtifact {
        schema_version: SCHEMA_VERSION.to_string(),
        artifact_id,
        artifact_type,
        name,
        harness: surface.harness,
        component_type: surface.component_type,
        runtime_confidence: confidence,
        local_path: root_abs.join(rel).to_string_lossy().replace('\\', "/"),
        source_uri: None,
        resolved_revision: None,
        content_digest: format!("sha256:{digest}"),
        provenance_status: "inferred".into(),
        declared_capabilities: Vec::new(),
        inferred_capabilities,
        evidence: vec![EvidenceRef {
            kind: "file_content".into(),
            location: rel_norm,
            detail: "passively discovered known harness surface".into(),
        }],
        metadata,
    }
}

fn discover_mcp_servers(
    rel: &Path,
    content: &str,
    harness: Harness,
    confidence: RuntimeConfidence,
    parent: &DiscoveredArtifact,
) -> Result<Vec<DiscoveredArtifact>, String> {
    let value = if rel.extension().and_then(|x| x.to_str()) == Some("toml") {
        let value: toml::Value =
            toml::from_str(content).map_err(|e| format!("TOML parse failed: {e}"))?;
        serde_json::to_value(value).map_err(|e| format!("TOML normalization failed: {e}"))?
    } else {
        let normalized = if rel.extension().and_then(|x| x.to_str()) == Some("jsonc") {
            strip_jsonc_comments(content)
        } else {
            content.to_owned()
        };
        serde_json::from_str::<JsonValue>(&normalized)
            .map_err(|e| format!("JSON parse failed: {e}"))?
    };

    let maps = mcp_server_maps(&value, harness, rel);
    let mut servers = Vec::new();
    for (scope, map) in maps {
        for (name, config) in map {
            let Some(obj) = config.as_object() else {
                continue;
            };
            let command = obj.get("command").and_then(|value| match value {
                JsonValue::String(command) => Some(command.clone()),
                JsonValue::Array(parts) => {
                    parts.first().and_then(JsonValue::as_str).map(str::to_owned)
                }
                _ => None,
            });
            let url = obj
                .get("url")
                .or_else(|| obj.get("serverUrl"))
                .and_then(JsonValue::as_str)
                .map(str::to_owned);
            let mut caps = BTreeSet::new();
            if command.is_some() {
                caps.insert("process.exec".to_string());
            }
            if url.is_some() {
                caps.insert("network.connect".to_string());
            }
            caps.insert("mcp.call".to_string());
            let canonical_config = canonical_json(config);
            let server_digest = sha256_hex(canonical_config.as_bytes());
            let id = stable_id(&format!(
                "{}|mcp_server|{}|{}|{}|{}",
                SCHEMA_VERSION,
                harness_name(harness),
                parent.artifact_id,
                scope,
                name
            ));
            let mut metadata = BTreeMap::new();
            metadata.insert("parent_artifact_id".into(), parent.artifact_id.clone());
            metadata.insert("mcp_scope".into(), scope.clone());
            if let Some(root_relative) = parent.metadata.get("root_relative") {
                metadata.insert("root_relative".into(), root_relative.clone());
            }
            metadata.insert("passive_discovery".into(), "true".into());
            if let Some(cmd) = &command {
                let command_name = command_basename(cmd);
                metadata.insert("command_name".into(), command_name.clone());
                if let Some(pin_state) = package_ref_state(&command_name, obj) {
                    metadata.insert("package_ref_state".into(), pin_state.into());
                }
            }
            if let Some(url) = &url {
                metadata.insert(
                    "transport".into(),
                    if url.starts_with("https://") {
                        "https"
                    } else if url.starts_with("http://") {
                        "http"
                    } else {
                        "remote"
                    }
                    .into(),
                );
            }
            servers.push(DiscoveredArtifact {
                schema_version: SCHEMA_VERSION.into(),
                artifact_id: id,
                artifact_type: "mcp_server".into(),
                name: name.clone(),
                harness,
                component_type: ComponentType::McpServer,
                runtime_confidence: confidence,
                local_path: parent.local_path.clone(),
                source_uri: url,
                resolved_revision: None,
                content_digest: format!("sha256:{server_digest}"),
                provenance_status: "declared".into(),
                declared_capabilities: Vec::new(),
                inferred_capabilities: caps.into_iter().collect(),
                evidence: vec![EvidenceRef {
                    kind: "config_entry".into(),
                    location: format!("{}#mcp:{}:{}", normalize_rel(rel), scope, name),
                    detail: "parsed statically; server was not started".into(),
                }],
                metadata,
            });
        }
    }
    Ok(servers)
}

fn mcp_server_maps<'a>(
    value: &'a JsonValue,
    harness: Harness,
    rel: &Path,
) -> Vec<(String, &'a serde_json::Map<String, JsonValue>)> {
    let mut out = Vec::new();
    let Some(root) = value.as_object() else {
        return out;
    };

    for key in ["mcpServers", "mcp_servers", "mcp"] {
        if let Some(map) = root.get(key).and_then(JsonValue::as_object) {
            out.push((key.to_string(), map));
        }
    }

    if harness == Harness::ClaudeCode
        && rel.file_name().and_then(|name| name.to_str()) == Some(".claude.json")
    {
        if let Some(projects) = root.get("projects").and_then(JsonValue::as_object) {
            for (project_path, project) in projects {
                let Some(project_obj) = project.as_object() else {
                    continue;
                };
                let Some(map) = project_obj.get("mcpServers").and_then(JsonValue::as_object) else {
                    continue;
                };
                let project_key = &sha256_hex(project_path.as_bytes())[..12];
                out.push((format!("project:{project_key}:mcpServers"), map));
            }
        }
    }

    if out.is_empty()
        && matches!(
            rel.file_name().and_then(|name| name.to_str()),
            Some(".mcp.json") | Some("mcp.json")
        )
        && looks_like_flat_mcp_map(root)
    {
        out.push(("flat".into(), root));
    }

    out
}

fn looks_like_flat_mcp_map(map: &serde_json::Map<String, JsonValue>) -> bool {
    !map.is_empty()
        && map.values().all(|value| {
            value.as_object().is_some_and(|server| {
                server.contains_key("command")
                    || server.contains_key("url")
                    || server.contains_key("serverUrl")
                    || server.contains_key("type")
            })
        })
}

fn package_ref_state(
    command_name: &str,
    config: &serde_json::Map<String, JsonValue>,
) -> Option<&'static str> {
    let command = command_name.to_ascii_lowercase();
    let args = config
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(JsonValue::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    match command.as_str() {
        "npx" | "npx.exe" => {
            let package = args.iter().copied().find(|arg| !arg.starts_with('-'))?;
            Some(if npm_ref_is_exact(package) {
                "pinned"
            } else {
                "unpinned"
            })
        }
        "uvx" | "uvx.exe" => {
            let package = args.iter().copied().find(|arg| !arg.starts_with('-'))?;
            Some(
                if python_ref_is_exact(package) || npm_ref_is_exact(package) {
                    "pinned"
                } else {
                    "unpinned"
                },
            )
        }
        "pip" | "pip.exe" | "pip3" | "pip3.exe" => {
            let install_index = args
                .iter()
                .position(|arg| arg.eq_ignore_ascii_case("install"))?;
            let package = args[install_index + 1..]
                .iter()
                .copied()
                .find(|arg| !arg.starts_with('-'))?;
            Some(if python_ref_is_exact(package) {
                "pinned"
            } else {
                "unpinned"
            })
        }
        _ => None,
    }
}

fn npm_ref_is_exact(package: &str) -> bool {
    let version = if package.starts_with('@') {
        package
            .rsplit('/')
            .next()
            .and_then(|tail| tail.rsplit_once('@').map(|(_, v)| v))
    } else {
        package.rsplit_once('@').map(|(_, version)| version)
    };
    version.is_some_and(exact_semver_like)
}

fn exact_semver_like(version: &str) -> bool {
    if version.is_empty()
        || matches!(
            version.chars().next(),
            Some('^' | '~' | '>' | '<' | '=' | '*')
        )
        || matches!(version, "latest" | "next" | "beta" | "canary")
    {
        return false;
    }
    let without_build = version
        .split_once('+')
        .map(|(core, _)| core)
        .unwrap_or(version);
    let core = without_build
        .split_once('-')
        .map(|(core, _)| core)
        .unwrap_or(without_build);
    let parts = core.trim_start_matches('v').split('.').collect::<Vec<_>>();
    parts.len() == 3 && parts.iter().all(|part| part.parse::<u64>().is_ok())
}

fn python_ref_is_exact(requirement: &str) -> bool {
    if requirement == "." || requirement.starts_with("./") || requirement.starts_with("../") {
        return true;
    }
    let Some((name, version)) = requirement.split_once("==") else {
        return false;
    };
    !name.trim().is_empty()
        && !version.trim().is_empty()
        && !version.chars().any(|ch| matches!(ch, '*' | ',' | ';'))
}

fn infer_capabilities(content: &str, component_type: ComponentType) -> Vec<String> {
    let lower = content.to_ascii_lowercase();
    let mut caps = BTreeSet::new();
    if matches!(
        component_type,
        ComponentType::Command | ComponentType::HookConfig
    ) || lower.contains("bash(")
        || lower.contains("powershell")
        || lower.contains("cmd.exe")
        || lower.contains("allowed-tools") && lower.contains("bash")
    {
        caps.insert("process.exec".to_string());
    }
    if lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("webfetch")
        || lower.contains("http://")
        || lower.contains("https://")
    {
        caps.insert("network.connect".to_string());
    }
    if lower.contains("git push --force") || lower.contains("git push -f") {
        caps.insert("git.force_push".to_string());
    } else if lower.contains("git push") {
        caps.insert("git.push".to_string());
    }
    if lower.contains("write") || lower.contains("edit") || lower.contains("fs.write") {
        caps.insert("fs.write".to_string());
    }
    if lower.contains("read") || lower.contains("fs.read") {
        caps.insert("fs.read".to_string());
    }
    if lower.contains("mcp") {
        caps.insert("mcp.discover".to_string());
    }
    caps.into_iter().collect()
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bytes.truncate(limit as usize);
    }
    Ok(bytes)
}

fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut previous = '\0';
            for comment_ch in chars.by_ref() {
                if comment_ch == '\n' {
                    out.push('\n');
                }
                if previous == '*' && comment_ch == '/' {
                    break;
                }
                previous = comment_ch;
            }
            continue;
        }

        out.push(ch);
    }

    strip_json_trailing_commas(&out)
}

fn strip_json_trailing_commas(input: &str) -> String {
    let chars = input.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escaped = false;

    for (index, ch) in chars.iter().copied().enumerate() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            out.push(ch);
            continue;
        }

        if ch == ',' {
            let next_non_whitespace = chars[index + 1..]
                .iter()
                .copied()
                .find(|candidate| !candidate.is_whitespace());
            if matches!(next_non_whitespace, Some('}') | Some(']')) {
                continue;
            }
        }

        out.push(ch);
    }

    out
}

fn canonical_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".into(),
        JsonValue::Bool(v) => v.to_string(),
        JsonValue::Number(v) => v.to_string(),
        JsonValue::String(v) => serde_json::to_string(v).expect("string serialization"),
        JsonValue::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        JsonValue::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let pairs = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).expect("key serialization"),
                        canonical_json(&map[k])
                    )
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn stable_id(input: &str) -> String {
    format!("proofdrift:{}", &sha256_hex(input.as_bytes())[..32])
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn normalize_rel(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
fn command_basename(command: &str) -> String {
    Path::new(command)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| command.to_string())
}
fn harness_name(h: Harness) -> &'static str {
    match h {
        Harness::ClaudeCode => "claude_code",
        Harness::Codex => "codex",
        Harness::GeminiCli => "gemini_cli",
        Harness::Cursor => "cursor",
        Harness::OpenCode => "opencode",
        Harness::CrossAgent => "cross_agent",
        Harness::MicrosoftApm => "microsoft_apm",
        Harness::Unknown => "unknown",
    }
}
fn contract_artifact_type(component_type: ComponentType) -> &'static str {
    match component_type {
        ComponentType::Skill => "skill",
        ComponentType::Agent => "agent",
        ComponentType::HookConfig => "hook",
        ComponentType::McpServer => "mcp_server",
        ComponentType::PluginConfig => "plugin",
        ComponentType::Instruction
        | ComponentType::Settings
        | ComponentType::Command
        | ComponentType::McpConfig
        | ComponentType::Rule
        | ComponentType::Manifest
        | ComponentType::Lockfile => "file",
        ComponentType::Other => "other",
    }
}

fn component_type_name(t: ComponentType) -> &'static str {
    match t {
        ComponentType::Instruction => "instruction",
        ComponentType::Settings => "settings",
        ComponentType::Skill => "skill",
        ComponentType::Agent => "agent",
        ComponentType::Command => "command",
        ComponentType::HookConfig => "hook_config",
        ComponentType::McpConfig => "mcp_config",
        ComponentType::McpServer => "mcp_server",
        ComponentType::Rule => "rule",
        ComponentType::PluginConfig => "plugin_config",
        ComponentType::Manifest => "manifest",
        ComponentType::Lockfile => "lockfile",
        ComponentType::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TMP: AtomicU64 = AtomicU64::new(1);

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("proofdrift-discover-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TestDir {
        TestDir::new()
    }

    #[test]
    fn classifies_root_active_but_docs_copy_as_docs_example() {
        let tmp = tempdir();
        fs::write(tmp.path().join("CLAUDE.md"), "Use Read only").unwrap();
        fs::create_dir_all(tmp.path().join("docs/setup")).unwrap();
        fs::write(
            tmp.path().join("docs/setup/CLAUDE.md"),
            "curl https://example.invalid",
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        let root = result
            .artifacts
            .iter()
            .find(|a| a.local_path.ends_with("/CLAUDE.md") && !a.local_path.contains("/docs/"))
            .unwrap();
        let docs = result
            .artifacts
            .iter()
            .find(|a| a.local_path.contains("/docs/setup/CLAUDE.md"))
            .unwrap();
        assert_eq!(root.runtime_confidence, RuntimeConfidence::ActiveRuntime);
        assert_eq!(docs.runtime_confidence, RuntimeConfidence::DocsExample);
    }

    #[test]
    fn mcp_discovery_is_static_and_has_stable_digest() {
        let tmp = tempdir();
        fs::write(tmp.path().join(".mcp.json"), r#"{"mcpServers":{"danger":{"command":"do-not-run","args":["--write-marker"]},"remote":{"url":"https://example.com/mcp"}}}"#).unwrap();
        let first = discover_project(tmp.path()).unwrap();
        let second = discover_project(tmp.path()).unwrap();
        let servers: Vec<_> = first
            .artifacts
            .iter()
            .filter(|a| a.component_type == ComponentType::McpServer)
            .collect();
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().any(|a| a.name == "danger"
            && a.inferred_capabilities
                .contains(&"process.exec".to_string())));
        assert_eq!(
            serde_json::to_string(&first.artifacts).unwrap(),
            serde_json::to_string(&second.artifacts).unwrap()
        );
    }

    #[test]
    fn user_scope_is_opt_in_and_keeps_mcp_confidence() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join(".claude.json"),
            r#"{"mcpServers":{"user-server":{"url":"https://example.com/mcp"}}}"#,
        )
        .unwrap();

        let default_result = discover_project(tmp.path()).unwrap();
        assert!(default_result.artifacts.is_empty());

        let options = DiscoverOptions {
            include_user_scope: true,
            ..DiscoverOptions::default()
        };
        let opted_in = discover_project_with_options(tmp.path(), &options).unwrap();
        assert!(opted_in
            .artifacts
            .iter()
            .any(|artifact| artifact.runtime_confidence == RuntimeConfidence::UserScope));
        assert!(opted_in.artifacts.iter().any(|artifact| {
            artifact.component_type == ComponentType::McpServer
                && artifact.name == "user-server"
                && artifact.runtime_confidence == RuntimeConfidence::UserScope
        }));
    }

    #[test]
    fn parses_codex_toml_mcp_without_executing_it() {
        let tmp = tempdir();
        fs::create_dir_all(tmp.path().join(".codex")).unwrap();
        fs::write(
            tmp.path().join(".codex/config.toml"),
            "[mcp_servers.demo]\ncommand = \"npx\"\nargs = [\"-y\", \"demo-server@1.2.3\"]\n",
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        let server = result
            .artifacts
            .iter()
            .find(|artifact| artifact.component_type == ComponentType::McpServer)
            .unwrap();
        assert_eq!(server.harness, Harness::Codex);
        assert_eq!(server.name, "demo");
        assert!(server
            .inferred_capabilities
            .contains(&"process.exec".to_string()));
    }

    #[test]
    fn parses_opencode_jsonc_mcp() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join("opencode.jsonc"),
            "{\n  /* block comment */\n  \"mcp\": {\"remote\": {\"url\": \"https://example.com/mcp\",},}, // trailing commas\n}\n",
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        assert!(result.artifacts.iter().any(|artifact| {
            artifact.component_type == ComponentType::McpServer
                && artifact.harness == Harness::OpenCode
                && artifact.name == "remote"
        }));
    }

    #[test]
    fn claude_user_config_discovers_project_scopes_without_id_collision() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join(".claude.json"),
            r#"{"projects":{"C:\\work\\one":{"mcpServers":{"same":{"command":"server-one"}}},"/work/two":{"mcpServers":{"same":{"command":"server-two"}}}}}"#,
        )
        .unwrap();
        let options = DiscoverOptions {
            include_user_scope: true,
            ..DiscoverOptions::default()
        };
        let result = discover_project_with_options(tmp.path(), &options).unwrap();
        let servers = result
            .artifacts
            .iter()
            .filter(|artifact| artifact.component_type == ComponentType::McpServer)
            .collect::<Vec<_>>();
        assert_eq!(servers.len(), 2);
        assert_ne!(servers[0].artifact_id, servers[1].artifact_id);
        assert!(servers
            .iter()
            .all(|server| server.metadata.contains_key("mcp_scope")));
    }

    #[test]
    fn flat_mcp_map_is_ingested_when_entries_look_like_servers() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"alpha":{"command":"server-a"},"beta":{"url":"https://example.com/mcp"}}"#,
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        assert_eq!(
            result
                .artifacts
                .iter()
                .filter(|artifact| artifact.component_type == ComponentType::McpServer)
                .count(),
            2
        );
    }

    #[test]
    fn structured_package_refs_record_pin_state_without_storing_package_args() {
        let tmp = tempdir();
        fs::write(
            tmp.path().join(".mcp.json"),
            r#"{"mcpServers":{"safe":{"command":"npx","args":["-y","safe-tool@1.2.3"]},"range":{"command":"npx","args":["-y","range-tool@^1.2.0"]}}}"#,
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        let safe = result
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "safe")
            .unwrap();
        let range = result
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "range")
            .unwrap();
        assert_eq!(
            safe.metadata.get("package_ref_state").map(String::as_str),
            Some("pinned")
        );
        assert_eq!(
            range.metadata.get("package_ref_state").map(String::as_str),
            Some("unpinned")
        );
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("safe-tool@1.2.3"));
        assert!(!encoded.contains("range-tool@^1.2.0"));
    }

    #[test]
    fn claude_plugin_manifest_is_discovered_as_plugin_contract_artifact() {
        let tmp = tempdir();
        let manifest_dir = tmp.path().join("plugins/demo/.claude-plugin");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::write(
            manifest_dir.join("plugin.json"),
            r#"{"name":"demo-plugin","version":"1.2.3","repository":"https://example.com/demo.git"}"#,
        )
        .unwrap();

        let result = discover_project(tmp.path()).unwrap();
        let plugin = result
            .artifacts
            .iter()
            .find(|artifact| artifact.component_type == ComponentType::PluginConfig)
            .unwrap();
        assert_eq!(plugin.artifact_type, "plugin");
        assert_eq!(plugin.name, "demo-plugin");
        assert_eq!(
            plugin.metadata.get("declared_version").map(String::as_str),
            Some("1.2.3")
        );
        assert_eq!(
            plugin
                .metadata
                .get("declared_repository_present")
                .map(String::as_str),
            Some("true")
        );
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("https://example.com/demo.git"));
    }

    #[test]
    fn claude_settings_emit_hook_and_enabled_plugin_children() {
        let tmp = tempdir();
        fs::create_dir_all(tmp.path().join(".claude")).unwrap();
        fs::write(
            tmp.path().join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"command":"echo hook"}]},"enabledPlugins":{"active@market":true,"disabled@market":false}}"#,
        )
        .unwrap();

        let result = discover_project(tmp.path()).unwrap();
        let hook = result
            .artifacts
            .iter()
            .find(|artifact| artifact.component_type == ComponentType::HookConfig)
            .unwrap();
        assert_eq!(hook.artifact_type, "hook");
        assert_eq!(hook.runtime_confidence, RuntimeConfidence::ActiveRuntime);
        assert!(hook
            .inferred_capabilities
            .contains(&"process.exec".to_string()));

        let active_plugin = result
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "active@market")
            .unwrap();
        assert_eq!(active_plugin.component_type, ComponentType::PluginConfig);
        assert_eq!(active_plugin.artifact_type, "plugin");
        assert_eq!(
            active_plugin.metadata.get("enabled").map(String::as_str),
            Some("true")
        );
        assert!(!result
            .artifacts
            .iter()
            .any(|artifact| artifact.name == "disabled@market"));
        assert!(!serde_json::to_string(&result)
            .unwrap()
            .contains("echo hook"));
    }

    #[test]
    fn malformed_config_is_diagnostic_not_fatal() {
        let tmp = tempdir();
        fs::write(tmp.path().join(".mcp.json"), "{ definitely-not-json").unwrap();
        let result = discover_project(tmp.path()).unwrap();
        assert_eq!(result.stats.parse_warnings, 1);
        assert_eq!(
            result
                .artifacts
                .iter()
                .filter(|artifact| artifact.component_type == ComponentType::McpServer)
                .count(),
            0
        );
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("JSON parse failed")));
    }

    #[test]
    fn oversized_candidate_is_skipped_without_reading_content() {
        let tmp = tempdir();
        fs::write(tmp.path().join("CLAUDE.md"), "x".repeat(64)).unwrap();
        let options = DiscoverOptions {
            max_file_bytes: 16,
            ..DiscoverOptions::default()
        };
        let result = discover_project_with_options(tmp.path(), &options).unwrap();
        assert_eq!(result.stats.files_skipped_too_large, 1);
        assert_eq!(result.stats.files_hashed, 0);
        assert!(result.artifacts.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("skipped oversized candidate")));
    }

    #[test]
    fn oversized_candidates_and_entry_count_are_bounded() {
        let tmp = tempdir();
        fs::write(tmp.path().join("CLAUDE.md"), "x".repeat(64)).unwrap();
        fs::write(tmp.path().join("a.txt"), "x").unwrap();
        fs::write(tmp.path().join("b.txt"), "x").unwrap();
        let options = DiscoverOptions {
            max_file_bytes: 16,
            max_entries: 2,
            ..DiscoverOptions::default()
        };
        let result = discover_project_with_options(tmp.path(), &options).unwrap();
        assert!(result.stats.entries_visited <= 2);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("entry limit")));
    }

    #[test]
    fn ignored_dependency_trees_do_not_create_false_runtime_artifacts() {
        let tmp = tempdir();
        fs::create_dir_all(tmp.path().join("node_modules/pkg")).unwrap();
        fs::write(
            tmp.path().join("node_modules/pkg/CLAUDE.md"),
            "Bash(*) and npx unpinned",
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        assert!(result.artifacts.is_empty());
    }

    #[test]
    fn json_contract_fixture_deserializes_and_uses_shared_artifact_types() {
        let fixture = include_str!("../../../contracts/fixtures/discovery/discover.expected.json");
        let parsed: DiscoveryResult = serde_json::from_str(fixture).unwrap();
        let allowed = [
            "repo",
            "commit",
            "file",
            "skill",
            "hook",
            "agent",
            "plugin",
            "mcp_server",
            "model",
            "dataset",
            "binary",
            "container",
            "package",
            "other",
        ];
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert!(parsed
            .artifacts
            .iter()
            .all(|artifact| allowed.contains(&artifact.artifact_type.as_str())));
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_to_outside_is_not_followed() {
        let tmp = tempdir();
        let outside = tempdir();
        fs::write(outside.path().join("CLAUDE.md"), "Bash(*) and npx unsafe").unwrap();
        let link = tmp.path().join("linked-outside");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(outside.path())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to create Windows junction regression fixture"
        );

        let result = discover_project(tmp.path()).unwrap();
        assert!(result.artifacts.is_empty());
        assert!(result.stats.symlinks_skipped >= 1);

        fs::remove_dir(&link).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlink_candidates() {
        let tmp = tempdir();
        let outside = tempdir();
        fs::write(outside.path().join("CLAUDE.md"), "outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("CLAUDE.md"),
            tmp.path().join("CLAUDE.md"),
        )
        .unwrap();
        let result = discover_project(tmp.path()).unwrap();
        assert!(result.artifacts.is_empty());
    }
}
