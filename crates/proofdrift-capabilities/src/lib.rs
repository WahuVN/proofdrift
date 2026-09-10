//! Canonical capability taxonomy and deterministic extraction helpers.
//!
//! Declared, inferred and observed evidence are intentionally distinct.
//! Static inference never upgrades itself to runtime observation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::Url;

pub const CAPABILITY_SCHEMA_VERSION: &str = "1.0.0";
pub const TAXONOMY_VERSION: &str = "capability-taxonomy-v0";

fn default_taxonomy_version() -> String {
    TAXONOMY_VERSION.to_string()
}

pub const TAXONOMY: &[&str] = &[
    "fs.read",
    "fs.write",
    "fs.create",
    "fs.delete",
    "fs.rename",
    "process.exec",
    "process.kill",
    "network.connect",
    "network.listen",
    "git.read",
    "git.commit",
    "git.reset",
    "git.checkout",
    "git.push",
    "git.force_push",
    "secret.read",
    "secret.egress",
    "mcp.list",
    "mcp.call",
    "db.read",
    "db.write",
    "db.schema",
    "cloud.read",
    "cloud.mutate",
    "browser.navigate",
    "browser.download",
    "browser.upload",
    "browser.submit",
    "money.spend",
    "identity.act_as",
    "package.install",
    "credential.use",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    Declared,
    Inferred,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Any,
    Path,
    Host,
    GitRef,
    McpTool,
    Database,
    CloudResource,
    BrowserTarget,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceSelector {
    pub kind: ResourceKind,
    pub original: String,
    pub normalized: String,
}

impl ResourceSelector {
    pub fn any() -> Self {
        Self {
            kind: ResourceKind::Any,
            original: "*".into(),
            normalized: "*".into(),
        }
    }

    pub fn literal(kind: ResourceKind, value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            kind,
            original: value.clone(),
            normalized: value,
        }
    }

    pub fn matches(&self, candidate: &str) -> bool {
        wildcard_match(&self.normalized, candidate)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    pub schema_version: String,
    #[serde(default = "default_taxonomy_version")]
    pub taxonomy_version: String,
    pub capability_id: String,
    pub action_family: String,
    /// Canonical ProofDrift v1 wire field. This mirrors `resource.normalized`.
    pub resource_selector: String,
    /// Rich typed resource metadata retained as a forward-compatible extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceSelector>,
    #[serde(default)]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub source: CapabilitySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub risk_tags: BTreeSet<String>,
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, Value>,
}

impl Capability {
    pub fn new(
        capability_id: impl Into<String>,
        resource: ResourceSelector,
        source: CapabilitySource,
    ) -> Result<Self, CapabilityError> {
        let capability_id = capability_id.into();
        validate_capability_id(&capability_id)?;
        let action_family = capability_id.clone();
        Ok(Self {
            schema_version: CAPABILITY_SCHEMA_VERSION.into(),
            taxonomy_version: TAXONOMY_VERSION.into(),
            capability_id,
            action_family,
            resource_selector: resource.normalized.clone(),
            resource: Some(resource),
            constraints: BTreeMap::new(),
            scope: None,
            source,
            confidence: None,
            evidence_refs: Vec::new(),
            risk_tags: BTreeSet::new(),
            extensions: BTreeMap::new(),
        })
    }

    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.schema_version != CAPABILITY_SCHEMA_VERSION {
            return Err(CapabilityError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        validate_capability_id(&self.capability_id)?;
        if self.action_family != self.capability_id {
            return Err(CapabilityError::ActionFamilyMismatch {
                capability_id: self.capability_id.clone(),
                action_family: self.action_family.clone(),
            });
        }
        if self.taxonomy_version != TAXONOMY_VERSION {
            return Err(CapabilityError::UnsupportedTaxonomyVersion(
                self.taxonomy_version.clone(),
            ));
        }
        if let Some(resource) = &self.resource {
            if self.resource_selector != resource.normalized {
                return Err(CapabilityError::ResourceSelectorMismatch {
                    selector: self.resource_selector.clone(),
                    normalized: resource.normalized.clone(),
                });
            }
        }
        if matches!(self.source, CapabilitySource::Inferred) {
            if self
                .confidence
                .is_some_and(|value| !(0.0..=1.0).contains(&value))
            {
                return Err(CapabilityError::InvalidInferenceConfidence);
            }
        } else if self.confidence.is_some() {
            return Err(CapabilityError::UnexpectedConfidence(self.source));
        }
        Ok(())
    }

    /// Match an already-normalized runtime resource against the canonical
    /// resource selector carried by this capability.
    pub fn matches_normalized_resource(&self, candidate: &str) -> bool {
        wildcard_match(&self.resource_selector, candidate)
    }

    pub fn fingerprint(&self) -> Result<String, CapabilityError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(CapabilityError::Serialize)?;
        Ok(hex_sha256(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDescriptor {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeAction {
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub normalized_args: Value,
    #[serde(default)]
    pub evidence_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub taxonomy_version: String,
    pub capabilities: Vec<Capability>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("unsupported capability schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("unsupported capability taxonomy version: {0}")]
    UnsupportedTaxonomyVersion(String),
    #[error("unknown capability id: {0}")]
    UnknownCapability(String),
    #[error("action family {action_family} does not match capability {capability_id}")]
    ActionFamilyMismatch {
        capability_id: String,
        action_family: String,
    },
    #[error("resource selector {selector} does not match normalized resource {normalized}")]
    ResourceSelectorMismatch {
        selector: String,
        normalized: String,
    },
    #[error("inferred capability confidence must be within 0.0..=1.0")]
    InvalidInferenceConfidence,
    #[error("confidence is only valid for inferred capabilities, got {0:?}")]
    UnexpectedConfidence(CapabilitySource),
    #[error("resource contains a NUL byte")]
    NulByte,
    #[error("path escapes its logical root via parent traversal: {0}")]
    ParentTraversal(String),
    #[error("network target is invalid: {0}")]
    InvalidNetworkTarget(String),
    #[error("network target must not contain credentials")]
    EmbeddedCredentials,
    #[error("serialization failed: {0}")]
    Serialize(serde_json::Error),
}

pub fn is_known_capability(value: &str) -> bool {
    TAXONOMY.contains(&value)
}

pub fn validate_capability_id(value: &str) -> Result<(), CapabilityError> {
    if is_known_capability(value) {
        Ok(())
    } else {
        Err(CapabilityError::UnknownCapability(value.to_string()))
    }
}

pub fn normalize_path_resource(input: &str) -> Result<String, CapabilityError> {
    if input.contains('\0') {
        return Err(CapabilityError::NulByte);
    }
    let replaced = input.trim().replace('\\', "/");
    let (prefix, rest) = split_path_prefix(&replaced);
    let mut parts = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(CapabilityError::ParentTraversal(input.to_string()));
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if prefix.is_empty() {
        Ok(if joined.is_empty() {
            ".".into()
        } else {
            joined
        })
    } else if joined.is_empty() {
        Ok(prefix)
    } else if prefix.ends_with('/') {
        Ok(format!("{prefix}{joined}"))
    } else {
        Ok(format!("{prefix}/{joined}"))
    }
}

fn split_path_prefix(path: &str) -> (String, &str) {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let rest = path[2..].strip_prefix('/').unwrap_or(&path[2..]);
        return (format!("{drive}:/"), rest);
    }
    if let Some(rest) = path.strip_prefix('/') {
        return ("/".into(), rest);
    }
    (String::new(), path)
}

pub fn normalize_network_target(input: &str) -> Result<String, CapabilityError> {
    if input.contains('\0') {
        return Err(CapabilityError::NulByte);
    }
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CapabilityError::InvalidNetworkTarget(input.to_string()));
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = Url::parse(&with_scheme)
        .map_err(|_| CapabilityError::InvalidNetworkTarget(input.to_string()))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CapabilityError::EmbeddedCredentials);
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| CapabilityError::InvalidNetworkTarget(input.to_string()))?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok(format!("{host}:{port}"))
}

pub fn canonicalize_resource(
    capability_id: &str,
    resource: &str,
) -> Result<ResourceSelector, CapabilityError> {
    validate_capability_id(capability_id)?;
    let (kind, normalized) =
        if capability_id.starts_with("fs.") || capability_id.starts_with("secret.") {
            (ResourceKind::Path, normalize_path_resource(resource)?)
        } else if capability_id.starts_with("network.") {
            (ResourceKind::Host, normalize_network_target(resource)?)
        } else if capability_id.starts_with("git.") {
            (ResourceKind::GitRef, resource.trim().replace('\\', "/"))
        } else if capability_id.starts_with("mcp.") {
            (ResourceKind::McpTool, resource.trim().to_string())
        } else if capability_id.starts_with("db.") {
            (ResourceKind::Database, resource.trim().to_string())
        } else if capability_id.starts_with("cloud.") {
            (ResourceKind::CloudResource, resource.trim().to_string())
        } else if capability_id.starts_with("browser.") {
            (ResourceKind::BrowserTarget, resource.trim().to_string())
        } else {
            (ResourceKind::Other, resource.trim().to_string())
        };
    Ok(ResourceSelector {
        kind,
        original: resource.to_string(),
        normalized,
    })
}

pub fn extract_declared_permissions<I, S>(
    permissions: I,
    evidence_ref: Option<&str>,
) -> ExtractionResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut capabilities = Vec::new();
    let mut diagnostics = Vec::new();
    for permission in permissions {
        let raw = permission.as_ref().trim();
        let id = match raw.to_ascii_lowercase().as_str() {
            "read" | "fs.read" | "filesystem:read" => Some("fs.read"),
            "write" | "fs.write" | "filesystem:write" => Some("fs.write"),
            "exec" | "shell" | "process.exec" | "command" => Some("process.exec"),
            "network" | "network.connect" | "http" => Some("network.connect"),
            "git.push" | "push" => Some("git.push"),
            "git.force_push" | "force-push" | "force_push" => Some("git.force_push"),
            "secret.read" | "secrets" => Some("secret.read"),
            "secret.egress" => Some("secret.egress"),
            "mcp.call" | "mcp" => Some("mcp.call"),
            "package.install" | "install" => Some("package.install"),
            "credential.use" | "credentials" => Some("credential.use"),
            _ => None,
        };
        match id {
            Some(id) => {
                let mut cap =
                    Capability::new(id, ResourceSelector::any(), CapabilitySource::Declared)
                        .expect("built-in taxonomy id");
                if let Some(reference) = evidence_ref {
                    cap.evidence_refs.push(reference.to_string());
                }
                capabilities.push(cap);
            }
            None => diagnostics.push(format!("UNKNOWN_DECLARED_PERMISSION:{raw}")),
        }
    }
    sort_and_dedup(&mut capabilities);
    ExtractionResult {
        taxonomy_version: TAXONOMY_VERSION.into(),
        capabilities,
        diagnostics,
    }
}

pub fn infer_tool_capabilities(tool: &ToolDescriptor) -> ExtractionResult {
    let schema = serde_json::to_string(&tool.input_schema).unwrap_or_default();
    let haystack = format!("{} {} {}", tool.name, tool.description, schema).to_ascii_lowercase();
    let mut hits: Vec<(&str, f32, &str)> = vec![("mcp.call", 0.99, "INFER_MCP_TOOL_PRESENT")];
    add_rule(
        &mut hits,
        &haystack,
        &["force push", "force_push", "--force"],
        "git.force_push",
        0.92,
        "INFER_GIT_FORCE_PUSH",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["git push", "push branch", "push commit"],
        "git.push",
        0.88,
        "INFER_GIT_PUSH",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["delete file", "remove file", "unlink", "delete_path"],
        "fs.delete",
        0.88,
        "INFER_FS_DELETE",
    );
    add_rule(
        &mut hits,
        &haystack,
        &[
            "write file",
            "edit file",
            "save file",
            "update file",
            "create file",
        ],
        "fs.write",
        0.82,
        "INFER_FS_WRITE",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["read file", "open file", "list files", "search files"],
        "fs.read",
        0.80,
        "INFER_FS_READ",
    );
    add_rule(
        &mut hits,
        &haystack,
        &[
            "shell",
            "execute command",
            "run command",
            "spawn process",
            "powershell",
            "bash",
        ],
        "process.exec",
        0.90,
        "INFER_PROCESS_EXEC",
    );
    add_rule(
        &mut hits,
        &haystack,
        &[
            "http://",
            "https://",
            "request url",
            "fetch url",
            "network",
            "webhook",
        ],
        "network.connect",
        0.75,
        "INFER_NETWORK_CONNECT",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["api key", "secret", "credential", "token", "ssh key"],
        "secret.read",
        0.58,
        "INFER_SECRET_SURFACE",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["upload", "send secret", "exfil", "egress"],
        "secret.egress",
        0.62,
        "INFER_SECRET_EGRESS",
    );
    add_rule(
        &mut hits,
        &haystack,
        &[
            "install package",
            "npm install",
            "pip install",
            "cargo install",
        ],
        "package.install",
        0.90,
        "INFER_PACKAGE_INSTALL",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["database write", "insert into", "update row", "delete row"],
        "db.write",
        0.84,
        "INFER_DB_WRITE",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["select query", "database read", "query database"],
        "db.read",
        0.76,
        "INFER_DB_READ",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["browser submit", "submit form"],
        "browser.submit",
        0.88,
        "INFER_BROWSER_SUBMIT",
    );
    add_rule(
        &mut hits,
        &haystack,
        &["browser navigate", "open webpage", "navigate url"],
        "browser.navigate",
        0.80,
        "INFER_BROWSER_NAVIGATE",
    );

    let resource = ResourceSelector::literal(ResourceKind::McpTool, tool.name.clone());
    let mut capabilities = Vec::new();
    for (id, confidence, rule) in hits {
        let mut cap = Capability::new(id, resource.clone(), CapabilitySource::Inferred)
            .expect("built-in inference taxonomy id");
        cap.confidence = Some(confidence);
        cap.evidence_refs.push(rule.to_string());
        if let Some(reference) = &tool.evidence_ref {
            cap.evidence_refs.push(reference.clone());
        }
        if matches!(
            id,
            "git.force_push" | "secret.egress" | "fs.delete" | "package.install"
        ) {
            cap.risk_tags.insert("high_impact".into());
        }
        capabilities.push(cap);
    }
    sort_and_dedup(&mut capabilities);
    ExtractionResult {
        taxonomy_version: TAXONOMY_VERSION.into(),
        capabilities,
        diagnostics: Vec::new(),
    }
}

pub fn capability_from_runtime_action(
    action: &RuntimeAction,
) -> Result<Capability, CapabilityError> {
    let id = normalize_runtime_action_name(&action.action)
        .ok_or_else(|| CapabilityError::UnknownCapability(action.action.clone()))?;
    let resource = canonicalize_resource(id, &action.resource)?;
    let mut cap = Capability::new(id, resource, CapabilitySource::Observed)?;
    if let Some(reference) = &action.evidence_ref {
        cap.evidence_refs.push(reference.clone());
    }
    if !action.normalized_args.is_null() {
        cap.constraints
            .insert("observed_args_present".into(), Value::Bool(true));
    }
    Ok(cap)
}

pub fn normalize_runtime_action_name(action: &str) -> Option<&'static str> {
    match action.trim().to_ascii_lowercase().as_str() {
        "read" | "fs.read" | "file.read" => Some("fs.read"),
        "write" | "fs.write" | "file.write" => Some("fs.write"),
        "create" | "fs.create" | "file.create" => Some("fs.create"),
        "delete" | "fs.delete" | "file.delete" => Some("fs.delete"),
        "rename" | "fs.rename" | "file.rename" => Some("fs.rename"),
        "exec" | "process.exec" | "shell.exec" => Some("process.exec"),
        "kill" | "process.kill" => Some("process.kill"),
        "network.connect" | "http.request" | "socket.connect" => Some("network.connect"),
        "network.listen" | "socket.listen" => Some("network.listen"),
        "git.read" => Some("git.read"),
        "git.commit" => Some("git.commit"),
        "git.reset" => Some("git.reset"),
        "git.checkout" => Some("git.checkout"),
        "git.push" => Some("git.push"),
        "git.force_push" | "git.push.force" => Some("git.force_push"),
        "secret.read" => Some("secret.read"),
        "secret.egress" => Some("secret.egress"),
        "mcp.list" | "tools/list" => Some("mcp.list"),
        "mcp.call" | "tools/call" => Some("mcp.call"),
        "db.read" => Some("db.read"),
        "db.write" => Some("db.write"),
        "db.schema" => Some("db.schema"),
        "cloud.read" => Some("cloud.read"),
        "cloud.mutate" => Some("cloud.mutate"),
        "browser.navigate" => Some("browser.navigate"),
        "browser.download" => Some("browser.download"),
        "browser.upload" => Some("browser.upload"),
        "browser.submit" => Some("browser.submit"),
        "money.spend" => Some("money.spend"),
        "identity.act_as" => Some("identity.act_as"),
        "package.install" => Some("package.install"),
        "credential.use" => Some("credential.use"),
        _ => None,
    }
}

fn add_rule<'a>(
    hits: &mut Vec<(&'a str, f32, &'a str)>,
    haystack: &str,
    needles: &[&str],
    capability: &'a str,
    confidence: f32,
    rule: &'a str,
) {
    if needles.iter().any(|needle| haystack.contains(needle)) {
        hits.push((capability, confidence, rule));
    }
}

fn sort_and_dedup(capabilities: &mut Vec<Capability>) {
    capabilities.sort_by(|a, b| {
        (&a.capability_id, &a.resource_selector, a.source).cmp(&(
            &b.capability_id,
            &b.resource_selector,
            b.source,
        ))
    });
    capabilities.dedup_by(|a, b| {
        a.capability_id == b.capability_id
            && a.resource_selector == b.resource_selector
            && a.source == b.source
    });
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return candidate == prefix || candidate.starts_with(&format!("{prefix}/"));
    }
    if !pattern.contains('*') {
        return pattern == candidate;
    }
    let starts_wild = pattern.starts_with('*');
    let mut remaining = candidate;
    let mut first = true;
    for part in pattern.split('*').filter(|p| !p.is_empty()) {
        match remaining.find(part) {
            Some(index) if !first || starts_wild || index == 0 => {
                remaining = &remaining[index + part.len()..]
            }
            _ => return false,
        }
        first = false;
    }
    pattern.ends_with('*') || remaining.is_empty()
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_contains_high_risk_actions_and_rejects_unknown() {
        for id in [
            "git.force_push",
            "secret.egress",
            "package.install",
            "money.spend",
        ] {
            assert!(is_known_capability(id));
        }
        assert!(!is_known_capability("magic.root"));
    }

    #[test]
    fn path_normalization_is_cross_platform_and_rejects_escape() {
        assert_eq!(
            normalize_path_resource(r"c:\repo\src\.\lib.rs").unwrap(),
            "C:/repo/src/lib.rs"
        );
        assert_eq!(normalize_path_resource("repo/a/../b").unwrap(), "repo/b");
        assert!(matches!(
            normalize_path_resource("../outside"),
            Err(CapabilityError::ParentTraversal(_))
        ));
    }

    #[test]
    fn unicode_domain_is_idna_normalized_and_credentials_rejected() {
        assert_eq!(
            normalize_network_target("https://bücher.example/path").unwrap(),
            "xn--bcher-kva.example:443"
        );
        assert!(matches!(
            normalize_network_target("https://u:p@example.com"),
            Err(CapabilityError::EmbeddedCredentials)
        ));
    }

    #[test]
    fn inference_never_promotes_to_observed() {
        let result = infer_tool_capabilities(&ToolDescriptor {
            name: "dangerous_writer".into(),
            description: "write file and git push; may execute command".into(),
            input_schema: serde_json::json!({"type":"object"}),
            transport: Some("stdio".into()),
            evidence_ref: Some("tool-schema:sha256:abc".into()),
        });
        assert!(result
            .capabilities
            .iter()
            .any(|c| c.capability_id == "fs.write"));
        assert!(result
            .capabilities
            .iter()
            .any(|c| c.capability_id == "git.push"));
        assert!(result
            .capabilities
            .iter()
            .all(|c| c.source == CapabilitySource::Inferred));
        assert!(result.capabilities.iter().all(|c| c.confidence.is_some()));
    }

    #[test]
    fn runtime_action_is_observed_without_confidence() {
        let cap = capability_from_runtime_action(&RuntimeAction {
            action: "git.push.force".into(),
            resource: "origin/main".into(),
            normalized_args: Value::Null,
            evidence_ref: Some("event:42".into()),
        })
        .unwrap();
        assert_eq!(cap.capability_id, "git.force_push");
        assert_eq!(cap.source, CapabilitySource::Observed);
        assert_eq!(cap.confidence, None);
    }

    #[test]
    fn declared_unknown_permission_stays_diagnostic() {
        let result = extract_declared_permissions(["read", "teleport"], Some("config:1"));
        assert_eq!(result.capabilities.len(), 1);
        assert_eq!(
            result.diagnostics,
            vec!["UNKNOWN_DECLARED_PERMISSION:teleport"]
        );
    }

    #[test]
    fn canonical_wire_shape_deserializes_and_validates() {
        let cap: Capability = serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "capability_id": "network.connect",
            "action_family": "network.connect",
            "resource_selector": "github.com:443",
            "constraints": {"tls": true},
            "source": "inferred",
            "evidence_refs": ["artifact:skill:review"],
            "risk_tags": ["network"]
        }))
        .unwrap();
        assert_eq!(cap.taxonomy_version, TAXONOMY_VERSION);
        assert!(cap.resource.is_none());
        assert_eq!(cap.resource_selector, "github.com:443");
        cap.validate().unwrap();
    }

    #[test]
    fn rich_resource_drift_is_rejected_before_fingerprint() {
        let mut cap = Capability::new(
            "fs.read",
            ResourceSelector::literal(ResourceKind::Path, "C:/repo/**"),
            CapabilitySource::Declared,
        )
        .unwrap();
        cap.resource.as_mut().unwrap().normalized = "C:/other/**".into();
        assert!(matches!(
            cap.fingerprint(),
            Err(CapabilityError::ResourceSelectorMismatch { .. })
        ));
    }

    #[test]
    fn selector_matching_and_fingerprint_are_deterministic() {
        let selector = ResourceSelector::literal(ResourceKind::Path, "C:/repo/**");
        assert!(selector.matches("C:/repo/src/lib.rs"));
        assert!(!selector.matches("C:/other/lib.rs"));
        assert!(ResourceSelector::literal(ResourceKind::McpTool, "git.*").matches("git.push"));
        let mut cap = Capability::new(
            "fs.read",
            ResourceSelector::any(),
            CapabilitySource::Declared,
        )
        .unwrap();
        cap.constraints.insert("b".into(), Value::Bool(true));
        cap.constraints
            .insert("a".into(), Value::String("x".into()));
        assert_eq!(cap.fingerprint().unwrap(), cap.fingerprint().unwrap());
        assert_eq!(cap.fingerprint().unwrap().len(), 64);
    }
}
