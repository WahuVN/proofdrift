use super::sha256_prefixed;
use crate::{ArtifactIdentity, ArtifactType, GraphError, ProvenanceGraph, ProvenanceStatus};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("recorded MCP registry json exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("recorded MCP registry exceeds {0} tools")]
    TooManyTools(usize),
    #[error("invalid recorded MCP registry json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    tools: Vec<serde_json::Value>,
}

pub fn ingest_recorded_registry_json(json: &str) -> Result<ProvenanceGraph, McpError> {
    if json.len() > super::MAX_RECORDED_JSON_BYTES {
        return Err(McpError::InputTooLarge(super::MAX_RECORDED_JSON_BYTES));
    }
    let record: Record = serde_json::from_str(json)?;
    if record.tools.len() > super::MAX_RECORDED_ITEMS {
        return Err(McpError::TooManyTools(super::MAX_RECORDED_ITEMS));
    }
    let id = format!("mcp:server:{}", record.name.to_ascii_lowercase());
    let mut node = ArtifactIdentity::new(&id, ArtifactType::McpServer, record.name);
    node.version = record.version;
    node.source_uri = record.source.as_deref().map(super::sanitize_source_uri);
    node.provenance_status = ProvenanceStatus::Declared;
    if let Some(t) = record.transport {
        node.metadata.insert("transport".into(), t.into());
    }
    let canonical_tools = super::canonical_tools_json(&record.tools)?;
    node.metadata.insert(
        "tool_schema_digest".into(),
        sha256_prefixed(&canonical_tools).into(),
    );
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(node)?;
    Ok(graph)
}
