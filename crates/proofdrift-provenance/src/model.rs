use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Repo,
    Commit,
    File,
    Skill,
    Hook,
    Agent,
    Plugin,
    McpServer,
    Model,
    Dataset,
    Binary,
    Container,
    Package,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    Verified,
    Declared,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Observed,
    Derived,
    Declared,
    External,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    pub provenance_status: ProvenanceStatus,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

impl ArtifactIdentity {
    pub fn new(
        artifact_id: impl Into<String>,
        artifact_type: ArtifactType,
        name: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            artifact_id: artifact_id.into(),
            artifact_type,
            name: name.into(),
            version: None,
            source_uri: None,
            resolved_revision: None,
            content_digest: None,
            local_path: None,
            provenance_status: ProvenanceStatus::Unknown,
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRelation {
    Includes,
    Loads,
    Invokes,
    DependsOn,
    BuiltFrom,
    DerivedFrom,
    TrainedOn,
    FineTunedFrom,
    MergedFrom,
    QuantizedFrom,
    ProducedBy,
    VerifiedBy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceEdge {
    pub from_artifact_id: String,
    pub relation: ProvenanceRelation,
    pub to_artifact_id: String,
    pub evidence_kind: EvidenceKind,
    pub source: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl ProvenanceEdge {
    pub fn key(&self) -> String {
        format!(
            "{}|{:?}|{}|{}",
            self.from_artifact_id, self.relation, self.to_artifact_id, self.source
        )
    }
}
