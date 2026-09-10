use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use serde_yaml::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApmLockError {
    #[error("APM lockfile exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("invalid yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unsupported APM lockfile version {0}; supported versions: 1, 2")]
    UnsupportedVersion(String),
    #[error("lockfile root must be a mapping")]
    Root,
    #[error("dependencies must be a sequence")]
    Dependencies,
    #[error("dependency at index {0} must be a mapping with name/repo_url")]
    Dependency(usize),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

fn scalar(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(Value::String(key.into()))
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub fn ingest_apm_lock(
    yaml: &str,
    owner: ArtifactIdentity,
) -> Result<ProvenanceGraph, ApmLockError> {
    if yaml.len() > super::MAX_LOCKFILE_BYTES {
        return Err(ApmLockError::InputTooLarge(super::MAX_LOCKFILE_BYTES));
    }
    let root: Value = serde_yaml::from_str(yaml)?;
    let map = root.as_mapping().ok_or(ApmLockError::Root)?;
    let version = scalar(map, "lockfile_version").unwrap_or_else(|| "1".into());
    if version != "1" && version != "2" {
        return Err(ApmLockError::UnsupportedVersion(version));
    }
    let deps = map
        .get(Value::String("dependencies".into()))
        .and_then(Value::as_sequence)
        .ok_or(ApmLockError::Dependencies)?;
    let owner_id = owner.artifact_id.clone();
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(owner)?;
    for (i, dep) in deps.iter().enumerate() {
        let row = dep.as_mapping().ok_or(ApmLockError::Dependency(i))?;
        let name = scalar(row, "name")
            .or_else(|| scalar(row, "repo_url"))
            .ok_or(ApmLockError::Dependency(i))?;
        let repo = scalar(row, "repo_url");
        let version = scalar(row, "version");
        let revision = scalar(row, "resolved_commit").or_else(|| scalar(row, "resolved_ref"));
        let digest = scalar(row, "content_hash").or_else(|| scalar(row, "source_digest"));
        let id_anchor = repo
            .as_deref()
            .map(super::sanitize_source_uri)
            .unwrap_or_else(|| name.clone());
        let artifact_id = format!("apm:package:{}", id_anchor.trim().to_ascii_lowercase());
        let mut artifact = ArtifactIdentity::new(&artifact_id, ArtifactType::Package, name);
        artifact.version = version;
        artifact.source_uri = repo.as_deref().map(super::sanitize_source_uri);
        artifact.resolved_revision = revision;
        artifact.content_digest = digest.map(|d| {
            if d.starts_with("sha256:") {
                d
            } else {
                format!("sha256:{d}")
            }
        });
        artifact.provenance_status = ProvenanceStatus::Declared;
        if let Some(license) = scalar(row, "declared_license") {
            artifact.metadata.insert("license".into(), license.into());
        }
        if let Some(source) = scalar(row, "source") {
            artifact.metadata.insert("apm_source".into(), source.into());
        }
        graph.add_artifact(artifact)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: owner_id.clone(),
            relation: ProvenanceRelation::DependsOn,
            to_artifact_id: artifact_id,
            evidence_kind: EvidenceKind::Declared,
            source: "apm.lock.yaml".into(),
            verified: false,
            confidence: None,
        })?;
    }
    Ok(graph)
}
