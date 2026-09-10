use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CargoLockError {
    #[error("Cargo.lock exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("invalid Cargo.lock TOML subset: {0}")]
    Parse(String),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

/// Minimal deterministic parser for Cargo.lock package blocks. It intentionally recognizes only
/// provenance-relevant scalar fields and fails closed on malformed package records.
pub fn ingest_cargo_lock(
    text: &str,
    owner: ArtifactIdentity,
) -> Result<ProvenanceGraph, CargoLockError> {
    if text.len() > super::MAX_LOCKFILE_BYTES {
        return Err(CargoLockError::InputTooLarge(super::MAX_LOCKFILE_BYTES));
    }
    let mut graph = ProvenanceGraph::default();
    let owner_id = owner.artifact_id.clone();
    graph.add_artifact(owner)?;
    let mut current: Option<(String, String, Option<String>, Option<String>)> = None;
    let flush = |row: Option<(String, String, Option<String>, Option<String>)>,
                 graph: &mut ProvenanceGraph|
     -> Result<(), CargoLockError> {
        if let Some((name, version, source, checksum)) = row {
            let source_clean = source.as_deref().map(super::sanitize_source_uri);
            let id = format!("cargo:package:{}@{}", name.to_ascii_lowercase(), version);
            let mut node = ArtifactIdentity::new(&id, ArtifactType::Package, name);
            node.version = Some(version);
            node.source_uri = source_clean;
            node.content_digest = checksum.map(|v| format!("sha256:{v}"));
            node.provenance_status = ProvenanceStatus::Declared;
            graph.add_artifact(node)?;
            graph.add_edge(ProvenanceEdge {
                from_artifact_id: owner_id.clone(),
                relation: ProvenanceRelation::DependsOn,
                to_artifact_id: id,
                evidence_kind: EvidenceKind::Declared,
                source: "Cargo.lock".into(),
                verified: false,
                confidence: None,
            })?;
        }
        Ok(())
    };
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(current.take(), &mut graph)?;
            current = Some((String::new(), String::new(), None, None));
            continue;
        }
        let Some(row) = current.as_mut() else {
            continue;
        };
        if let Some((k, v)) = t.split_once('=') {
            let value = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "name" => row.0 = value,
                "version" => row.1 = value,
                "source" => row.2 = Some(value),
                "checksum" => row.3 = Some(value),
                _ => {}
            }
        }
    }
    flush(current, &mut graph)?;
    if graph.artifacts.values().any(|a| {
        a.artifact_id.starts_with("cargo:package:")
            && (a.name.is_empty() || a.version.as_deref() == Some(""))
    }) {
        return Err(CargoLockError::Parse("package missing name/version".into()));
    }
    Ok(graph)
}
