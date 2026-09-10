use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NpmLockError {
    #[error("package-lock.json exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("invalid package-lock.json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported package-lock version {0}; supported: 1, 2, 3")]
    UnsupportedVersion(u64),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

#[derive(Debug, Deserialize)]
struct PackageLock {
    #[serde(rename = "lockfileVersion")]
    lockfile_version: u64,
    #[serde(default)]
    packages: BTreeMap<String, PackageRow>,
    #[serde(default)]
    dependencies: BTreeMap<String, LegacyDependency>,
}

#[derive(Debug, Deserialize)]
struct PackageRow {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    dev: bool,
}

#[derive(Debug, Deserialize)]
struct LegacyDependency {
    version: String,
    #[serde(default)]
    resolved: Option<String>,
    #[serde(default)]
    integrity: Option<String>,
    #[serde(default)]
    dev: bool,
}

fn integrity_digest(raw: Option<String>) -> Option<String> {
    raw.map(|v| format!("sri:{v}"))
}

fn npm_name_from_path(path: &str) -> Option<String> {
    let marker = "node_modules/";
    let idx = path.rfind(marker)?;
    let name = &path[idx + marker.len()..];
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

pub fn ingest_package_lock(
    json: &str,
    owner: ArtifactIdentity,
) -> Result<ProvenanceGraph, NpmLockError> {
    if json.len() > super::MAX_LOCKFILE_BYTES {
        return Err(NpmLockError::InputTooLarge(super::MAX_LOCKFILE_BYTES));
    }
    let lock: PackageLock = serde_json::from_str(json)?;
    if !(1..=3).contains(&lock.lockfile_version) {
        return Err(NpmLockError::UnsupportedVersion(lock.lockfile_version));
    }
    let owner_id = owner.artifact_id.clone();
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(owner)?;

    if lock.lockfile_version >= 2 && !lock.packages.is_empty() {
        for (path, row) in lock.packages {
            if path.is_empty() {
                continue;
            }
            let Some(name) = npm_name_from_path(&path) else {
                continue;
            };
            let version = row.version.unwrap_or_else(|| "unknown".into());
            let id = format!("npm:package:{}@{}", name.to_ascii_lowercase(), version);
            let mut node = ArtifactIdentity::new(&id, ArtifactType::Package, name);
            node.version = Some(version);
            node.source_uri = row.resolved.as_deref().map(super::sanitize_source_uri);
            node.content_digest = integrity_digest(row.integrity);
            node.provenance_status = ProvenanceStatus::Declared;
            if let Some(license) = row.license {
                node.metadata.insert("license".into(), license.into());
            }
            if row.dev {
                node.metadata.insert("dev".into(), true.into());
            }
            graph.add_artifact(node)?;
            graph.add_edge(ProvenanceEdge {
                from_artifact_id: owner_id.clone(),
                relation: ProvenanceRelation::DependsOn,
                to_artifact_id: id,
                evidence_kind: EvidenceKind::Declared,
                source: "package-lock.json".into(),
                verified: false,
                confidence: None,
            })?;
        }
    } else {
        for (name, row) in lock.dependencies {
            let id = format!("npm:package:{}@{}", name.to_ascii_lowercase(), row.version);
            let mut node = ArtifactIdentity::new(&id, ArtifactType::Package, name);
            node.version = Some(row.version);
            node.source_uri = row.resolved.as_deref().map(super::sanitize_source_uri);
            node.content_digest = integrity_digest(row.integrity);
            node.provenance_status = ProvenanceStatus::Declared;
            if row.dev {
                node.metadata.insert("dev".into(), true.into());
            }
            graph.add_artifact(node)?;
            graph.add_edge(ProvenanceEdge {
                from_artifact_id: owner_id.clone(),
                relation: ProvenanceRelation::DependsOn,
                to_artifact_id: id,
                evidence_kind: EvidenceKind::Declared,
                source: "package-lock.json".into(),
                verified: false,
                confidence: None,
            })?;
        }
    }
    Ok(graph)
}
