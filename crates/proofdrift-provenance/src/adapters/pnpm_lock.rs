use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use serde_yaml::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PnpmLockError {
    #[error("pnpm-lock.yaml exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("invalid pnpm-lock.yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("pnpm lockfile root must be a mapping")]
    Root,
    #[error("unsupported pnpm lockfile version {0}")]
    UnsupportedVersion(String),
    #[error("pnpm lockfile has more than {0} package records")]
    TooManyPackages(usize),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

fn scalar(value: Option<&Value>) -> Option<String> {
    value.and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn map_get<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn parse_package_key(raw: &str, row: &serde_yaml::Mapping) -> Option<(String, String)> {
    let raw = raw.trim_start_matches('/');
    if let (Some(name), Some(version)) = (
        scalar(map_get(row, "name")),
        scalar(map_get(row, "version")),
    ) {
        return Some((name, version));
    }

    let no_peer = raw.split('(').next().unwrap_or(raw);
    if no_peer.starts_with('@') {
        let idx = no_peer.rfind('@')?;
        if idx == 0 {
            return None;
        }
        return Some((no_peer[..idx].to_string(), no_peer[idx + 1..].to_string()));
    }
    let idx = no_peer.rfind('@')?;
    Some((no_peer[..idx].to_string(), no_peer[idx + 1..].to_string()))
}

pub fn ingest_pnpm_lock(
    yaml: &str,
    owner: ArtifactIdentity,
) -> Result<ProvenanceGraph, PnpmLockError> {
    if yaml.len() > super::MAX_LOCKFILE_BYTES {
        return Err(PnpmLockError::InputTooLarge(super::MAX_LOCKFILE_BYTES));
    }
    let root: Value = serde_yaml::from_str(yaml)?;
    let root = root.as_mapping().ok_or(PnpmLockError::Root)?;
    let version = scalar(map_get(root, "lockfileVersion")).unwrap_or_else(|| "unknown".into());
    let major = version
        .trim_matches('\'')
        .split('.')
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if !(5..=9).contains(&major) {
        return Err(PnpmLockError::UnsupportedVersion(version));
    }

    let owner_id = owner.artifact_id.clone();
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(owner)?;
    let Some(packages) = map_get(root, "packages").and_then(Value::as_mapping) else {
        return Ok(graph);
    };
    if packages.len() > super::MAX_RECORDED_ITEMS {
        return Err(PnpmLockError::TooManyPackages(super::MAX_RECORDED_ITEMS));
    }

    for (key, value) in packages {
        let Some(raw_key) = key.as_str() else {
            continue;
        };
        let Some(row) = value.as_mapping() else {
            continue;
        };
        let Some((name, version)) = parse_package_key(raw_key, row) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        let id = format!("pnpm:package:{}@{}", name.to_ascii_lowercase(), version);
        let mut node = ArtifactIdentity::new(&id, ArtifactType::Package, name);
        node.version = Some(version);
        node.provenance_status = ProvenanceStatus::Declared;

        if let Some(resolution) = map_get(row, "resolution").and_then(Value::as_mapping) {
            if let Some(integrity) = scalar(map_get(resolution, "integrity")) {
                node.content_digest = Some(format!("sri:{integrity}"));
            }
            if let Some(tarball) = scalar(map_get(resolution, "tarball")) {
                node.source_uri = Some(super::sanitize_source_uri(&tarball));
            }
        }
        if let Some(dev) = map_get(row, "dev").and_then(Value::as_bool) {
            if dev {
                node.metadata.insert("dev".into(), true.into());
            }
        }
        graph.add_artifact(node)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: owner_id.clone(),
            relation: ProvenanceRelation::DependsOn,
            to_artifact_id: id,
            evidence_kind: EvidenceKind::Declared,
            source: "pnpm-lock.yaml".into(),
            verified: false,
            confidence: None,
        })?;
    }
    Ok(graph)
}
