use crate::model::ArtifactIdentity;
use crate::ProvenanceGraph;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftKind {
    ArtifactAdded,
    ArtifactRemoved,
    SourceRefDrift,
    HashDrift,
    LicenseMetadataDrift,
    ToolSchemaDrift,
    LineageDrift,
    EdgeAdded,
    EdgeRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProvenanceDrift {
    pub artifact_id: String,
    pub kind: DriftKind,
    pub before: Option<String>,
    pub after: Option<String>,
}

fn text(v: Option<&serde_json::Value>) -> Option<String> {
    v.map(|x| match x {
        serde_json::Value::String(s) => s.clone(),
        _ => x.to_string(),
    })
}

fn compare_field(
    out: &mut Vec<ProvenanceDrift>,
    id: &str,
    kind: DriftKind,
    before: Option<String>,
    after: Option<String>,
) {
    if before != after {
        out.push(ProvenanceDrift {
            artifact_id: id.to_string(),
            kind,
            before,
            after,
        });
    }
}

fn source_ref(a: &ArtifactIdentity) -> Option<String> {
    if a.source_uri.is_none() && a.resolved_revision.is_none() && a.version.is_none() {
        return None;
    }
    Some(format!(
        "source={};revision={};version={}",
        a.source_uri.as_deref().unwrap_or(""),
        a.resolved_revision.as_deref().unwrap_or(""),
        a.version.as_deref().unwrap_or("")
    ))
}

fn compare_artifact(
    out: &mut Vec<ProvenanceDrift>,
    before: &ArtifactIdentity,
    after: &ArtifactIdentity,
) {
    compare_field(
        out,
        &before.artifact_id,
        DriftKind::SourceRefDrift,
        source_ref(before),
        source_ref(after),
    );
    compare_field(
        out,
        &before.artifact_id,
        DriftKind::HashDrift,
        before.content_digest.clone(),
        after.content_digest.clone(),
    );
    compare_field(
        out,
        &before.artifact_id,
        DriftKind::LicenseMetadataDrift,
        text(before.metadata.get("license")),
        text(after.metadata.get("license")),
    );
    compare_field(
        out,
        &before.artifact_id,
        DriftKind::ToolSchemaDrift,
        text(before.metadata.get("tool_schema_digest")),
        text(after.metadata.get("tool_schema_digest")),
    );
    compare_field(
        out,
        &before.artifact_id,
        DriftKind::LineageDrift,
        text(before.metadata.get("lineage")),
        text(after.metadata.get("lineage")),
    );
}

pub fn detect_drift(baseline: &ProvenanceGraph, current: &ProvenanceGraph) -> Vec<ProvenanceDrift> {
    let ids: BTreeSet<_> = baseline
        .artifacts
        .keys()
        .chain(current.artifacts.keys())
        .cloned()
        .collect();
    let mut out = Vec::new();
    for id in ids {
        match (baseline.artifacts.get(&id), current.artifacts.get(&id)) {
            (None, Some(_)) => out.push(ProvenanceDrift {
                artifact_id: id,
                kind: DriftKind::ArtifactAdded,
                before: None,
                after: Some("present".into()),
            }),
            (Some(_), None) => out.push(ProvenanceDrift {
                artifact_id: id,
                kind: DriftKind::ArtifactRemoved,
                before: Some("present".into()),
                after: None,
            }),
            (Some(b), Some(c)) => compare_artifact(&mut out, b, c),
            (None, None) => unreachable!(),
        }
    }
    let before_edges: BTreeMap<_, _> = baseline.edges.iter().map(|e| (e.key(), e)).collect();
    let after_edges: BTreeMap<_, _> = current.edges.iter().map(|e| (e.key(), e)).collect();
    let edge_keys: BTreeSet<_> = before_edges
        .keys()
        .chain(after_edges.keys())
        .cloned()
        .collect();
    for key in edge_keys {
        match (before_edges.get(&key), after_edges.get(&key)) {
            (None, Some(_)) => out.push(ProvenanceDrift {
                artifact_id: key,
                kind: DriftKind::EdgeAdded,
                before: None,
                after: Some("present".into()),
            }),
            (Some(_), None) => out.push(ProvenanceDrift {
                artifact_id: key,
                kind: DriftKind::EdgeRemoved,
                before: Some("present".into()),
                after: None,
            }),
            _ => {}
        }
    }
    out.sort();
    out
}
