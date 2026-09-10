use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GithubError {
    #[error("recorded GitHub json exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("invalid recorded GitHub json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

#[derive(Debug, Deserialize)]
struct Repo {
    full_name: String,
    html_url: String,
    #[serde(default)]
    default_branch: Option<String>,
    #[serde(default)]
    license: Option<License>,
}
#[derive(Debug, Deserialize)]
struct License {
    #[serde(default)]
    spdx_id: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Commit {
    sha: String,
}
#[derive(Debug, Deserialize)]
struct Snapshot {
    repository: Repo,
    #[serde(default)]
    commit: Option<Commit>,
}

pub fn ingest_recorded_json(json: &str) -> Result<ProvenanceGraph, GithubError> {
    if json.len() > super::MAX_RECORDED_JSON_BYTES {
        return Err(GithubError::InputTooLarge(super::MAX_RECORDED_JSON_BYTES));
    }
    let input: Snapshot = serde_json::from_str(json)?;
    let repo_id = format!(
        "github:repo:{}",
        input.repository.full_name.to_ascii_lowercase()
    );
    let mut repo = ArtifactIdentity::new(&repo_id, ArtifactType::Repo, &input.repository.full_name);
    repo.source_uri = Some(super::sanitize_source_uri(&input.repository.html_url));
    repo.resolved_revision = input.repository.default_branch;
    repo.provenance_status = ProvenanceStatus::Declared;
    if let Some(spdx) = input.repository.license.and_then(|l| l.spdx_id) {
        repo.metadata.insert("license".into(), spdx.into());
    }
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(repo)?;
    if let Some(commit) = input.commit {
        let commit_id = format!("git:commit:{}", commit.sha.to_ascii_lowercase());
        let mut node = ArtifactIdentity::new(&commit_id, ArtifactType::Commit, &commit.sha);
        node.source_uri = graph
            .artifacts
            .get(&repo_id)
            .and_then(|r| r.source_uri.clone());
        node.resolved_revision = Some(commit.sha.clone());
        node.content_digest = Some(format!("git:{}", commit.sha.to_ascii_lowercase()));
        node.provenance_status = ProvenanceStatus::Declared;
        graph.add_artifact(node)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: repo_id,
            relation: ProvenanceRelation::Includes,
            to_artifact_id: commit_id,
            evidence_kind: EvidenceKind::External,
            source: "github-api-recording".into(),
            verified: false,
            confidence: None,
        })?;
    }
    Ok(graph)
}
