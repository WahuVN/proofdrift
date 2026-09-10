use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GitInspectError {
    #[error("git command failed: {0}")]
    Git(String),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

fn git(repo: &Path, args: &[&str]) -> Result<String, GitInspectError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| GitInspectError::Git(e.to_string()))?;
    if !output.status.success() {
        return Err(GitInspectError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn inspect_repository(repo: &Path) -> Result<ProvenanceGraph, GitInspectError> {
    let root = git(repo, &["rev-parse", "--show-toplevel"])?;
    let commit = git(repo, &["rev-parse", "HEAD"])?;
    let branch = git(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let remote = git(repo, &["config", "--get", "remote.origin.url"])
        .ok()
        .filter(|s| !s.is_empty());
    let repo_anchor = remote
        .as_deref()
        .map(normalize_remote)
        .unwrap_or_else(|| format!("local:{}", super::sha256_prefixed(root.as_bytes())));
    let repo_id = format!("git:repo:{repo_anchor}");
    let commit_id = format!("git:commit:{}", commit.to_ascii_lowercase());
    let sanitized_remote = remote.as_deref().map(super::sanitize_source_uri);

    let mut repo_node = ArtifactIdentity::new(
        &repo_id,
        ArtifactType::Repo,
        repo.file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("repository"),
    );
    repo_node.source_uri = sanitized_remote.clone();
    repo_node.local_path = Some(root);
    repo_node.resolved_revision = Some(branch);
    repo_node.provenance_status = ProvenanceStatus::Inferred;

    let mut commit_node = ArtifactIdentity::new(&commit_id, ArtifactType::Commit, &commit);
    commit_node.source_uri = sanitized_remote;
    commit_node.resolved_revision = Some(commit.clone());
    commit_node.content_digest = Some(format!("git:{}", commit.to_ascii_lowercase()));
    commit_node.provenance_status = ProvenanceStatus::Verified;

    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(repo_node)?;
    graph.add_artifact(commit_node)?;
    graph.add_edge(ProvenanceEdge {
        from_artifact_id: repo_id,
        relation: ProvenanceRelation::Includes,
        to_artifact_id: commit_id,
        evidence_kind: EvidenceKind::Observed,
        source: "git-local".into(),
        verified: true,
        confidence: None,
    })?;
    Ok(graph)
}

pub fn normalize_remote(input: &str) -> String {
    let mut s = super::sanitize_source_uri(input).replace('\\', "/");
    if let Some(rest) = s.strip_prefix("git@") {
        if let Some((host, path)) = rest.split_once(':') {
            s = format!("https://{host}/{path}");
        }
    }
    if let Some(rest) = s.strip_prefix("ssh://git@") {
        s = format!("https://{rest}");
    }
    while s.ends_with('/') {
        s.pop();
    }
    if s.to_ascii_lowercase().ends_with(".git") {
        s.truncate(s.len() - 4);
    }
    s.to_ascii_lowercase()
}
