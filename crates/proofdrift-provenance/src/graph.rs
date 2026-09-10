use crate::model::{ArtifactIdentity, ProvenanceEdge, ProvenanceRelation, SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GraphError {
    #[error("artifact id must not be empty")]
    EmptyArtifactId,
    #[error("edge references missing artifact: {0}")]
    MissingArtifact(String),
    #[error("artifact id collision with different content: {0}")]
    ArtifactCollision(String),
    #[error("invalid edge confidence {0}; expected 0..=1")]
    InvalidConfidence(String),
    #[error("json serialization failed: {0}")]
    Json(String),
    #[error("unsupported provenance graph schema version: {0}")]
    UnsupportedSchema(String),
    #[error("artifact {artifact_id} has schema {found}; expected {expected}")]
    ArtifactSchemaMismatch {
        artifact_id: String,
        found: String,
        expected: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceGraph {
    pub schema_version: String,
    pub artifacts: BTreeMap<String, ArtifactIdentity>,
    pub edges: Vec<ProvenanceEdge>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenancePath {
    pub artifact_ids: Vec<String>,
    pub relations: Vec<ProvenanceRelation>,
    pub fully_verified: bool,
}

impl Default for ProvenanceGraph {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            artifacts: BTreeMap::new(),
            edges: Vec::new(),
        }
    }
}

impl ProvenanceGraph {
    pub fn add_artifact(&mut self, artifact: ArtifactIdentity) -> Result<(), GraphError> {
        if artifact.artifact_id.trim().is_empty() {
            return Err(GraphError::EmptyArtifactId);
        }
        if let Some(existing) = self.artifacts.get(&artifact.artifact_id) {
            if existing != &artifact {
                return Err(GraphError::ArtifactCollision(artifact.artifact_id));
            }
            return Ok(());
        }
        self.artifacts
            .insert(artifact.artifact_id.clone(), artifact);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: ProvenanceEdge) -> Result<(), GraphError> {
        for id in [&edge.from_artifact_id, &edge.to_artifact_id] {
            if !self.artifacts.contains_key(id) {
                return Err(GraphError::MissingArtifact(id.clone()));
            }
        }
        if let Some(c) = edge.confidence {
            if !(0.0..=1.0).contains(&c) || c.is_nan() {
                return Err(GraphError::InvalidConfidence(c.to_string()));
            }
        }
        let key = edge.key();
        match self
            .edges
            .binary_search_by(|existing| existing.key().cmp(&key))
        {
            Ok(_) => Ok(()),
            Err(index) => {
                self.edges.insert(index, edge);
                Ok(())
            }
        }
    }

    pub fn merge(&mut self, other: ProvenanceGraph) -> Result<(), GraphError> {
        for node in other.artifacts.into_values() {
            self.add_artifact(node)?;
        }
        for edge in other.edges {
            self.add_edge(edge)?;
        }
        Ok(())
    }

    pub fn to_json_pretty(&self) -> Result<String, GraphError> {
        serde_json::to_string_pretty(self).map_err(|e| GraphError::Json(e.to_string()))
    }

    /// Parses persisted or untrusted graph JSON and re-validates schema and edge invariants.
    pub fn from_json_strict(json: &str) -> Result<Self, GraphError> {
        let raw: Self = serde_json::from_str(json).map_err(|e| GraphError::Json(e.to_string()))?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(GraphError::UnsupportedSchema(raw.schema_version));
        }
        let mut validated = Self::default();
        for artifact in raw.artifacts.into_values() {
            if artifact.schema_version != SCHEMA_VERSION {
                return Err(GraphError::ArtifactSchemaMismatch {
                    artifact_id: artifact.artifact_id,
                    found: artifact.schema_version,
                    expected: SCHEMA_VERSION.to_string(),
                });
            }
            validated.add_artifact(artifact)?;
        }
        for edge in raw.edges {
            validated.add_edge(edge)?;
        }
        Ok(validated)
    }

    pub fn incoming(&self, artifact_id: &str) -> Vec<&ProvenanceEdge> {
        let mut rows: Vec<_> = self
            .edges
            .iter()
            .filter(|e| e.to_artifact_id == artifact_id)
            .collect();
        rows.sort_by_key(|e| e.key());
        rows
    }

    pub fn outgoing(&self, artifact_id: &str) -> Vec<&ProvenanceEdge> {
        let mut rows: Vec<_> = self
            .edges
            .iter()
            .filter(|e| e.from_artifact_id == artifact_id)
            .collect();
        rows.sort_by_key(|e| e.key());
        rows
    }

    /// Returns deterministic upstream explanation paths ending at `artifact_id`.
    /// A default path cap prevents hostile/highly-branching graphs from growing memory without bound.
    pub fn why_is_this_here(&self, artifact_id: &str, max_depth: usize) -> Vec<ProvenancePath> {
        self.why_is_this_here_bounded(artifact_id, max_depth, 256)
    }

    pub fn why_is_this_here_bounded(
        &self,
        artifact_id: &str,
        max_depth: usize,
        max_paths: usize,
    ) -> Vec<ProvenancePath> {
        if max_depth == 0 || max_paths == 0 {
            return Vec::new();
        }
        if !self.artifacts.contains_key(artifact_id) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut queue = VecDeque::from([(
            artifact_id.to_string(),
            vec![artifact_id.to_string()],
            Vec::new(),
            true,
        )]);
        let mut visited_depth: BTreeMap<String, usize> = BTreeMap::new();
        while let Some((current, ids_rev, rels_rev, verified)) = queue.pop_front() {
            let depth = rels_rev.len();
            if depth >= max_depth {
                continue;
            }
            let incoming = self.incoming(&current);
            if incoming.is_empty() && depth > 0 {
                let mut ids = ids_rev.clone();
                ids.reverse();
                let mut rels = rels_rev.clone();
                rels.reverse();
                out.push(ProvenancePath {
                    artifact_ids: ids,
                    relations: rels,
                    fully_verified: verified,
                });
                if out.len() >= max_paths {
                    break;
                }
                continue;
            }
            for edge in incoming {
                let next_depth = depth + 1;
                if visited_depth
                    .get(&edge.from_artifact_id)
                    .is_some_and(|d| *d < next_depth)
                {
                    continue;
                }
                visited_depth.insert(edge.from_artifact_id.clone(), next_depth);
                let mut ids = ids_rev.clone();
                ids.push(edge.from_artifact_id.clone());
                let mut rels = rels_rev.clone();
                rels.push(edge.relation.clone());
                queue.push_back((
                    edge.from_artifact_id.clone(),
                    ids,
                    rels,
                    verified && edge.verified,
                ));
            }
        }
        out.sort_by(|a, b| {
            a.artifact_ids
                .cmp(&b.artifact_ids)
                .then(a.relations.cmp(&b.relations))
        });
        out
    }

    pub fn what_loads_this(&self, artifact_id: &str) -> Vec<String> {
        let load_relations = [
            ProvenanceRelation::Includes,
            ProvenanceRelation::Loads,
            ProvenanceRelation::Invokes,
            ProvenanceRelation::DependsOn,
        ];
        let ids: BTreeSet<_> = self
            .incoming(artifact_id)
            .into_iter()
            .filter(|e| load_relations.contains(&e.relation))
            .map(|e| e.from_artifact_id.clone())
            .collect();
        ids.iter().cloned().collect()
    }

    pub fn what_changed_since(&self, baseline: &Self) -> Vec<crate::drift::ProvenanceDrift> {
        crate::drift::detect_drift(baseline, self)
    }

    pub fn show_unverified_chain(&self) -> Vec<&ProvenanceEdge> {
        let mut rows: Vec<_> = self.edges.iter().filter(|e| !e.verified).collect();
        rows.sort_by_key(|e| e.key());
        rows
    }

    pub fn provenance_gaps(&self) -> Vec<&ArtifactIdentity> {
        let mut rows: Vec<_> = self
            .artifacts
            .values()
            .filter(|a| a.source_uri.is_none() || a.content_digest.is_none())
            .collect();
        rows.sort_by_key(|a| &a.artifact_id);
        rows
    }

    pub fn license_gaps(&self) -> Vec<&ArtifactIdentity> {
        let mut rows: Vec<_> = self
            .artifacts
            .values()
            .filter(|a| !a.metadata.contains_key("license"))
            .collect();
        rows.sort_by_key(|a| &a.artifact_id);
        rows
    }
}
