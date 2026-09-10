use crate::{
    ArtifactIdentity, ArtifactType, EvidenceKind, GraphError, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation, ProvenanceStatus,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HfError {
    #[error("recorded Hugging Face json exceeds {0} bytes")]
    InputTooLarge(usize),
    #[error("recorded Hugging Face metadata exceeds {0} lineage/file items")]
    TooManyItems(usize),
    #[error("invalid recorded Hugging Face json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Graph(#[from] GraphError),
}

#[derive(Debug, Deserialize)]
struct Card {
    id: String,
    #[serde(default)]
    sha: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    base_model: Vec<String>,
    #[serde(default)]
    datasets: Vec<String>,
    #[serde(default)]
    siblings: Vec<Sibling>,
    #[serde(default)]
    pipeline_tag: Option<String>,
}
#[derive(Debug, Deserialize)]
struct Sibling {
    rfilename: String,
    #[serde(default)]
    blob_id: Option<String>,
}

pub fn ingest_recorded_model_card(json: &str) -> Result<ProvenanceGraph, HfError> {
    if json.len() > super::MAX_RECORDED_JSON_BYTES {
        return Err(HfError::InputTooLarge(super::MAX_RECORDED_JSON_BYTES));
    }
    let card: Card = serde_json::from_str(json)?;
    if card.base_model.len() + card.datasets.len() + card.siblings.len() > super::MAX_RECORDED_ITEMS
    {
        return Err(HfError::TooManyItems(super::MAX_RECORDED_ITEMS));
    }
    let model_id = format!("hf:model:{}", card.id.to_ascii_lowercase());
    let mut model = ArtifactIdentity::new(&model_id, ArtifactType::Model, &card.id);
    model.source_uri = Some(format!("https://huggingface.co/{}", card.id));
    model.resolved_revision = card.sha.clone();
    model.content_digest = card.sha.map(|s| format!("hf-revision:{s}"));
    model.provenance_status = ProvenanceStatus::Declared;
    if let Some(v) = card.license {
        model.metadata.insert("license".into(), v.into());
    }
    if let Some(v) = card.pipeline_tag {
        model.metadata.insert("pipeline_tag".into(), v.into());
    }
    let lineage = card.base_model.join(",");
    if !lineage.is_empty() {
        model.metadata.insert("lineage".into(), lineage.into());
    }
    let mut graph = ProvenanceGraph::default();
    graph.add_artifact(model)?;

    for base in card.base_model {
        let id = format!("hf:model:{}", base.to_ascii_lowercase());
        let mut node = ArtifactIdentity::new(&id, ArtifactType::Model, &base);
        node.source_uri = Some(format!("https://huggingface.co/{base}"));
        node.provenance_status = ProvenanceStatus::Declared;
        graph.add_artifact(node)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: model_id.clone(),
            relation: ProvenanceRelation::DerivedFrom,
            to_artifact_id: id,
            evidence_kind: EvidenceKind::Declared,
            source: "huggingface-model-card".into(),
            verified: false,
            confidence: None,
        })?;
    }
    for dataset in card.datasets {
        let id = format!("hf:dataset:{}", dataset.to_ascii_lowercase());
        let mut node = ArtifactIdentity::new(&id, ArtifactType::Dataset, &dataset);
        node.source_uri = Some(format!("https://huggingface.co/datasets/{dataset}"));
        node.provenance_status = ProvenanceStatus::Declared;
        graph.add_artifact(node)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: model_id.clone(),
            relation: ProvenanceRelation::TrainedOn,
            to_artifact_id: id,
            evidence_kind: EvidenceKind::Declared,
            source: "huggingface-model-card".into(),
            verified: false,
            confidence: None,
        })?;
    }
    for sibling in card.siblings {
        let id = format!(
            "hf:file:{}/{}",
            card.id.to_ascii_lowercase(),
            sibling.rfilename
        );
        let mut node = ArtifactIdentity::new(&id, ArtifactType::File, &sibling.rfilename);
        node.source_uri = Some(format!(
            "https://huggingface.co/{}/blob/main/{}",
            card.id, sibling.rfilename
        ));
        node.content_digest = sibling.blob_id.map(|v| format!("hf-blob:{v}"));
        node.provenance_status = ProvenanceStatus::Declared;
        graph.add_artifact(node)?;
        graph.add_edge(ProvenanceEdge {
            from_artifact_id: model_id.clone(),
            relation: ProvenanceRelation::Includes,
            to_artifact_id: id,
            evidence_kind: EvidenceKind::External,
            source: "huggingface-api-recording".into(),
            verified: false,
            confidence: None,
        })?;
    }
    Ok(graph)
}
