//! Provenance graph primitives and offline source enrichment for the ProofDrift.
//! The crate intentionally treats external metadata as declared evidence unless independently
//! verified. It does not perform network I/O during parsing.

pub mod adapters;
pub mod bom;
pub mod drift;
pub mod graph;
pub mod model;

pub use drift::{detect_drift, DriftKind, ProvenanceDrift};
pub use graph::{GraphError, ProvenanceGraph, ProvenancePath};
pub use model::{
    ArtifactIdentity, ArtifactType, EvidenceKind, ProvenanceEdge, ProvenanceRelation,
    ProvenanceStatus,
};
