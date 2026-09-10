#![forbid(unsafe_code)]
//! Core lifecycle and deterministic trust/evidence logic.

mod lifecycle;
mod reason_codes;
mod report;
mod store;
mod trust_diff;

pub use lifecycle::{SessionLifecycle, SessionState, TransitionError};
pub use reason_codes::{is_known_reason_code, ReasonCode, KNOWN_REASON_CODES};
pub use report::{normalize_trust_report, score_from_components, ReportError};
pub use store::{
    ArtifactStore, EventStore, FindingStore, InMemoryArtifactStore, InMemoryEventStore,
    InMemoryFindingStore, StoreError,
};
pub use trust_diff::{diff_snapshots, DiffError};
