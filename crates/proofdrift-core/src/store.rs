use proofdrift_schema::{
    canonical_sha256, canonical_sha256_excluding, AgentEvent, ArtifactIdentity, Finding,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store lock poisoned")]
    Poisoned,
    #[error("duplicate event id: {0}")]
    DuplicateEventId(String),
    #[error("event {event_id} has sequence {actual}; expected {expected}")]
    InvalidSequence {
        event_id: String,
        expected: u64,
        actual: u64,
    },
    #[error("event {event_id} previous hash mismatch")]
    PreviousHashMismatch { event_id: String },
    #[error("event {event_id} supplied hash does not match canonical event content")]
    EventHashMismatch { event_id: String },
    #[error("conflicting artifact id: {0}")]
    ArtifactConflict(String),
    #[error("conflicting finding id: {0}")]
    FindingConflict(String),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] proofdrift_schema::CanonicalError),
}

pub trait EventStore: Send + Sync {
    fn append(&self, event: AgentEvent) -> Result<AgentEvent, StoreError>;
    fn events(&self, session_id: &str) -> Result<Vec<AgentEvent>, StoreError>;
}

#[derive(Default)]
pub struct InMemoryEventStore {
    inner: Mutex<EventStoreState>,
}

#[derive(Default)]
struct EventStoreState {
    sessions: BTreeMap<String, Vec<AgentEvent>>,
    event_ids: BTreeSet<String>,
}

impl EventStore for InMemoryEventStore {
    fn append(&self, mut event: AgentEvent) -> Result<AgentEvent, StoreError> {
        let mut state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        if state.event_ids.contains(&event.event_id) {
            return Err(StoreError::DuplicateEventId(event.event_id));
        }

        let (expected_sequence, expected_prev) = match state.sessions.get(&event.session_id) {
            Some(existing) => (
                existing.len() as u64 + 1,
                existing.last().and_then(|prior| prior.event_hash.clone()),
            ),
            None => (1, None),
        };
        if event.sequence != expected_sequence {
            return Err(StoreError::InvalidSequence {
                event_id: event.event_id,
                expected: expected_sequence,
                actual: event.sequence,
            });
        }

        if event.prev_event_hash != expected_prev {
            return Err(StoreError::PreviousHashMismatch {
                event_id: event.event_id,
            });
        }

        let computed = canonical_sha256_excluding(&event, &["event_hash"])?;
        if let Some(supplied) = event.event_hash.as_deref() {
            if supplied != computed {
                return Err(StoreError::EventHashMismatch {
                    event_id: event.event_id,
                });
            }
        }
        event.event_hash = Some(computed);
        state.event_ids.insert(event.event_id.clone());
        state
            .sessions
            .entry(event.session_id.clone())
            .or_default()
            .push(event.clone());
        Ok(event)
    }

    fn events(&self, session_id: &str) -> Result<Vec<AgentEvent>, StoreError> {
        let state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state.sessions.get(session_id).cloned().unwrap_or_default())
    }
}

pub trait ArtifactStore: Send + Sync {
    fn put(&self, artifact: ArtifactIdentity) -> Result<(), StoreError>;
    fn get(&self, artifact_id: &str) -> Result<Option<ArtifactIdentity>, StoreError>;
    fn list(&self) -> Result<Vec<ArtifactIdentity>, StoreError>;
}

#[derive(Default)]
pub struct InMemoryArtifactStore {
    inner: Mutex<BTreeMap<String, ArtifactIdentity>>,
}

impl ArtifactStore for InMemoryArtifactStore {
    fn put(&self, artifact: ArtifactIdentity) -> Result<(), StoreError> {
        let mut state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        if let Some(existing) = state.get(&artifact.artifact_id) {
            if canonical_sha256(existing)? != canonical_sha256(&artifact)? {
                return Err(StoreError::ArtifactConflict(artifact.artifact_id));
            }
            return Ok(());
        }
        state.insert(artifact.artifact_id.clone(), artifact);
        Ok(())
    }

    fn get(&self, artifact_id: &str) -> Result<Option<ArtifactIdentity>, StoreError> {
        let state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state.get(artifact_id).cloned())
    }

    fn list(&self) -> Result<Vec<ArtifactIdentity>, StoreError> {
        let state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state.values().cloned().collect())
    }
}

pub trait FindingStore: Send + Sync {
    fn put(&self, finding: Finding) -> Result<(), StoreError>;
    fn get(&self, finding_id: &str) -> Result<Option<Finding>, StoreError>;
    fn list(&self) -> Result<Vec<Finding>, StoreError>;
}

#[derive(Default)]
pub struct InMemoryFindingStore {
    inner: Mutex<BTreeMap<String, Finding>>,
}

impl FindingStore for InMemoryFindingStore {
    fn put(&self, finding: Finding) -> Result<(), StoreError> {
        let mut state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        if let Some(existing) = state.get(&finding.finding_id) {
            if canonical_sha256(existing)? != canonical_sha256(&finding)? {
                return Err(StoreError::FindingConflict(finding.finding_id));
            }
            return Ok(());
        }
        state.insert(finding.finding_id.clone(), finding);
        Ok(())
    }

    fn get(&self, finding_id: &str) -> Result<Option<Finding>, StoreError> {
        let state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state.get(finding_id).cloned())
    }

    fn list(&self) -> Result<Vec<Finding>, StoreError> {
        let state = self.inner.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(state.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofdrift_schema::{EnforcementLevel, SCHEMA_VERSION};
    use std::sync::Arc;
    use std::thread;

    fn event(session: &str, id: &str, sequence: u64, prev: Option<String>) -> AgentEvent {
        AgentEvent {
            schema_version: SCHEMA_VERSION.to_owned(),
            event_id: id.to_owned(),
            session_id: session.to_owned(),
            sequence,
            timestamp_wall: "2026-09-10T00:00:00Z".to_owned(),
            timestamp_monotonic_ns: Some(sequence),
            actor: "test".to_owned(),
            adapter_id: "fixture".to_owned(),
            adapter_version: Some("1".to_owned()),
            event_type: "tool.call".to_owned(),
            proposed_action: Some("fs.read".to_owned()),
            resource: Some("workspace/**".to_owned()),
            normalized_args: None,
            decision_id: None,
            outcome: "observed".to_owned(),
            enforcement_level: EnforcementLevel::L0,
            evidence_refs: vec![],
            prev_event_hash: prev,
            event_hash: None,
            extensions: Default::default(),
        }
    }

    #[test]
    fn append_hashes_and_chains_events() {
        let store = InMemoryEventStore::default();
        let first = store.append(event("s", "e1", 1, None)).unwrap();
        let second = store
            .append(event("s", "e2", 2, first.event_hash.clone()))
            .unwrap();
        assert!(first.event_hash.is_some());
        assert_eq!(second.prev_event_hash, first.event_hash);
    }

    #[test]
    fn duplicate_and_out_of_order_events_are_rejected() {
        let store = InMemoryEventStore::default();
        store.append(event("s", "e1", 1, None)).unwrap();
        assert!(matches!(
            store.append(event("s2", "e1", 1, None)),
            Err(StoreError::DuplicateEventId(_))
        ));
        assert!(matches!(
            store.append(event("s", "e3", 3, None)),
            Err(StoreError::InvalidSequence { .. })
        ));
    }

    #[test]
    fn supplied_tampered_hash_is_rejected() {
        let store = InMemoryEventStore::default();
        let mut tampered = event("s", "e1", 1, None);
        tampered.event_hash = Some("0".repeat(64));
        assert!(matches!(
            store.append(tampered),
            Err(StoreError::EventHashMismatch { .. })
        ));
    }

    #[test]
    fn independent_sessions_can_ingest_concurrently() {
        let store = Arc::new(InMemoryEventStore::default());
        let mut handles = Vec::new();
        for index in 0..16 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let session = format!("s{index}");
                let id = format!("e{index}");
                store.append(event(&session, &id, 1, None)).unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        for index in 0..16 {
            assert_eq!(store.events(&format!("s{index}")).unwrap().len(), 1);
        }
    }
}
