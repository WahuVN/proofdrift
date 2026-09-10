use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementLevel {
    L0Inventoried,
    L1Brokered,
    L2Isolated,
    L3Attested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementMode {
    ObserveOnly,
    EnforcedAtBoundary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub schema_version: String,
    pub event_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    pub actor: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub event_type: String,
    pub proposed_action: String,
    pub resource: String,
    pub normalized_args: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub outcome: String,
    pub enforcement_level: EnforcementLevel,
    pub enforcement_mode: EnforcementMode,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("event sink error: {message}")]
pub struct EventSinkError {
    pub message: String,
}

impl EventSinkError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait RuntimeEventSink: Send + Sync {
    fn record(&self, event: RuntimeEvent) -> Result<(), EventSinkError>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryEventSink {
    events: Arc<Mutex<Vec<RuntimeEvent>>>,
}

impl InMemoryEventSink {
    pub fn events(&self) -> Vec<RuntimeEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl RuntimeEventSink for InMemoryEventSink {
    fn record(&self, event: RuntimeEvent) -> Result<(), EventSinkError> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }
}
