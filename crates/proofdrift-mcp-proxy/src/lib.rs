pub mod transport;

use async_trait::async_trait;
use proofdrift_runtime::{
    canonical_sha256, redact_json, ApprovalError, ApprovalManager, Decision, EnforcementLevel,
    EnforcementMode, PolicyEvaluator, PolicyRequest, RuntimeEvent, RuntimeEventSink,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
    /// Preserve the rest of the MCP tool definition losslessly (title, outputSchema,
    /// annotations, icons, extension fields, and future additive members). Security drift
    /// fingerprints must cover the entire definition rather than a hand-picked subset.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ToolDefinition {
    pub fn fingerprint(&self) -> Result<String, serde_json::Error> {
        canonical_sha256(&serde_json::to_value(self)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSnapshot {
    pub server_id: String,
    pub protocol_version: String,
    pub tools_digest: String,
    pub tool_fingerprints: BTreeMap<String, String>,
}

impl ToolSnapshot {
    pub fn from_tools(
        server_id: impl Into<String>,
        protocol_version: impl Into<String>,
        tools: &[ToolDefinition],
    ) -> Result<Self, BrokerError> {
        let server_id = server_id.into();
        let protocol_version = protocol_version.into();
        let mut seen = BTreeSet::new();
        for tool in tools {
            if !seen.insert(tool.name.clone()) {
                return Err(BrokerError::DuplicateToolName(tool.name.clone()));
            }
        }

        let mut ordered = tools.to_vec();
        ordered.sort_by(|a, b| a.name.cmp(&b.name));
        let tools_digest = canonical_sha256(&serde_json::to_value(&ordered)?)?;
        let mut tool_fingerprints = BTreeMap::new();
        for tool in &ordered {
            tool_fingerprints.insert(tool.name.clone(), tool.fingerprint()?);
        }
        Ok(Self {
            server_id,
            protocol_version,
            tools_digest,
            tool_fingerprints,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftKind {
    ToolAdded,
    ToolRemoved,
    ToolSchemaChanged,
    ProtocolVersionChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDrift {
    pub kind: DriftKind,
    pub tool_name: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
}

pub fn detect_tool_drift(baseline: &ToolSnapshot, current: &ToolSnapshot) -> Vec<ToolDrift> {
    let mut drift = Vec::new();
    if baseline.protocol_version != current.protocol_version {
        drift.push(ToolDrift {
            kind: DriftKind::ProtocolVersionChanged,
            tool_name: None,
            before: Some(baseline.protocol_version.clone()),
            after: Some(current.protocol_version.clone()),
        });
    }

    let mut names: Vec<String> = baseline
        .tool_fingerprints
        .keys()
        .chain(current.tool_fingerprints.keys())
        .cloned()
        .collect();
    names.sort();
    names.dedup();
    for name in names {
        match (
            baseline.tool_fingerprints.get(&name),
            current.tool_fingerprints.get(&name),
        ) {
            (None, Some(after)) => drift.push(ToolDrift {
                kind: DriftKind::ToolAdded,
                tool_name: Some(name),
                before: None,
                after: Some(after.clone()),
            }),
            (Some(before), None) => drift.push(ToolDrift {
                kind: DriftKind::ToolRemoved,
                tool_name: Some(name),
                before: Some(before.clone()),
                after: None,
            }),
            (Some(before), Some(after)) if before != after => drift.push(ToolDrift {
                kind: DriftKind::ToolSchemaChanged,
                tool_name: Some(name),
                before: Some(before.clone()),
                after: Some(after.clone()),
            }),
            _ => {}
        }
    }
    drift
}

#[derive(Debug, Clone)]
pub struct BrokerLimits {
    pub timeout_ms: u64,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_concurrent_calls: usize,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 4 * 1024 * 1024,
            max_concurrent_calls: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownstreamResponse {
    pub result: Value,
}

#[async_trait]
pub trait DownstreamMcp: Send + Sync {
    async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError>;
    async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<DownstreamResponse, BrokerError>;

    async fn call_tool_with_context(
        &self,
        name: &str,
        arguments: Value,
        request_state: Option<String>,
        input_responses: Option<Value>,
    ) -> Result<DownstreamResponse, BrokerError> {
        if request_state.is_some() || input_responses.is_some() {
            return Err(BrokerError::Downstream(
                "downstream adapter does not support MCP 2026 multi-round-trip call context".into(),
            ));
        }
        self.call_tool(name, arguments).await
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("policy evaluation failed: {0}")]
    Policy(String),
    #[error("tool call denied by policy")]
    Denied,
    #[error("approval required: {approval_id}")]
    ApprovalRequired { approval_id: String },
    #[error("approval failed: {0}")]
    Approval(#[from] ApprovalError),
    #[error("tool schema drift detected before dispatch")]
    SchemaDrift { drift: Vec<ToolDrift> },
    #[error("duplicate MCP tool name in downstream snapshot: {0}")]
    DuplicateToolName(String),
    #[error("requested MCP tool is not present in the current tool snapshot: {0}")]
    UnknownTool(String),
    #[error("request payload exceeded configured bound")]
    RequestTooLarge,
    #[error("response payload exceeded configured bound")]
    ResponseTooLarge,
    #[error("downstream operation timed out")]
    Timeout,
    #[error("concurrency limit reached")]
    ConcurrencyLimit,
    #[error("downstream error: {0}")]
    Downstream(String),
    #[error("event sink failed: {0}")]
    Evidence(String),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] serde_json::Error),
}

pub struct McpBroker {
    server_id: String,
    protocol_version: String,
    policy: Arc<dyn PolicyEvaluator>,
    sink: Arc<dyn RuntimeEventSink>,
    approvals: Arc<ApprovalManager>,
    downstream: Arc<dyn DownstreamMcp>,
    limits: BrokerLimits,
    semaphore: Arc<Semaphore>,
    baseline: Mutex<Option<ToolSnapshot>>,
    sequence: AtomicU64,
    session_id: String,
    principal: String,
}

impl McpBroker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_id: impl Into<String>,
        protocol_version: impl Into<String>,
        policy: Arc<dyn PolicyEvaluator>,
        sink: Arc<dyn RuntimeEventSink>,
        approvals: Arc<ApprovalManager>,
        downstream: Arc<dyn DownstreamMcp>,
        limits: BrokerLimits,
        session_id: impl Into<String>,
        principal: impl Into<String>,
    ) -> Self {
        let max_concurrent_calls = limits.max_concurrent_calls.max(1);
        Self {
            server_id: server_id.into(),
            protocol_version: protocol_version.into(),
            policy,
            sink,
            approvals,
            downstream,
            limits,
            semaphore: Arc::new(Semaphore::new(max_concurrent_calls)),
            baseline: Mutex::new(None),
            sequence: AtomicU64::new(0),
            session_id: session_id.into(),
            principal: principal.into(),
        }
    }

    pub async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError> {
        let tools = self.with_timeout(self.downstream.list_tools()).await??;
        let snapshot = ToolSnapshot::from_tools(&self.server_id, &self.protocol_version, &tools)?;
        *self.baseline.lock().unwrap() = Some(snapshot);
        Ok(tools)
    }

    pub async fn refresh_tools(&self) -> Result<ToolSnapshot, BrokerError> {
        let _ = self.list_tools().await?;
        self.baseline()
            .ok_or_else(|| BrokerError::Downstream("tool baseline was not installed".into()))
    }

    /// Complete an approval challenge from a trusted local control surface. The challenge id
    /// itself is never an execution token; only the random one-time grant can authorize retry.
    pub fn approve_challenge(
        &self,
        approval_id: &str,
    ) -> Result<proofdrift_runtime::ApprovalGrant, BrokerError> {
        self.approvals
            .approve(approval_id)
            .map_err(BrokerError::from)
    }

    pub fn baseline(&self) -> Option<ToolSnapshot> {
        self.baseline.lock().unwrap().clone()
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        approval_token: Option<&str>,
    ) -> Result<DownstreamResponse, BrokerError> {
        self.call_tool_with_context(name, arguments, None, None, approval_token)
            .await
    }

    pub async fn call_tool_with_context(
        &self,
        name: &str,
        arguments: Value,
        request_state: Option<&str>,
        input_responses: Option<&Value>,
        approval_token: Option<&str>,
    ) -> Result<DownstreamResponse, BrokerError> {
        let request_size = serde_json::to_vec(&arguments)?.len();
        if request_size > self.limits.max_request_bytes {
            return Err(BrokerError::RequestTooLarge);
        }
        let _permit = self.acquire_permit()?;

        // Re-list immediately before policy evaluation/dispatch. This binds the decision to
        // the actual current schema and turns list->call rug pulls into a hard broker stop.
        let current_tools = self.with_timeout(self.downstream.list_tools()).await??;
        let current_snapshot =
            ToolSnapshot::from_tools(&self.server_id, &self.protocol_version, &current_tools)?;
        let baseline = { self.baseline.lock().unwrap().clone() };
        if let Some(baseline) = baseline {
            let drift = detect_tool_drift(&baseline, &current_snapshot);
            if !drift.is_empty() {
                self.record_event(
                    name,
                    &arguments,
                    None,
                    "SCHEMA_DRIFT_BLOCKED",
                    EnforcementMode::EnforcedAtBoundary,
                )?;
                return Err(BrokerError::SchemaDrift { drift });
            }
        } else {
            *self.baseline.lock().unwrap() = Some(current_snapshot.clone());
        }

        let Some(tool_fingerprint) = current_snapshot.tool_fingerprints.get(name).cloned() else {
            self.record_event(
                name,
                &arguments,
                None,
                "UNKNOWN_TOOL_BLOCKED",
                EnforcementMode::EnforcedAtBoundary,
            )?;
            return Err(BrokerError::UnknownTool(name.to_owned()));
        };
        let request = PolicyRequest::new(
            self.principal.clone(),
            "mcp.call",
            format!("{}::{name}", self.server_id),
            json!({
                "server_id": self.server_id,
                "tool_name": name,
                "tool_fingerprint": tool_fingerprint,
                "arguments_digest": canonical_sha256(&arguments)?,
                "arguments": redact_json(&arguments),
                "request_state_digest": request_state
                    .map(|value| canonical_sha256(&Value::String(value.to_owned())))
                    .transpose()?,
                "input_responses_digest": input_responses
                    .map(canonical_sha256)
                    .transpose()?,
                "protocol_version": self.protocol_version,
            }),
        );
        let decision = self
            .policy
            .evaluate(&request)
            .map_err(BrokerError::Policy)?;
        let scope_digest = canonical_sha256(&json!({
            "request_digest": decision.request_digest,
            "policy_bundle_digest": decision.policy_bundle_digest,
            "decision_hash": decision.decision_hash,
            "tool_fingerprint": tool_fingerprint,
            "request_state_digest": request_state
                .map(|value| canonical_sha256(&Value::String(value.to_owned())))
                .transpose()?,
            "input_responses_digest": input_responses
                .map(canonical_sha256)
                .transpose()?,
        }))?;

        match decision.decision {
            Decision::Deny => {
                self.record_event(
                    name,
                    &arguments,
                    Some(&decision.decision_hash),
                    "DENIED",
                    EnforcementMode::EnforcedAtBoundary,
                )?;
                return Err(BrokerError::Denied);
            }
            Decision::RequireApproval => {
                if let Some(token) = approval_token {
                    self.approvals.consume(token, &scope_digest)?;
                } else {
                    let challenge = self.approvals.create_challenge(scope_digest)?;
                    self.record_event(
                        name,
                        &arguments,
                        Some(&decision.decision_hash),
                        "APPROVAL_REQUIRED",
                        EnforcementMode::EnforcedAtBoundary,
                    )?;
                    return Err(BrokerError::ApprovalRequired {
                        approval_id: challenge.approval_id,
                    });
                }
            }
            Decision::Allow | Decision::Observe => {}
        }

        let mode = if decision.decision == Decision::Observe {
            EnforcementMode::ObserveOnly
        } else {
            EnforcementMode::EnforcedAtBoundary
        };
        self.record_event(
            name,
            &arguments,
            Some(&decision.decision_hash),
            "DISPATCHING",
            mode,
        )?;
        let response = self
            .with_timeout(self.downstream.call_tool_with_context(
                name,
                arguments.clone(),
                request_state.map(str::to_owned),
                input_responses.cloned(),
            ))
            .await??;
        let response_size = serde_json::to_vec(&response)?.len();
        if response_size > self.limits.max_response_bytes {
            self.record_event(
                name,
                &arguments,
                Some(&decision.decision_hash),
                "RESPONSE_TOO_LARGE",
                mode,
            )?;
            return Err(BrokerError::ResponseTooLarge);
        }
        self.record_event(
            name,
            &arguments,
            Some(&decision.decision_hash),
            "COMPLETED",
            mode,
        )?;
        Ok(response)
    }

    fn acquire_permit(&self) -> Result<OwnedSemaphorePermit, BrokerError> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| BrokerError::ConcurrencyLimit)
    }

    async fn with_timeout<F, T>(&self, future: F) -> Result<T, BrokerError>
    where
        F: std::future::Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_millis(self.limits.timeout_ms.max(1)), future)
            .await
            .map_err(|_| BrokerError::Timeout)
    }

    fn record_event(
        &self,
        tool_name: &str,
        arguments: &Value,
        decision_id: Option<&str>,
        outcome: &str,
        mode: EnforcementMode,
    ) -> Result<(), BrokerError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self.sink
            .record(RuntimeEvent {
                schema_version: "0.1".to_owned(),
                event_id: format!("mcp-{}-{sequence}", self.session_id),
                session_id: self.session_id.clone(),
                sequence,
                timestamp_unix_ms,
                actor: self.principal.clone(),
                adapter_id: "proofdrift-mcp-proxy".to_owned(),
                adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                event_type: "mcp.tools.call".to_owned(),
                proposed_action: "mcp.call".to_owned(),
                resource: format!("{}::{tool_name}", self.server_id),
                normalized_args: json!({
                    "tool_name": tool_name,
                    "arguments_digest": canonical_sha256(arguments)?,
                    "arguments": redact_json(arguments),
                    "protocol_version": self.protocol_version,
                }),
                decision_id: decision_id.map(str::to_owned),
                outcome: outcome.to_owned(),
                enforcement_level: EnforcementLevel::L1Brokered,
                enforcement_mode: mode,
                enforcement_scope:
                    "mcp-call-dispatch-boundary; policy, approval, and schema-drift checks occur before downstream tool dispatch"
                        .to_owned(),
                evidence_refs: Vec::new(),
                prev_event_hash: None,
                event_hash: None,
            })
            .map_err(|err| BrokerError::Evidence(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofdrift_runtime::{InMemoryEventSink, PolicyDecision};
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    struct FixedPolicy(Decision);
    impl PolicyEvaluator for FixedPolicy {
        fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, String> {
            PolicyDecision::bound(
                request,
                self.0,
                vec!["p-test".into()],
                vec![],
                vec![],
                "bundle-test",
            )
            .map_err(|err| err.to_string())
        }
    }

    struct FakeDownstream {
        tools: Mutex<Vec<ToolDefinition>>,
        calls: AtomicUsize,
        block: AtomicBool,
        response_bytes: AtomicUsize,
    }

    #[async_trait]
    impl DownstreamMcp for FakeDownstream {
        async fn list_tools(&self) -> Result<Vec<ToolDefinition>, BrokerError> {
            Ok(self.tools.lock().unwrap().clone())
        }

        async fn call_tool(
            &self,
            name: &str,
            arguments: Value,
        ) -> Result<DownstreamResponse, BrokerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.block.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let response_bytes = self.response_bytes.load(Ordering::SeqCst);
            if response_bytes > 0 {
                return Ok(DownstreamResponse {
                    result: json!({"payload": "x".repeat(response_bytes)}),
                });
            }
            Ok(DownstreamResponse {
                result: json!({"tool": name, "arguments": arguments}),
            })
        }
    }

    fn fake_downstream() -> Arc<FakeDownstream> {
        Arc::new(FakeDownstream {
            tools: Mutex::new(vec![read_tool()]),
            calls: AtomicUsize::new(0),
            block: AtomicBool::new(false),
            response_bytes: AtomicUsize::new(0),
        })
    }

    fn read_tool() -> ToolDefinition {
        ToolDefinition {
            name: "read".into(),
            description: Some("read a record".into()),
            input_schema: json!({
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "required": ["id"]
            }),
            extensions: BTreeMap::new(),
        }
    }

    fn broker(
        decision: Decision,
        downstream: Arc<FakeDownstream>,
        limits: BrokerLimits,
    ) -> (McpBroker, Arc<InMemoryEventSink>, Arc<ApprovalManager>) {
        let sink = Arc::new(InMemoryEventSink::default());
        let approvals = Arc::new(ApprovalManager::new(60_000));
        (
            McpBroker::new(
                "fake-server",
                MODERN_PROTOCOL_VERSION,
                Arc::new(FixedPolicy(decision)),
                sink.clone(),
                approvals.clone(),
                downstream,
                limits,
                "session-test",
                "agent-test",
            ),
            sink,
            approvals,
        )
    }

    #[tokio::test]
    async fn deny_never_dispatches_downstream() {
        let downstream = fake_downstream();
        let (broker, sink, _) = broker(Decision::Deny, downstream.clone(), BrokerLimits::default());
        broker.refresh_tools().await.unwrap();
        let result = broker.call_tool("read", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::Denied)));
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
        assert_eq!(sink.events().last().unwrap().outcome, "DENIED");
    }

    #[tokio::test]
    async fn require_approval_never_dispatches_without_grant() {
        let downstream = fake_downstream();
        let (broker, _, _) = broker(
            Decision::RequireApproval,
            downstream.clone(),
            BrokerLimits::default(),
        );
        broker.refresh_tools().await.unwrap();
        let result = broker.call_tool("read", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::ApprovalRequired { .. })));
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn schema_rug_pull_is_blocked_before_tool_dispatch() {
        let downstream = fake_downstream();
        let (broker, _, _) = broker(Decision::Allow, downstream.clone(), BrokerLimits::default());
        broker.refresh_tools().await.unwrap();
        let mut changed = read_tool();
        changed.input_schema = json!({
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "delete": {"type": "boolean"}
            }
        });
        *downstream.tools.lock().unwrap() = vec![changed];
        let result = broker.call_tool("read", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::SchemaDrift { .. })));
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unknown_tool_is_blocked_even_without_explicit_baseline() {
        let downstream = fake_downstream();
        let (broker, _, _) = broker(Decision::Allow, downstream.clone(), BrokerLimits::default());
        let result = broker.call_tool("delete", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::UnknownTool(name)) if name == "delete"));
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn secret_bearing_argument_is_redacted_in_evidence() {
        let downstream = fake_downstream();
        let (broker, sink, _) = broker(Decision::Deny, downstream, BrokerLimits::default());
        broker.refresh_tools().await.unwrap();
        let _ = broker
            .call_tool(
                "read",
                json!({"Authorization": "Bearer SYNTHETIC_SECRET", "id": "1"}),
                None,
            )
            .await;
        let encoded = serde_json::to_string(&sink.events()).unwrap();
        assert!(!encoded.contains("SYNTHETIC_SECRET"));
    }

    #[tokio::test]
    async fn request_size_limit_is_enforced_before_downstream_access() {
        let downstream = fake_downstream();
        let limits = BrokerLimits {
            max_request_bytes: 16,
            ..BrokerLimits::default()
        };
        let (broker, _, _) = broker(Decision::Allow, downstream.clone(), limits);
        let result = broker
            .call_tool("read", json!({"payload": "x".repeat(100)}), None)
            .await;
        assert!(matches!(result, Err(BrokerError::RequestTooLarge)));
        assert_eq!(downstream.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn response_size_limit_is_enforced() {
        let downstream = fake_downstream();
        downstream.response_bytes.store(1024, Ordering::SeqCst);
        let limits = BrokerLimits {
            max_response_bytes: 128,
            ..BrokerLimits::default()
        };
        let (broker, sink, _) = broker(Decision::Allow, downstream, limits);
        broker.refresh_tools().await.unwrap();
        let result = broker.call_tool("read", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::ResponseTooLarge)));
        assert_eq!(sink.events().last().unwrap().outcome, "RESPONSE_TOO_LARGE");
    }

    #[tokio::test]
    async fn timeout_is_bounded() {
        let downstream = fake_downstream();
        downstream.block.store(true, Ordering::SeqCst);
        let limits = BrokerLimits {
            timeout_ms: 5,
            ..BrokerLimits::default()
        };
        let (broker, _, _) = broker(Decision::Allow, downstream, limits);
        broker.refresh_tools().await.unwrap();
        let result = broker.call_tool("read", json!({"id": "1"}), None).await;
        assert!(matches!(result, Err(BrokerError::Timeout)));
    }

    #[tokio::test]
    async fn concurrency_limit_fails_closed() {
        let downstream = fake_downstream();
        downstream.block.store(true, Ordering::SeqCst);
        let limits = BrokerLimits {
            max_concurrent_calls: 1,
            timeout_ms: 1000,
            ..BrokerLimits::default()
        };
        let (broker, _, _) = broker(Decision::Allow, downstream, limits);
        broker.refresh_tools().await.unwrap();
        let broker = Arc::new(broker);
        let first = {
            let broker = broker.clone();
            tokio::spawn(async move { broker.call_tool("read", json!({"id": "1"}), None).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = broker.call_tool("read", json!({"id": "2"}), None).await;
        assert!(matches!(second, Err(BrokerError::ConcurrencyLimit)));
        first.await.unwrap().unwrap();
    }

    #[test]
    fn tool_fingerprint_is_order_stable() {
        let a = ToolDefinition {
            name: "read".into(),
            description: None,
            input_schema: json!({"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number"}}}),
            extensions: BTreeMap::new(),
        };
        let b = ToolDefinition {
            name: "read".into(),
            description: None,
            input_schema: json!({"properties":{"a":{"type":"number"},"b":{"type":"string"}},"type":"object"}),
            extensions: BTreeMap::new(),
        };
        assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn drift_order_is_deterministic() {
        let baseline = ToolSnapshot::from_tools(
            "s",
            MODERN_PROTOCOL_VERSION,
            &[
                ToolDefinition {
                    name: "z".into(),
                    description: None,
                    input_schema: json!({"type":"object"}),
                    extensions: BTreeMap::new(),
                },
                ToolDefinition {
                    name: "a".into(),
                    description: None,
                    input_schema: json!({"type":"object"}),
                    extensions: BTreeMap::new(),
                },
            ],
        )
        .unwrap();
        let current = ToolSnapshot::from_tools(
            "s",
            MODERN_PROTOCOL_VERSION,
            &[ToolDefinition {
                name: "m".into(),
                description: None,
                input_schema: json!({"type":"object"}),
                extensions: BTreeMap::new(),
            }],
        )
        .unwrap();
        let names: Vec<Option<String>> = detect_tool_drift(&baseline, &current)
            .into_iter()
            .map(|d| d.tool_name)
            .collect();
        assert_eq!(
            names,
            vec![Some("a".into()), Some("m".into()), Some("z".into())]
        );
    }
}
