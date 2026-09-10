use proofdrift_evidence::{AgentEventInput, EvidenceStore, Redactor, StoredEvent};
use proofdrift_policy::{
    built_in_policy_pack, CompiledPolicyPack, PolicyDecisionKind, PolicyEngine,
    PolicyRequest as CedarPolicyRequest,
};
use proofdrift_runtime::{
    ApprovalManager, CommandRunner, Decision as RuntimeDecision, DockerCommandRunner,
    DockerIsolationConfig, EnforcementLevel, EnforcementMode, EventSinkError,
    GuardedProcessExecutor, PolicyDecision as RuntimePolicyDecision,
    PolicyEvaluator as RuntimePolicyEvaluator, PolicyRequest as RuntimePolicyRequest, ProcessError,
    ProcessInvocation, RuntimeEvent, RuntimeEventSink, TokioCommandRunner,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Serialize)]
pub(crate) struct GuardedRunResult {
    pub session_id: String,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_lossy: bool,
    pub stderr_lossy: bool,
    pub events_recorded: usize,
    pub evidence_db: String,
    pub enforcement_level: &'static str,
    pub enforcement_scope: &'static str,
    pub policy_pack: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ReportResult {
    SessionList {
        sessions: Vec<String>,
    },
    Session {
        session_id: String,
        valid: bool,
        event_count: usize,
        final_hash: String,
        events: Vec<StoredEvent>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum GuardedRunError {
    #[error("policy denied the command at the process boundary; session={session_id}")]
    Denied {
        session_id: String,
        evidence_db: String,
        events_recorded: usize,
    },
    #[error("approval required before dispatch: {approval_id}; session={session_id}")]
    ApprovalRequired {
        approval_id: String,
        session_id: String,
        evidence_db: String,
        events_recorded: usize,
    },
    #[error("runtime setup failed: {0}")]
    Setup(String),
    #[error("guarded process failed: {0}")]
    Runtime(String),
}

pub(crate) enum RunIsolation {
    None,
    Docker {
        image: String,
        workspace_writable: bool,
    },
}

pub(crate) struct CedarRuntimePolicy {
    engine: PolicyEngine,
    pack: Arc<CompiledPolicyPack>,
}

impl CedarRuntimePolicy {
    pub(crate) fn from_builtin(name: &str) -> Result<Self, GuardedRunError> {
        let source = built_in_policy_pack(name).ok_or_else(|| {
            GuardedRunError::Setup(format!("unknown built-in policy pack: {name}"))
        })?;
        let engine = PolicyEngine::default();
        let pack = engine
            .compile_cached(source)
            .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
        Ok(Self { engine, pack })
    }
}

/// Convert ordinary runtime JSON into the subset accepted by Cedar context JSON.
/// Optional object fields encoded as `null` are omitted. A `null` inside an array
/// is ambiguous (dropping it would change positional meaning), so it fails closed.
/// Floating-point values are rejected rather than rounded.
fn cedar_compatible_context_value(value: &Value) -> Result<Option<Value>, String> {
    match value {
        Value::Null => Ok(None),
        Value::Bool(_) | Value::String(_) => Ok(Some(value.clone())),
        Value::Number(number) => {
            if number.as_i64().is_some() || number.as_u64().is_some() {
                Ok(Some(value.clone()))
            } else {
                Err("Cedar runtime context does not accept floating-point numbers".into())
            }
        }
        Value::Object(map) => {
            let mut clean = serde_json::Map::new();
            for (key, child) in map {
                if let Some(child) = cedar_compatible_context_value(child)? {
                    clean.insert(key.clone(), child);
                }
            }
            Ok(Some(Value::Object(clean)))
        }
        Value::Array(items) => {
            let mut clean = Vec::with_capacity(items.len());
            for child in items {
                let Some(child) = cedar_compatible_context_value(child)? else {
                    return Err("Cedar runtime context rejects null array elements".into());
                };
                clean.push(child);
            }
            Ok(Some(Value::Array(clean)))
        }
    }
}

impl RuntimePolicyEvaluator for CedarRuntimePolicy {
    fn evaluate(&self, request: &RuntimePolicyRequest) -> Result<RuntimePolicyDecision, String> {
        let request_digest = request.digest().map_err(|error| error.to_string())?;
        let request_id = format!("runtime-{}", &request_digest[..16]);
        let mut cedar = CedarPolicyRequest::with_request_id(
            request_id,
            request.principal.clone(),
            request.action.clone(),
            request.resource.clone(),
        );
        if let Value::Object(map) = &request.context {
            for (key, value) in map {
                if let Some(value) = cedar_compatible_context_value(value)? {
                    cedar.context.insert(key.clone(), value);
                }
            }
        } else if let Some(value) = cedar_compatible_context_value(&request.context)? {
            cedar.context.insert("runtime_context".into(), value);
        }
        cedar.session_path_summary = request.session_path_summary.clone();
        cedar.provenance = request.provenance.clone();
        if let Some(capability) = &request.capability {
            cedar.capability = serde_json::from_value(capability.clone()).ok();
        }

        let decision = self
            .engine
            .evaluate(&self.pack, &cedar, None)
            .map_err(|error| error.to_string())?;
        let runtime_decision = match decision.decision {
            PolicyDecisionKind::Allow => RuntimeDecision::Allow,
            PolicyDecisionKind::Deny => RuntimeDecision::Deny,
            PolicyDecisionKind::RequireApproval => RuntimeDecision::RequireApproval,
            PolicyDecisionKind::Observe => RuntimeDecision::Observe,
        };
        RuntimePolicyDecision::bound(
            request,
            runtime_decision,
            decision.policy_ids,
            decision.reason_codes,
            decision.diagnostics,
            decision.policy_bundle_digest,
        )
        .map_err(|error| error.to_string())
    }
}

pub(crate) struct PersistentRuntimeSink {
    store: Mutex<EvidenceStore>,
    events_recorded: AtomicUsize,
}

impl PersistentRuntimeSink {
    pub(crate) fn open(path: &Path) -> Result<Self, GuardedRunError> {
        let store = EvidenceStore::open(path, Redactor::default())
            .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
        Ok(Self {
            store: Mutex::new(store),
            events_recorded: AtomicUsize::new(0),
        })
    }

    fn count(&self) -> usize {
        self.events_recorded.load(Ordering::SeqCst)
    }
}

impl RuntimeEventSink for PersistentRuntimeSink {
    fn record(&self, event: RuntimeEvent) -> Result<(), EventSinkError> {
        let enforcement_level = if event.enforcement_mode == EnforcementMode::ObserveOnly {
            "OBSERVE_ONLY"
        } else {
            match event.enforcement_level {
                EnforcementLevel::L0Inventoried => "L0",
                EnforcementLevel::L1Brokered => "L1",
                EnforcementLevel::L2Isolated => "L2",
                EnforcementLevel::L3Attested => "L3",
            }
        };
        let mut extensions = BTreeMap::new();
        extensions.insert("runtime_sequence".into(), Value::from(event.sequence));
        extensions.insert(
            "enforcement_mode".into(),
            serde_json::to_value(event.enforcement_mode)
                .map_err(|error| EventSinkError::new(error.to_string()))?,
        );
        extensions.insert(
            "enforcement_scope".into(),
            Value::String(event.enforcement_scope.clone()),
        );
        let input = AgentEventInput {
            event_id: event.event_id,
            session_id: event.session_id,
            timestamp_wall: format!("unix-ms:{}", event.timestamp_unix_ms),
            timestamp_monotonic_ns: None,
            actor: event.actor,
            adapter_id: event.adapter_id,
            adapter_version: Some(event.adapter_version),
            event_type: event.event_type,
            proposed_action: event.proposed_action,
            resource: event.resource,
            normalized_args: event.normalized_args,
            decision_id: event.decision_id,
            outcome: event.outcome,
            enforcement_level: enforcement_level.into(),
            evidence_refs: event.evidence_refs,
            extensions,
        };
        let mut store = self
            .store
            .lock()
            .map_err(|_| EventSinkError::new("evidence store lock poisoned"))?;
        store
            .append(input)
            .map_err(|error| EventSinkError::new(error.to_string()))?;
        self.events_recorded.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

pub(crate) fn evidence_db_path(root: &Path) -> PathBuf {
    root.join(".proofdrift").join("evidence.sqlite3")
}

fn new_session_id(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}-{}-{millis}", std::process::id())
}

pub(crate) fn execute_guarded_command(
    command: &[String],
    cwd: &Path,
    policy_name: &str,
    timeout_ms: u64,
    max_output_bytes: usize,
    isolation: RunIsolation,
) -> Result<GuardedRunResult, GuardedRunError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| GuardedRunError::Setup("run command is empty".into()))?;
    let policy = Arc::new(CedarRuntimePolicy::from_builtin(policy_name)?);
    let db_path = evidence_db_path(cwd);
    let sink = Arc::new(PersistentRuntimeSink::open(&db_path)?);
    let approvals = Arc::new(ApprovalManager::new(60_000));
    let session_id = new_session_id("run");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
    let runner: Arc<dyn CommandRunner> = match isolation {
        RunIsolation::None => Arc::new(TokioCommandRunner),
        RunIsolation::Docker {
            image,
            workspace_writable,
        } => {
            let runner = DockerCommandRunner::new(
                DockerIsolationConfig::hardened(image, cwd, workspace_writable)
                    .map_err(|error| GuardedRunError::Setup(error.to_string()))?,
            );
            runtime
                .block_on(runner.verify_boundary())
                .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
            Arc::new(runner)
        }
    };
    let enforcement_level = match runner.enforcement_level() {
        EnforcementLevel::L0Inventoried => "L0",
        EnforcementLevel::L1Brokered => "L1",
        EnforcementLevel::L2Isolated => "L2",
        EnforcementLevel::L3Attested => "L3",
    };
    let enforcement_scope = runner.enforcement_scope();
    let executor = GuardedProcessExecutor::new(
        policy,
        sink.clone(),
        approvals,
        runner,
        session_id.clone(),
        "proofdrift-cli",
    );
    let mut invocation = ProcessInvocation::new(program.clone(), args.to_vec());
    invocation.cwd = Some(cwd.to_path_buf());
    invocation.timeout_ms = timeout_ms.max(1);
    invocation.max_output_bytes = max_output_bytes.max(1);

    let output = match runtime.block_on(executor.execute(&invocation, None)) {
        Ok(output) => output,
        Err(ProcessError::Denied) => {
            return Err(GuardedRunError::Denied {
                session_id,
                evidence_db: db_path.display().to_string(),
                events_recorded: sink.count(),
            })
        }
        Err(ProcessError::ApprovalRequired { approval_id }) => {
            return Err(GuardedRunError::ApprovalRequired {
                approval_id,
                session_id,
                evidence_db: db_path.display().to_string(),
                events_recorded: sink.count(),
            })
        }
        Err(error) => return Err(GuardedRunError::Runtime(error.to_string())),
    };

    let stdout_lossy = std::str::from_utf8(&output.stdout).is_err();
    let stderr_lossy = std::str::from_utf8(&output.stderr).is_err();
    Ok(GuardedRunResult {
        session_id,
        status_code: output.status_code,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        stdout_lossy,
        stderr_lossy,
        events_recorded: sink.count(),
        evidence_db: db_path.display().to_string(),
        enforcement_level,
        enforcement_scope,
        policy_pack: policy_name.into(),
    })
}

pub(crate) fn load_report(
    root: &Path,
    session: Option<&str>,
) -> Result<ReportResult, GuardedRunError> {
    let db_path = evidence_db_path(root);
    if !db_path.exists() {
        return Ok(ReportResult::SessionList {
            sessions: Vec::new(),
        });
    }
    let store = EvidenceStore::open(&db_path, Redactor::default())
        .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
    match session {
        None => Ok(ReportResult::SessionList {
            sessions: store
                .list_sessions()
                .map_err(|error| GuardedRunError::Setup(error.to_string()))?,
        }),
        Some(session_id) => {
            let events = store
                .load_session(session_id)
                .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
            if events.is_empty() {
                return Err(GuardedRunError::Setup(format!(
                    "evidence session not found: {session_id}"
                )));
            }
            let verification = store
                .verify_session(session_id)
                .map_err(|error| GuardedRunError::Setup(error.to_string()))?;
            Ok(ReportResult::Session {
                session_id: session_id.into(),
                valid: verification.valid,
                event_count: verification.event_count,
                final_hash: verification.final_hash,
                events,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofdrift_runtime::PolicyRequest;
    use serde_json::json;

    #[test]
    fn cedar_runtime_adapter_allows_safe_exec_and_denies_force_push() -> Result<(), GuardedRunError>
    {
        let adapter = CedarRuntimePolicy::from_builtin("safe-local-dev")?;
        let safe = PolicyRequest::new(
            "proofdrift-cli",
            "process.exec",
            "process",
            json!({"program":"echo"}),
        );
        let safe_decision = adapter.evaluate(&safe).map_err(GuardedRunError::Setup)?;
        assert_eq!(safe_decision.decision, RuntimeDecision::Allow);

        let force = PolicyRequest::new(
            "proofdrift-cli",
            "git.force_push",
            "origin/main",
            json!({"program":"git"}),
        );
        let force_decision = adapter.evaluate(&force).map_err(GuardedRunError::Setup)?;
        assert_eq!(force_decision.decision, RuntimeDecision::Deny);
        Ok(())
    }

    #[test]
    fn cedar_context_omits_optional_null_and_rejects_ambiguous_values() -> Result<(), String> {
        let value = json!({
            "program": "cmd.exe",
            "git_intent": null,
            "nested": {"optional": null, "count": 2}
        });
        let clean = cedar_compatible_context_value(&value)?
            .ok_or_else(|| "top-level object unexpectedly disappeared".to_string())?;
        assert_eq!(clean, json!({"program":"cmd.exe","nested":{"count":2}}));
        assert!(cedar_compatible_context_value(&json!([1, null, 2])).is_err());
        assert!(cedar_compatible_context_value(&json!(1.5)).is_err());
        Ok(())
    }
}
