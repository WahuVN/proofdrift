use crate::{
    approval::{ApprovalError, ApprovalManager},
    canonical::canonical_sha256,
    event::{EnforcementLevel, EnforcementMode, RuntimeEvent, RuntimeEventSink},
    git_guard::{classify_git_argv, GitIntent},
    policy::{Decision, PolicyEvaluator, PolicyRequest},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    None,
    BashLike,
    PowerShell,
    Cmd,
    OtherShell,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessClassification {
    pub shell_kind: ShellKind,
    pub opaque_nested_shell: bool,
    pub git_intent: Option<GitIntent>,
    pub capability: String,
}

#[derive(Debug, Clone)]
pub struct ProcessInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Environment values are deliberately never serialized into evidence by this module.
    pub env: BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl ProcessInvocation {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
            cwd: None,
            env: BTreeMap::new(),
            timeout_ms: 30_000,
            max_output_bytes: 1024 * 1024,
        }
    }

    pub fn argv_digest(&self) -> Result<String, serde_json::Error> {
        canonical_sha256(&json!({"program": self.program, "args": self.args}))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("policy evaluation failed: {0}")]
    Policy(String),
    #[error("process execution denied by policy")]
    Denied,
    #[error("approval required: {approval_id}")]
    ApprovalRequired { approval_id: String },
    #[error("approval failed: {0}")]
    Approval(#[from] ApprovalError),
    #[error("process timed out")]
    Timeout,
    #[error("process output exceeded configured bound")]
    OutputLimit,
    #[error("process runner failed: {0}")]
    Runner(String),
    #[error("event sink failed: {0}")]
    Evidence(String),
    #[error("failed to canonicalize runtime request: {0}")]
    Canonical(#[from] serde_json::Error),
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, invocation: &ProcessInvocation) -> Result<ProcessOutput, ProcessError>;
}

#[derive(Debug, Default)]
pub struct TokioCommandRunner;

#[async_trait]
impl CommandRunner for TokioCommandRunner {
    async fn run(&self, invocation: &ProcessInvocation) -> Result<ProcessOutput, ProcessError> {
        let mut command = Command::new(&invocation.program);
        command
            .args(&invocation.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(cwd) = &invocation.cwd {
            command.current_dir(cwd);
        }
        if !invocation.env.is_empty() {
            command.envs(&invocation.env);
        }
        let child = command
            .spawn()
            .map_err(|err| ProcessError::Runner(err.to_string()))?;
        let output = tokio::time::timeout(
            Duration::from_millis(invocation.timeout_ms.max(1)),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| ProcessError::Timeout)?
        .map_err(|err| ProcessError::Runner(err.to_string()))?;
        if output.stdout.len().saturating_add(output.stderr.len()) > invocation.max_output_bytes {
            return Err(ProcessError::OutputLimit);
        }
        Ok(ProcessOutput {
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

pub fn classify_process(invocation: &ProcessInvocation) -> ProcessClassification {
    let executable = executable_name(&invocation.program);
    if executable == "git" || executable == "git.exe" {
        let mut argv = Vec::with_capacity(invocation.args.len() + 1);
        argv.push("git".to_owned());
        argv.extend(invocation.args.clone());
        let intent = classify_git_argv(&argv);
        return ProcessClassification {
            shell_kind: ShellKind::None,
            opaque_nested_shell: false,
            git_intent: Some(intent),
            capability: intent.capability().to_owned(),
        };
    }

    let (shell_kind, opaque_nested_shell) = match executable.as_str() {
        "bash" | "bash.exe" | "sh" | "sh.exe" | "zsh" | "zsh.exe" | "dash" | "dash.exe" => (
            ShellKind::BashLike,
            has_shell_command_flag(&invocation.args),
        ),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => (
            ShellKind::PowerShell,
            invocation.args.iter().any(|arg| {
                matches!(
                    arg.to_ascii_lowercase().as_str(),
                    "-command" | "-c" | "-encodedcommand" | "-enc"
                )
            }),
        ),
        "cmd" | "cmd.exe" => (
            ShellKind::Cmd,
            invocation
                .args
                .iter()
                .any(|arg| arg.eq_ignore_ascii_case("/c") || arg.eq_ignore_ascii_case("/k")),
        ),
        other if other.ends_with("shell") => (ShellKind::OtherShell, true),
        _ => (ShellKind::None, false),
    };

    ProcessClassification {
        shell_kind,
        opaque_nested_shell,
        git_intent: None,
        capability: "process.exec".to_owned(),
    }
}

fn executable_name(program: &str) -> String {
    program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_ascii_lowercase()
}

fn has_shell_command_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "-c"
            || arg == "--command"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c'))
    })
}

pub struct GuardedProcessExecutor {
    policy: Arc<dyn PolicyEvaluator>,
    sink: Arc<dyn RuntimeEventSink>,
    approvals: Arc<ApprovalManager>,
    runner: Arc<dyn CommandRunner>,
    sequence: AtomicU64,
    session_id: String,
    principal: String,
}

impl GuardedProcessExecutor {
    pub fn new(
        policy: Arc<dyn PolicyEvaluator>,
        sink: Arc<dyn RuntimeEventSink>,
        approvals: Arc<ApprovalManager>,
        runner: Arc<dyn CommandRunner>,
        session_id: impl Into<String>,
        principal: impl Into<String>,
    ) -> Self {
        Self {
            policy,
            sink,
            approvals,
            runner,
            sequence: AtomicU64::new(0),
            session_id: session_id.into(),
            principal: principal.into(),
        }
    }

    pub async fn execute(
        &self,
        invocation: &ProcessInvocation,
        approval_token: Option<&str>,
    ) -> Result<ProcessOutput, ProcessError> {
        let classification = classify_process(invocation);
        let argv_digest = invocation.argv_digest()?;
        let resource = invocation
            .cwd
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "process".to_owned());
        let request = PolicyRequest::new(
            self.principal.clone(),
            classification.capability.clone(),
            resource.clone(),
            json!({
                "program": executable_name(&invocation.program),
                "argv_digest": argv_digest,
                "arg_count": invocation.args.len(),
                "shell_kind": classification.shell_kind,
                "opaque_nested_shell": classification.opaque_nested_shell,
                "git_intent": classification.git_intent,
            }),
        );
        let decision = self
            .policy
            .evaluate(&request)
            .map_err(ProcessError::Policy)?;
        let scope_digest = canonical_sha256(&json!({
            "request_digest": decision.request_digest,
            "policy_bundle_digest": decision.policy_bundle_digest,
            "decision_hash": decision.decision_hash,
        }))?;

        match decision.decision {
            Decision::Deny => {
                self.record_event(
                    &request,
                    &decision.decision_hash,
                    "DENIED",
                    EnforcementMode::EnforcedAtBoundary,
                )?;
                return Err(ProcessError::Denied);
            }
            Decision::RequireApproval => {
                if let Some(token) = approval_token {
                    self.approvals.consume(token, &scope_digest)?;
                } else {
                    let challenge = self.approvals.create_challenge(scope_digest)?;
                    self.record_event(
                        &request,
                        &decision.decision_hash,
                        "APPROVAL_REQUIRED",
                        EnforcementMode::EnforcedAtBoundary,
                    )?;
                    return Err(ProcessError::ApprovalRequired {
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
        self.record_event(&request, &decision.decision_hash, "DISPATCHING", mode)?;
        let output = match self.runner.run(invocation).await {
            Ok(output) => output,
            Err(error) => {
                let outcome = match &error {
                    ProcessError::Timeout => "PROCESS_TIMEOUT",
                    ProcessError::OutputLimit => "PROCESS_OUTPUT_LIMIT",
                    ProcessError::Runner(_) => "RUNNER_ERROR",
                    _ => "PROCESS_ERROR",
                };
                self.record_event(&request, &decision.decision_hash, outcome, mode)?;
                return Err(error);
            }
        };
        let outcome = if output.status_code == Some(0) {
            "COMPLETED"
        } else {
            "PROCESS_EXIT_NONZERO"
        };
        self.record_event(&request, &decision.decision_hash, outcome, mode)?;
        Ok(output)
    }

    fn record_event(
        &self,
        request: &PolicyRequest,
        decision_id: &str,
        outcome: &str,
        mode: EnforcementMode,
    ) -> Result<(), ProcessError> {
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self.sink
            .record(RuntimeEvent {
                schema_version: "0.1".to_owned(),
                event_id: format!("proc-{}-{sequence}", self.session_id),
                session_id: self.session_id.clone(),
                sequence,
                timestamp_unix_ms,
                actor: self.principal.clone(),
                adapter_id: "proofdrift-runtime-process-wrapper".to_owned(),
                adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
                event_type: "process.exec".to_owned(),
                proposed_action: request.action.clone(),
                resource: request.resource.clone(),
                normalized_args: request.context.clone(),
                decision_id: Some(decision_id.to_owned()),
                outcome: outcome.to_owned(),
                enforcement_level: EnforcementLevel::L1Brokered,
                enforcement_mode: mode,
                evidence_refs: Vec::new(),
                prev_event_hash: None,
                event_hash: None,
            })
            .map_err(|err| ProcessError::Evidence(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InMemoryEventSink, PolicyDecision};
    use std::sync::{atomic::AtomicUsize, Mutex};

    struct FixedPolicy(Decision);
    impl PolicyEvaluator for FixedPolicy {
        fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, String> {
            PolicyDecision::bound(
                request,
                self.0,
                vec!["test-policy".into()],
                vec![],
                vec![],
                "test-bundle",
            )
            .map_err(|err| err.to_string())
        }
    }

    struct CountingRunner {
        calls: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl CommandRunner for CountingRunner {
        async fn run(&self, _: &ProcessInvocation) -> Result<ProcessOutput, ProcessError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProcessOutput {
                status_code: Some(0),
                stdout: b"ok".to_vec(),
                stderr: vec![],
            })
        }
    }

    struct ResultRunner {
        result: Mutex<Option<Result<ProcessOutput, ProcessError>>>,
    }

    #[async_trait]
    impl CommandRunner for ResultRunner {
        async fn run(&self, _: &ProcessInvocation) -> Result<ProcessOutput, ProcessError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(ProcessError::Runner("runner reused".into())))
        }
    }

    #[test]
    fn nested_shell_strings_are_marked_opaque() {
        let invocation = ProcessInvocation::new(
            "pwsh",
            vec![
                "-Command".into(),
                "git push --force; curl example.invalid".into(),
            ],
        );
        let classification = classify_process(&invocation);
        assert_eq!(classification.shell_kind, ShellKind::PowerShell);
        assert!(classification.opaque_nested_shell);
        assert_eq!(classification.git_intent, None);
    }

    #[test]
    fn direct_git_argv_is_classified_without_shell_guessing() {
        let invocation =
            ProcessInvocation::new("git", vec!["push".into(), "--force-with-lease".into()]);
        let classification = classify_process(&invocation);
        assert_eq!(classification.git_intent, Some(GitIntent::ForcePush));
        assert_eq!(classification.capability, "git.force_push");
    }

    #[tokio::test]
    async fn denied_process_never_reaches_runner() {
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(InMemoryEventSink::default());
        let executor = GuardedProcessExecutor::new(
            Arc::new(FixedPolicy(Decision::Deny)),
            sink.clone(),
            Arc::new(ApprovalManager::new(10_000)),
            Arc::new(CountingRunner {
                calls: calls.clone(),
            }),
            "test-session",
            "test-agent",
        );
        let result = executor
            .execute(&ProcessInvocation::new("git", vec!["push".into()]), None)
            .await;
        assert!(matches!(result, Err(ProcessError::Denied)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(sink.events().len(), 1);
    }

    #[tokio::test]
    async fn nonzero_exit_is_not_recorded_as_completed() {
        let sink = Arc::new(InMemoryEventSink::default());
        let executor = GuardedProcessExecutor::new(
            Arc::new(FixedPolicy(Decision::Allow)),
            sink.clone(),
            Arc::new(ApprovalManager::new(10_000)),
            Arc::new(ResultRunner {
                result: Mutex::new(Some(Ok(ProcessOutput {
                    status_code: Some(7),
                    stdout: vec![],
                    stderr: b"failed".to_vec(),
                }))),
            }),
            "nonzero-session",
            "test-agent",
        );
        let output = executor
            .execute(&ProcessInvocation::new("fake", vec![]), None)
            .await
            .unwrap();
        assert_eq!(output.status_code, Some(7));
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, "DISPATCHING");
        assert_eq!(events[1].outcome, "PROCESS_EXIT_NONZERO");
    }

    #[tokio::test]
    async fn runner_error_is_recorded_before_returning_error() {
        let sink = Arc::new(InMemoryEventSink::default());
        let executor = GuardedProcessExecutor::new(
            Arc::new(FixedPolicy(Decision::Allow)),
            sink.clone(),
            Arc::new(ApprovalManager::new(10_000)),
            Arc::new(ResultRunner {
                result: Mutex::new(Some(Err(ProcessError::Timeout))),
            }),
            "error-session",
            "test-agent",
        );
        let result = executor
            .execute(&ProcessInvocation::new("fake", vec![]), None)
            .await;
        assert!(matches!(result, Err(ProcessError::Timeout)));
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, "DISPATCHING");
        assert_eq!(events[1].outcome, "PROCESS_TIMEOUT");
    }

    #[tokio::test]
    async fn require_approval_never_dispatches_without_trusted_grant() {
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = GuardedProcessExecutor::new(
            Arc::new(FixedPolicy(Decision::RequireApproval)),
            Arc::new(InMemoryEventSink::default()),
            Arc::new(ApprovalManager::new(10_000)),
            Arc::new(CountingRunner {
                calls: calls.clone(),
            }),
            "test-session",
            "test-agent",
        );
        let result = executor
            .execute(&ProcessInvocation::new("git", vec!["push".into()]), None)
            .await;
        assert!(matches!(result, Err(ProcessError::ApprovalRequired { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
