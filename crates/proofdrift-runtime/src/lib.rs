//! Runtime enforcement primitives for the ProofDrift/ProofDrift codename project.
//!
//! This crate deliberately distinguishes an ProofDrift-controlled broker/process wrapper from
//! OS isolation. Nothing here claims ProofDrift L2 isolation.

pub mod adapter;
pub mod approval;
pub mod canonical;
pub mod event;
pub mod git_guard;
pub mod policy;
pub mod process;

pub use adapter::{
    adapter_capability_matrix, AdapterBoundary, AdapterCapabilities, HarnessAdapter,
};
pub use approval::{
    ApprovalChallenge, ApprovalError, ApprovalGrant, ApprovalManager, Clock, SystemClock,
};
pub use canonical::{canonical_json_bytes, canonical_sha256, redact_json};
pub use event::{
    EnforcementLevel, EnforcementMode, EventSinkError, InMemoryEventSink, RuntimeEvent,
    RuntimeEventSink,
};
pub use git_guard::{classify_git_argv, GitIntent};
pub use policy::{Decision, PolicyDecision, PolicyEvaluator, PolicyRequest};
pub use process::{
    classify_process, CommandRunner, GuardedProcessExecutor, ProcessClassification, ProcessError,
    ProcessInvocation, ProcessOutput, ShellKind, TokioCommandRunner,
};
