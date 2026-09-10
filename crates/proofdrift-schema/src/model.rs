use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type Extensions = BTreeMap<String, Value>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    Repo,
    Commit,
    File,
    Skill,
    Hook,
    Agent,
    Plugin,
    McpServer,
    Model,
    Dataset,
    Binary,
    Container,
    Package,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    Verified,
    Declared,
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArtifactIdentity {
    pub schema_version: String,
    pub artifact_id: String,
    pub artifact_type: ArtifactType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    pub provenance_status: ProvenanceStatus,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Observed,
    Derived,
    Declared,
    External,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvidenceValue<T> {
    pub schema_version: String,
    pub value: T,
    pub evidence_kind: EvidenceKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    Declared,
    Inferred,
    Observed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub schema_version: String,
    pub capability_id: String,
    pub action_family: String,
    pub resource_selector: String,
    #[serde(default)]
    pub constraints: BTreeMap<String, Value>,
    pub source: CapabilitySource,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub risk_tags: Vec<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EnforcementLevel {
    L0,
    L1,
    L2,
    L3,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentEvent {
    pub schema_version: String,
    pub event_id: String,
    pub session_id: String,
    pub sequence: u64,
    pub timestamp_wall: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_monotonic_ns: Option<u64>,
    pub actor: String,
    pub adapter_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_args: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub outcome: String,
    pub enforcement_level: EnforcementLevel,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyRequest {
    pub schema_version: String,
    pub request_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub context: BTreeMap<String, Value>,
    #[serde(default)]
    pub session_path_summary: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ArtifactIdentity>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionKind {
    Allow,
    Deny,
    RequireApproval,
    Observe,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub request_id: String,
    pub decision: DecisionKind,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    pub decision_hash: String,
    pub policy_bundle_digest: String,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Accepted,
    Fixed,
    Suppressed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub schema_version: String,
    pub finding_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub title: String,
    pub explanation: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub artifact_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Value>,
    pub remediation: String,
    pub fingerprint: String,
    pub status: FindingStatus,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveSurface {
    Auth,
    Crypto,
    Secret,
    Db,
    Migration,
    Concurrency,
    Network,
    PublicApi,
    Serialization,
    Config,
    Build,
    Deployment,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlastRadius {
    pub score: u32,
    #[serde(default)]
    pub components: BTreeMap<String, u32>,
    pub explanation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PatchImpact {
    pub schema_version: String,
    pub base: String,
    pub head: String,
    #[serde(default)]
    pub changed_files: Vec<String>,
    #[serde(default)]
    pub changed_symbols: Vec<String>,
    #[serde(default)]
    pub affected_modules: Vec<String>,
    #[serde(default)]
    pub dependency_edges: Vec<String>,
    #[serde(default)]
    pub sensitive_surfaces: Vec<SensitiveSurface>,
    pub blast_radius: BlastRadius,
    #[serde(default)]
    pub analysis_confidence: BTreeMap<String, f64>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TestEvidence {
    pub schema_version: String,
    pub command: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default)]
    pub test_ids: Vec<String>,
    #[serde(default)]
    pub suites: Vec<String>,
    pub exit_status: i32,
    pub duration_ms: u64,
    pub environment_fingerprint: String,
    #[serde(default)]
    pub coverage_refs: Vec<String>,
    #[serde(default)]
    pub changed_code_mapping: BTreeMap<String, Vec<String>>,
    pub observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_result: Option<String>,
    #[serde(default)]
    pub artifact_hashes: BTreeMap<String, String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceRelation {
    Includes,
    Loads,
    BuiltFrom,
    DerivedFrom,
    TrainedOn,
    FineTunedFrom,
    QuantizedFrom,
    Invokes,
    ProducedBy,
    VerifiedBy,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProvenanceEdge {
    pub schema_version: String,
    pub from_artifact_id: String,
    pub relation: ProvenanceRelation,
    pub to_artifact_id: String,
    pub evidence_kind: EvidenceKind,
    pub source: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageMetric {
    pub covered: u64,
    pub total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RiskComponent {
    pub component_id: String,
    pub value: i64,
    pub weight_milli: i64,
    pub rationale: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RiskScoreCard {
    pub formula: String,
    pub total: i64,
    #[serde(default)]
    pub components: Vec<RiskComponent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustReport {
    pub schema_version: String,
    pub scope: Value,
    #[serde(default)]
    pub inventory_summary: BTreeMap<String, u64>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub declared_vs_observed_drift: Vec<TrustDiffChange>,
    #[serde(default)]
    pub policy_decisions: Vec<PolicyDecision>,
    #[serde(default)]
    pub enforcement_coverage: BTreeMap<String, EnforcementLevel>,
    #[serde(default)]
    pub provenance_coverage: BTreeMap<String, CoverageMetric>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_impact: Option<PatchImpact>,
    #[serde(default)]
    pub test_evidence: Vec<TestEvidence>,
    #[serde(default)]
    pub residual_risks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_card: Option<RiskScoreCard>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BundleEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BundleManifest {
    pub schema_version: String,
    pub bundle_version: String,
    pub session_id: String,
    pub created_at: String,
    pub canonicalization: String,
    #[serde(default)]
    pub entries: Vec<BundleEntry>,
    #[serde(default)]
    pub attestation_refs: Vec<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BaselineSnapshot {
    pub schema_version: String,
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactIdentity>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(default)]
    pub enforcement_coverage: BTreeMap<String, EnforcementLevel>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustDiffChangeType {
    ComponentAdded,
    ComponentRemoved,
    ComponentChanged,
    SourceRefDrift,
    HashDrift,
    ToolSchemaDrift,
    CapabilityAdded,
    CapabilityRemoved,
    CapabilityExpanded,
    CapabilityReduced,
    DeclaredInferredMismatch,
    DeclaredObservedMismatch,
    PolicyChanged,
    EnforcementCoverageChanged,
    SecretSurfaceChanged,
    NetworkSurfaceChanged,
    PatchScopeChanged,
    TestEvidenceChanged,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustDiffChange {
    pub change_type: TrustDiffChangeType,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub explanation: String,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustDiff {
    pub schema_version: String,
    pub baseline_name: String,
    pub baseline_digest: String,
    pub current_digest: String,
    #[serde(default)]
    pub changes: Vec<TrustDiffChange>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceReferenceKind {
    Artifact,
    Event,
    Policy,
    Test,
    Runtime,
    External,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvidenceReference {
    pub schema_version: String,
    pub ref_id: String,
    pub kind: EvidenceReferenceKind,
    pub uri: String,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvidenceEnvelope {
    pub schema_version: String,
    pub subject: String,
    #[serde(default)]
    pub provenance: Vec<ArtifactIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub sequence: u64,
    #[serde(default)]
    pub policy_context: BTreeMap<String, Value>,
    #[serde(default)]
    pub capability_context: Vec<Capability>,
    pub decision: Value,
    #[serde(default)]
    pub evidence_refs: Vec<EvidenceReference>,
    pub digest: String,
    #[serde(default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftClass {
    #[serde(rename = "provenance drift")]
    Provenance,
    #[serde(rename = "capability drift")]
    Capability,
    #[serde(rename = "policy drift")]
    Policy,
    #[serde(rename = "runtime drift")]
    Runtime,
    #[serde(rename = "patch-impact drift")]
    PatchImpact,
    #[serde(rename = "test-proof drift")]
    TestProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum EvaluationVerdict {
    Pass,
    Warn,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DriftFinding {
    pub schema_version: String,
    pub finding_id: String,
    pub drift_class: DriftClass,
    pub verdict: EvaluationVerdict,
    pub explanation: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EvaluationDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub subject: String,
    pub verdict: EvaluationVerdict,
    #[serde(default)]
    pub findings: Vec<DriftFinding>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    pub digest: String,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    #[serde(flatten, default)]
    pub extensions: Extensions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_fields_are_preserved() {
        let value = json!({
            "schema_version":"1.0.0",
            "artifact_id":"artifact:test",
            "artifact_type":"file",
            "name":"x",
            "provenance_status":"unknown",
            "future_field":{"x":1}
        });
        let artifact: ArtifactIdentity = serde_json::from_value(value).unwrap();
        assert_eq!(
            artifact.extensions.get("future_field"),
            Some(&json!({"x":1}))
        );
        let roundtrip = serde_json::to_value(&artifact).unwrap();
        assert_eq!(roundtrip["future_field"], json!({"x":1}));
    }

    #[test]
    fn evidence_kinds_do_not_collapse_declared_inferred_and_observed() {
        assert_ne!(CapabilitySource::Declared, CapabilitySource::Inferred);
        assert_ne!(CapabilitySource::Inferred, CapabilitySource::Observed);
    }
}
