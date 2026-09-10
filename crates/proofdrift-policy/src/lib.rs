//! Cedar-backed policy engine for ProofDrift/ProofDrift codename.
//!
//! Security semantics:
//! - Cedar is authoritative for permit/forbid; a Cedar deny always wins.
//! - REQUIRE_APPROVAL and OBSERVE are transparent deterministic overlays applied
//!   only after Cedar returns Allow.
//! - Unknown capabilities fail closed before Cedar evaluation.
//! - Approval grants are one-time, expiring, and bound to both normalized
//!   request digest and policy bundle digest.

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityId, EntityTypeName, EntityUid,
    Policy, PolicyId, PolicySet, Request,
};
use proofdrift_capabilities::{canonicalize_resource, is_known_capability, Capability};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Shared PolicyRequest/PolicyDecision wire schema version.
pub const POLICY_SCHEMA_VERSION: &str = "1.0.0";
/// Policy-pack schema version; intentionally separate from the shared wire schema.
pub const POLICY_PACK_SCHEMA_VERSION: &str = "0.1";

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn default_request_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("req-{now:032x}-{:08x}-{sequence:016x}", std::process::id())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    RequireApproval,
    Observe,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Value>,
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, Value>,
}

impl PolicyRequest {
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        let principal = principal.into();
        let action = action.into();
        let resource = resource.into();
        let request_id = default_request_id();
        Self {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            request_id,
            principal,
            action,
            resource,
            context: BTreeMap::new(),
            session_path_summary: Vec::new(),
            capability: None,
            provenance: None,
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_request_id(
        request_id: impl Into<String>,
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        let mut request = Self::new(principal, action, resource);
        request.request_id = request_id.into();
        request
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBinding {
    #[serde(rename = "request_digest", alias = "request_hash")]
    pub request_hash: String,
    pub policy_bundle_digest: String,
    pub decision_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub schema_version: String,
    pub decision_id: String,
    pub request_id: String,
    pub decision: PolicyDecisionKind,
    pub policy_ids: Vec<String>,
    pub reason_codes: Vec<String>,
    pub diagnostics: Vec<String>,
    pub decision_hash: String,
    pub policy_bundle_digest: String,
    /// Normalized TOCTOU binding digest. Internal code keeps the historical
    /// `request_hash` field name while the wire contract uses `request_digest`.
    #[serde(rename = "request_digest", alias = "request_hash")]
    pub request_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_binding: Option<ExecutionBinding>,
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedCedarPolicy {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayRule {
    pub id: String,
    pub actions: BTreeSet<String>,
    pub resource_pattern: Option<String>,
    #[serde(default)]
    pub required_context_keys: BTreeSet<String>,
}

impl OverlayRule {
    fn scope_matches(&self, request: &NormalizedRequest) -> bool {
        if !self.actions.is_empty() && !self.actions.contains(&request.action) {
            return false;
        }
        match &self.resource_pattern {
            Some(pattern) => wildcard_match(pattern, &request.resource),
            None => true,
        }
    }

    fn missing_context_keys(&self, request: &NormalizedRequest) -> Vec<String> {
        self.required_context_keys
            .iter()
            .filter(|key| !request.context.contains_key(*key))
            .cloned()
            .collect()
    }

    fn matches(&self, request: &NormalizedRequest) -> bool {
        self.scope_matches(request) && self.missing_context_keys(request).is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPack {
    pub schema_version: String,
    pub name: String,
    pub version: String,
    pub cedar_policies: Vec<NamedCedarPolicy>,
    #[serde(default)]
    pub approval_rules: Vec<OverlayRule>,
    #[serde(default)]
    pub observe_rules: Vec<OverlayRule>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl PolicyPack {
    pub fn from_json(input: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(input).map_err(PolicyError::PackJson)
    }

    pub fn digest(&self) -> Result<String, PolicyError> {
        let normalized = self.normalized_for_digest();
        let bytes = serde_json::to_vec(&normalized).map_err(PolicyError::PackJson)?;
        Ok(hex_sha256(&bytes))
    }

    fn normalized_for_digest(&self) -> Self {
        let mut clone = self.clone();
        clone
            .cedar_policies
            .sort_by(|a, b| a.id.cmp(&b.id).then(a.text.cmp(&b.text)));
        clone.approval_rules.sort_by(|a, b| a.id.cmp(&b.id));
        clone.observe_rules.sort_by(|a, b| a.id.cmp(&b.id));
        clone
    }
}

#[derive(Debug, Clone)]
pub struct CompiledPolicyPack {
    pub pack: PolicyPack,
    pub digest: String,
    policies: PolicySet,
}

impl CompiledPolicyPack {
    pub fn compile(pack: PolicyPack) -> Result<Self, PolicyError> {
        if pack.schema_version != POLICY_PACK_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedPolicyPackSchema(
                pack.schema_version.clone(),
            ));
        }

        let digest = pack.digest()?;
        let mut policy_set = PolicySet::new();
        let mut seen_ids = BTreeSet::new();
        for item in &pack.cedar_policies {
            if item.id.trim().is_empty() {
                return Err(PolicyError::InvalidPolicyPack(
                    "Cedar policy id must not be empty".into(),
                ));
            }
            if !seen_ids.insert(item.id.clone()) {
                return Err(PolicyError::DuplicatePolicyId(item.id.clone()));
            }
            let policy = Policy::parse(Some(PolicyId::new(&item.id)), &item.text)
                .map_err(|e| PolicyError::CedarParse(item.id.clone(), e.to_string()))?;
            policy_set
                .add(policy)
                .map_err(|e| PolicyError::CedarSet(item.id.clone(), e.to_string()))?;
        }

        for rule in pack.approval_rules.iter().chain(pack.observe_rules.iter()) {
            if rule.id.trim().is_empty() {
                return Err(PolicyError::InvalidPolicyPack(
                    "overlay rule id must not be empty".into(),
                ));
            }
            if !seen_ids.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
            for action in &rule.actions {
                if !is_known_capability(action) {
                    return Err(PolicyError::UnknownOverlayCapability(
                        rule.id.clone(),
                        action.clone(),
                    ));
                }
            }
            if rule
                .required_context_keys
                .iter()
                .any(|key| key.trim().is_empty())
            {
                return Err(PolicyError::InvalidPolicyPack(format!(
                    "overlay rule {} contains an empty required context key",
                    rule.id
                )));
            }
        }

        Ok(Self {
            pack,
            digest,
            policies: policy_set,
        })
    }
}

#[derive(Debug)]
pub struct PolicyEngine {
    authorizer: Authorizer,
    cache: RwLock<BTreeMap<String, Arc<CompiledPolicyPack>>>,
    max_cache_entries: usize,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(64)
    }
}

impl PolicyEngine {
    pub fn new(max_cache_entries: usize) -> Self {
        Self {
            authorizer: Authorizer::new(),
            cache: RwLock::new(BTreeMap::new()),
            max_cache_entries: max_cache_entries.max(1),
        }
    }

    pub fn compile_cached(&self, pack: PolicyPack) -> Result<Arc<CompiledPolicyPack>, PolicyError> {
        let digest = pack.digest()?;
        if let Some(existing) = self
            .cache
            .read()
            .map_err(|_| PolicyError::LockPoisoned)?
            .get(&digest)
            .cloned()
        {
            return Ok(existing);
        }
        let compiled = Arc::new(CompiledPolicyPack::compile(pack)?);
        let mut cache = self.cache.write().map_err(|_| PolicyError::LockPoisoned)?;
        if let Some(existing) = cache.get(&digest).cloned() {
            return Ok(existing);
        }
        while cache.len() >= self.max_cache_entries {
            if let Some(first) = cache.keys().next().cloned() {
                cache.remove(&first);
            } else {
                break;
            }
        }
        cache.insert(digest, compiled.clone());
        Ok(compiled)
    }

    pub fn evaluate(
        &self,
        pack: &CompiledPolicyPack,
        request: &PolicyRequest,
        verified_approval: Option<&VerifiedApproval>,
    ) -> Result<PolicyDecision, PolicyError> {
        let raw_request_hash = hash_unvalidated_request(request)?;
        let decision_request_id = if request.request_id.trim().is_empty() {
            format!("invalid-{}", &raw_request_hash[..16])
        } else {
            request.request_id.trim().to_string()
        };

        if request.schema_version != POLICY_SCHEMA_VERSION {
            return build_decision(
                PolicyDecisionKind::Deny,
                Vec::new(),
                vec!["UNSUPPORTED_REQUEST_SCHEMA".into()],
                vec![format!(
                    "expected request schema {}, got {}",
                    POLICY_SCHEMA_VERSION, request.schema_version
                )],
                &pack.digest,
                &decision_request_id,
                &raw_request_hash,
            );
        }
        if request.request_id.trim().is_empty() {
            return build_decision(
                PolicyDecisionKind::Deny,
                Vec::new(),
                vec!["INVALID_REQUEST_ID".into()],
                vec!["request_id must not be empty".into()],
                &pack.digest,
                &decision_request_id,
                &raw_request_hash,
            );
        }
        if request.principal.trim().is_empty() {
            return build_decision(
                PolicyDecisionKind::Deny,
                Vec::new(),
                vec!["INVALID_PRINCIPAL".into()],
                vec!["principal must not be empty".into()],
                &pack.digest,
                &decision_request_id,
                &raw_request_hash,
            );
        }
        if let Some(capability) = &request.capability {
            if let Err(error) = capability.validate() {
                return build_decision(
                    PolicyDecisionKind::Deny,
                    Vec::new(),
                    vec!["INVALID_CAPABILITY_CONTRACT".into()],
                    vec![error.to_string()],
                    &pack.digest,
                    &decision_request_id,
                    &raw_request_hash,
                );
            }
            if capability.capability_id != request.action.trim() {
                return build_decision(
                    PolicyDecisionKind::Deny,
                    Vec::new(),
                    vec!["CAPABILITY_ACTION_MISMATCH".into()],
                    vec![format!(
                        "embedded capability {} does not match request action {}",
                        capability.capability_id, request.action
                    )],
                    &pack.digest,
                    &decision_request_id,
                    &raw_request_hash,
                );
            }
        }
        if !is_known_capability(request.action.trim()) {
            return build_decision(
                PolicyDecisionKind::Deny,
                Vec::new(),
                vec!["UNKNOWN_CAPABILITY".into()],
                vec![format!("unknown canonical capability: {}", request.action)],
                &pack.digest,
                &decision_request_id,
                &raw_request_hash,
            );
        }

        let normalized = normalize_request(request)?;
        let request_hash = normalized.digest()?;
        let cedar_request = to_cedar_request(&normalized)?;
        let response =
            self.authorizer
                .is_authorized(&cedar_request, &pack.policies, &Entities::empty());

        let mut policy_ids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        policy_ids.sort();
        policy_ids.dedup();

        let mut diagnostics: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        diagnostics.sort();
        diagnostics.dedup();

        if response.decision() == CedarDecision::Deny {
            let mut reasons = vec!["CEDAR_DENY".into()];
            if !diagnostics.is_empty() {
                reasons.push("CEDAR_EVAL_ERROR".into());
            }
            return build_decision(
                PolicyDecisionKind::Deny,
                policy_ids,
                reasons,
                diagnostics,
                &pack.digest,
                &normalized.request_id,
                &request_hash,
            );
        }

        // Overlay context is security-significant. If a rule's action/resource
        // scope applies but context needed to decide it is absent, do not let
        // the request fall through to a broader ALLOW.
        let scoped_overlay_rules: Vec<&OverlayRule> = pack
            .pack
            .approval_rules
            .iter()
            .chain(pack.pack.observe_rules.iter())
            .filter(|rule| rule.scope_matches(&normalized))
            .collect();
        let mut missing_context = BTreeSet::new();
        let mut missing_context_rule_ids = Vec::new();
        for rule in scoped_overlay_rules {
            let missing = rule.missing_context_keys(&normalized);
            if !missing.is_empty() {
                missing_context_rule_ids.push(rule.id.clone());
                missing_context.extend(missing);
            }
        }
        if !missing_context.is_empty() {
            policy_ids.extend(missing_context_rule_ids);
            diagnostics.push(format!(
                "missing required policy context keys: {}",
                missing_context.into_iter().collect::<Vec<_>>().join(",")
            ));
            return build_decision(
                PolicyDecisionKind::Deny,
                policy_ids,
                vec!["MISSING_REQUIRED_CONTEXT".into()],
                diagnostics,
                &pack.digest,
                &normalized.request_id,
                &request_hash,
            );
        }

        let matching_approval: Vec<&OverlayRule> = pack
            .pack
            .approval_rules
            .iter()
            .filter(|rule| rule.matches(&normalized))
            .collect();
        if !matching_approval.is_empty() {
            let approval_matches = verified_approval
                .map(|approval| {
                    approval.request_hash == request_hash
                        && approval.policy_bundle_digest == pack.digest
                })
                .unwrap_or(false);
            if !approval_matches {
                policy_ids.extend(matching_approval.iter().map(|r| r.id.clone()));
                policy_ids.sort();
                policy_ids.dedup();
                return build_decision(
                    PolicyDecisionKind::RequireApproval,
                    policy_ids,
                    vec!["APPROVAL_REQUIRED".into()],
                    diagnostics,
                    &pack.digest,
                    &normalized.request_id,
                    &request_hash,
                );
            }
            policy_ids.extend(matching_approval.iter().map(|r| r.id.clone()));
        }

        let matching_observe: Vec<&OverlayRule> = pack
            .pack
            .observe_rules
            .iter()
            .filter(|rule| rule.matches(&normalized))
            .collect();
        if !matching_observe.is_empty() {
            policy_ids.extend(matching_observe.iter().map(|r| r.id.clone()));
            policy_ids.sort();
            policy_ids.dedup();
            return build_decision(
                PolicyDecisionKind::Observe,
                policy_ids,
                vec!["OBSERVE_ONLY_RULE".into()],
                diagnostics,
                &pack.digest,
                &normalized.request_id,
                &request_hash,
            );
        }

        policy_ids.sort();
        policy_ids.dedup();
        build_decision(
            PolicyDecisionKind::Allow,
            policy_ids,
            vec!["CEDAR_ALLOW".into()],
            diagnostics,
            &pack.digest,
            &normalized.request_id,
            &request_hash,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct NormalizedRequest {
    schema_version: String,
    request_id: String,
    principal: String,
    action: String,
    resource: String,
    context: BTreeMap<String, Value>,
    session_path_summary: Vec<String>,
    capability: Option<Capability>,
    provenance: Option<Value>,
    extensions: BTreeMap<String, Value>,
}

impl NormalizedRequest {
    fn digest(&self) -> Result<String, PolicyError> {
        let bytes = serde_json::to_vec(self).map_err(PolicyError::RequestJson)?;
        Ok(hex_sha256(&bytes))
    }
}

pub fn request_digest(request: &PolicyRequest) -> Result<String, PolicyError> {
    if request.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::InvalidRequest(format!(
            "expected schema {}, got {}",
            POLICY_SCHEMA_VERSION, request.schema_version
        )));
    }
    if request.request_id.trim().is_empty() {
        return Err(PolicyError::InvalidRequest(
            "request_id must not be empty".into(),
        ));
    }
    if request.principal.trim().is_empty() {
        return Err(PolicyError::InvalidRequest(
            "principal must not be empty".into(),
        ));
    }
    if !is_known_capability(request.action.trim()) {
        return Err(PolicyError::InvalidRequest(format!(
            "unknown capability: {}",
            request.action
        )));
    }
    if let Some(capability) = &request.capability {
        capability
            .validate()
            .map_err(|error| PolicyError::InvalidRequest(error.to_string()))?;
        if capability.capability_id != request.action.trim() {
            return Err(PolicyError::InvalidRequest(format!(
                "embedded capability {} does not match action {}",
                capability.capability_id, request.action
            )));
        }
    }
    normalize_request(request)?.digest()
}

fn hash_unvalidated_request(request: &PolicyRequest) -> Result<String, PolicyError> {
    let bytes = serde_json::to_vec(request).map_err(PolicyError::RequestJson)?;
    Ok(hex_sha256(&bytes))
}

fn normalize_request(request: &PolicyRequest) -> Result<NormalizedRequest, PolicyError> {
    let canonical_resource = canonicalize_resource(&request.action, &request.resource)
        .map_err(|e| PolicyError::Resource(e.to_string()))?;
    let mut path = request.session_path_summary.clone();
    path.sort();
    path.dedup();
    Ok(NormalizedRequest {
        schema_version: request.schema_version.clone(),
        request_id: request.request_id.trim().to_string(),
        principal: request.principal.trim().to_string(),
        action: request.action.trim().to_string(),
        resource: canonical_resource.normalized,
        context: request.context.clone(),
        session_path_summary: path,
        capability: request.capability.clone(),
        provenance: request.provenance.clone(),
        extensions: request.extensions.clone(),
    })
}

fn to_cedar_request(request: &NormalizedRequest) -> Result<Request, PolicyError> {
    let principal = uid("Principal", &request.principal)?;
    let action = uid("Action", &request.action)?;
    let resource = uid("Resource", &request.resource)?;

    let mut context_map = Map::new();
    for (key, value) in &request.context {
        context_map.insert(key.clone(), value.clone());
    }
    context_map.insert(
        "capability_id".into(),
        Value::String(request.action.clone()),
    );
    context_map.insert(
        "resource_normalized".into(),
        Value::String(request.resource.clone()),
    );
    context_map.insert(
        "session_path_summary".into(),
        Value::Array(
            request
                .session_path_summary
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if let Some(provenance) = &request.provenance {
        context_map.insert("provenance".into(), provenance.clone());
    }
    if let Some(capability) = &request.capability {
        context_map.insert(
            "capability".into(),
            serde_json::to_value(capability).map_err(PolicyError::RequestJson)?,
        );
    }
    let context = Context::from_json_value(Value::Object(context_map), None)
        .map_err(|e| PolicyError::CedarContext(e.to_string()))?;
    Request::new(principal, action, resource, context, None)
        .map_err(|e| PolicyError::CedarRequest(e.to_string()))
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let entity_type = EntityTypeName::from_str(entity_type)
        .map_err(|e| PolicyError::CedarIdentity(e.to_string()))?;
    let entity_id =
        EntityId::from_str(id).map_err(|e| PolicyError::CedarIdentity(e.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(entity_type, entity_id))
}

fn build_decision(
    decision: PolicyDecisionKind,
    mut policy_ids: Vec<String>,
    mut reason_codes: Vec<String>,
    mut diagnostics: Vec<String>,
    policy_digest: &str,
    request_id: &str,
    request_hash: &str,
) -> Result<PolicyDecision, PolicyError> {
    policy_ids.sort();
    policy_ids.dedup();
    reason_codes.sort();
    reason_codes.dedup();
    diagnostics.sort();
    diagnostics.dedup();

    #[derive(Serialize)]
    struct DecisionMaterial<'a> {
        schema_version: &'a str,
        request_id: &'a str,
        decision: PolicyDecisionKind,
        policy_ids: &'a [String],
        reason_codes: &'a [String],
        diagnostics: &'a [String],
        policy_bundle_digest: &'a str,
        request_hash: &'a str,
    }
    let material = DecisionMaterial {
        schema_version: POLICY_SCHEMA_VERSION,
        request_id,
        decision,
        policy_ids: &policy_ids,
        reason_codes: &reason_codes,
        diagnostics: &diagnostics,
        policy_bundle_digest: policy_digest,
        request_hash,
    };
    let decision_hash =
        hex_sha256(&serde_json::to_vec(&material).map_err(PolicyError::RequestJson)?);
    let decision_id = format!("dec-{decision_hash}");
    let execution_binding =
        matches!(decision, PolicyDecisionKind::Allow).then(|| ExecutionBinding {
            request_hash: request_hash.to_string(),
            policy_bundle_digest: policy_digest.to_string(),
            decision_hash: decision_hash.clone(),
        });
    Ok(PolicyDecision {
        schema_version: POLICY_SCHEMA_VERSION.into(),
        decision_id,
        request_id: request_id.to_string(),
        decision,
        policy_ids,
        reason_codes,
        diagnostics,
        decision_hash,
        policy_bundle_digest: policy_digest.to_string(),
        request_hash: request_hash.to_string(),
        execution_binding,
        extensions: BTreeMap::new(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalGrant {
    pub grant_id: String,
    pub request_hash: String,
    pub policy_bundle_digest: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    grant_id: String,
    request_hash: String,
    policy_bundle_digest: String,
}

impl VerifiedApproval {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
}

#[derive(Debug, Clone)]
struct ApprovalRecord {
    grant: ApprovalGrant,
    consumed: bool,
}

#[derive(Debug, Default)]
pub struct ApprovalRegistry {
    records: Mutex<BTreeMap<String, ApprovalRecord>>,
}

impl ApprovalRegistry {
    /// Register a grant generated by a trusted UI/broker. `grant_id` must be a
    /// high-entropy opaque identifier in production; this crate intentionally
    /// does not invent its own signing or RNG protocol.
    pub fn issue(&self, grant: ApprovalGrant) -> Result<(), PolicyError> {
        if grant.grant_id.trim().is_empty() {
            return Err(PolicyError::InvalidApproval("empty grant id".into()));
        }
        let mut records = self.records.lock().map_err(|_| PolicyError::LockPoisoned)?;
        if records.contains_key(&grant.grant_id) {
            return Err(PolicyError::DuplicateApproval(grant.grant_id));
        }
        records.insert(
            grant.grant_id.clone(),
            ApprovalRecord {
                grant,
                consumed: false,
            },
        );
        Ok(())
    }

    pub fn consume(
        &self,
        grant_id: &str,
        expected_request_hash: &str,
        expected_policy_digest: &str,
        now_unix_ms: u64,
    ) -> Result<VerifiedApproval, PolicyError> {
        let mut records = self.records.lock().map_err(|_| PolicyError::LockPoisoned)?;
        let record = records
            .get_mut(grant_id)
            .ok_or_else(|| PolicyError::UnknownApproval(grant_id.to_string()))?;
        if record.consumed {
            return Err(PolicyError::ApprovalReplay(grant_id.to_string()));
        }
        if now_unix_ms >= record.grant.expires_at_unix_ms {
            return Err(PolicyError::ApprovalExpired(grant_id.to_string()));
        }
        if record.grant.request_hash != expected_request_hash {
            return Err(PolicyError::ApprovalRequestMismatch);
        }
        if record.grant.policy_bundle_digest != expected_policy_digest {
            return Err(PolicyError::ApprovalPolicyMismatch);
        }
        record.consumed = true;
        Ok(VerifiedApproval {
            grant_id: record.grant.grant_id.clone(),
            request_hash: record.grant.request_hash.clone(),
            policy_bundle_digest: record.grant.policy_bundle_digest.clone(),
        })
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy pack JSON error: {0}")]
    PackJson(serde_json::Error),
    #[error("request JSON error: {0}")]
    RequestJson(serde_json::Error),
    #[error("invalid policy request: {0}")]
    InvalidRequest(String),
    #[error("unsupported policy-pack schema version: {0}")]
    UnsupportedPolicyPackSchema(String),
    #[error("invalid policy pack: {0}")]
    InvalidPolicyPack(String),
    #[error("duplicate Cedar policy id: {0}")]
    DuplicatePolicyId(String),
    #[error("duplicate policy/overlay rule id: {0}")]
    DuplicateRuleId(String),
    #[error("unknown overlay capability in rule {0}: {1}")]
    UnknownOverlayCapability(String, String),
    #[error("Cedar parse failed for {0}: {1}")]
    CedarParse(String, String),
    #[error("Cedar policy set failed for {0}: {1}")]
    CedarSet(String, String),
    #[error("Cedar context failed: {0}")]
    CedarContext(String),
    #[error("Cedar request failed: {0}")]
    CedarRequest(String),
    #[error("Cedar identity failed: {0}")]
    CedarIdentity(String),
    #[error("resource normalization failed: {0}")]
    Resource(String),
    #[error("policy cache/approval lock poisoned")]
    LockPoisoned,
    #[error("invalid approval: {0}")]
    InvalidApproval(String),
    #[error("duplicate approval grant: {0}")]
    DuplicateApproval(String),
    #[error("unknown approval grant: {0}")]
    UnknownApproval(String),
    #[error("approval grant replay denied: {0}")]
    ApprovalReplay(String),
    #[error("approval grant expired: {0}")]
    ApprovalExpired(String),
    #[error("approval grant is bound to a different request")]
    ApprovalRequestMismatch,
    #[error("approval grant is bound to a different policy bundle")]
    ApprovalPolicyMismatch,
}

pub fn lint_pack(pack: &PolicyPack) -> Vec<String> {
    let mut diagnostics = Vec::new();
    if pack.schema_version != POLICY_PACK_SCHEMA_VERSION {
        diagnostics.push(format!("UNSUPPORTED_POLICY_SCHEMA:{}", pack.schema_version));
    }
    if pack.cedar_policies.is_empty() {
        diagnostics.push("NO_CEDAR_POLICIES".into());
    }

    let mut ids = BTreeSet::new();
    for policy in &pack.cedar_policies {
        if policy.id.trim().is_empty() {
            diagnostics.push("EMPTY_POLICY_ID".into());
        }
        if !ids.insert(policy.id.clone()) {
            diagnostics.push(format!("DUPLICATE_RULE_ID:{}", policy.id));
        }
        if let Err(error) = Policy::parse(Some(PolicyId::new(&policy.id)), &policy.text) {
            diagnostics.push(format!("CEDAR_PARSE:{}:{}", policy.id, error));
        }
    }

    for rule in pack.approval_rules.iter().chain(pack.observe_rules.iter()) {
        if rule.id.trim().is_empty() {
            diagnostics.push("EMPTY_OVERLAY_RULE_ID".into());
        }
        if !ids.insert(rule.id.clone()) {
            diagnostics.push(format!("DUPLICATE_RULE_ID:{}", rule.id));
        }
        if rule
            .required_context_keys
            .iter()
            .any(|key| key.trim().is_empty())
        {
            diagnostics.push(format!("EMPTY_REQUIRED_CONTEXT_KEY:{}", rule.id));
        }
        for action in &rule.actions {
            if !is_known_capability(action) {
                diagnostics.push(format!("UNKNOWN_OVERLAY_CAPABILITY:{}:{}", rule.id, action));
            }
        }
    }
    diagnostics.sort();
    diagnostics.dedup();
    diagnostics
}

pub fn built_in_policy_pack(name: &str) -> Option<PolicyPack> {
    let permit_reads = r#"permit(principal, action, resource) when { action in [Action::"fs.read", Action::"git.read", Action::"mcp.list", Action::"db.read", Action::"cloud.read"] };"#;
    let permit_safe_local = r#"permit(principal, action, resource) when { action in [Action::"fs.read", Action::"fs.write", Action::"fs.create", Action::"process.exec", Action::"git.read", Action::"git.commit", Action::"mcp.list", Action::"mcp.call", Action::"network.connect"] };"#;
    let permit_all = "permit(principal, action, resource);";
    let forbid_secret =
        r#"forbid(principal, action, resource) when { action == Action::"secret.egress" };"#;
    let forbid_force_main = r#"forbid(principal, action, resource) when { action == Action::"git.force_push" && resource == Resource::"origin/main" };"#;

    let base = |name: &str, policies: Vec<(&str, &str)>| PolicyPack {
        schema_version: POLICY_PACK_SCHEMA_VERSION.into(),
        name: name.into(),
        version: "0.1.0".into(),
        cedar_policies: policies
            .into_iter()
            .map(|(id, text)| NamedCedarPolicy {
                id: id.into(),
                text: text.into(),
            })
            .collect(),
        approval_rules: Vec::new(),
        observe_rules: Vec::new(),
        metadata: BTreeMap::new(),
    };

    match name {
        "safe-local-dev" => {
            let mut pack = base(
                name,
                vec![
                    ("allow-safe-local", permit_safe_local),
                    ("deny-secret-egress", forbid_secret),
                    ("deny-force-main", forbid_force_main),
                ],
            );
            pack.approval_rules.push(OverlayRule {
                id: "approval-network-connect".into(),
                actions: BTreeSet::from(["network.connect".into()]),
                resource_pattern: Some("*".into()),
                required_context_keys: BTreeSet::new(),
            });
            Some(pack)
        }
        "read-only-audit" => Some(base(name, vec![("allow-read-only", permit_reads)])),
        "no-secret-egress" => Some(base(
            name,
            vec![
                ("allow-base", permit_all),
                ("deny-secret-egress", forbid_secret),
            ],
        )),
        "protected-git-main" => Some(base(
            name,
            vec![
                ("allow-base", permit_all),
                ("deny-force-main", forbid_force_main),
            ],
        )),
        "constrained-mcp" => {
            let mut pack = base(
                name,
                vec![(
                    "allow-mcp",
                    r#"permit(principal, action, resource) when { action in [Action::"mcp.list", Action::"mcp.call"] };"#,
                )],
            );
            pack.approval_rules.push(OverlayRule {
                id: "approval-sensitive-mcp".into(),
                actions: BTreeSet::from(["mcp.call".into()]),
                resource_pattern: Some("dangerous.*".into()),
                required_context_keys: BTreeSet::new(),
            });
            Some(pack)
        }
        "CI-unattended" | "ci-unattended" => Some(base(
            "ci-unattended",
            vec![
                (
                    "allow-ci-read-exec",
                    r#"permit(principal, action, resource) when { action in [Action::"fs.read", Action::"git.read", Action::"process.exec", Action::"mcp.list", Action::"db.read"] };"#,
                ),
                ("deny-secret-egress", forbid_secret),
                ("deny-force-main", forbid_force_main),
            ],
        )),
        _ => None,
    }
}

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return candidate == prefix || candidate.starts_with(&format!("{prefix}/"));
    }
    if !pattern.contains('*') {
        return pattern == candidate;
    }
    let mut remaining = candidate;
    let starts_with_wildcard = pattern.starts_with('*');
    let mut first_part = true;
    for part in pattern.split('*').filter(|p| !p.is_empty()) {
        if let Some(index) = remaining.find(part) {
            if first_part && !starts_with_wildcard && index != 0 {
                return false;
            }
            remaining = &remaining[index + part.len()..];
        } else {
            return false;
        }
        first_part = false;
    }
    pattern.ends_with('*') || remaining.is_empty()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_and_pack(name: &str) -> (PolicyEngine, Arc<CompiledPolicyPack>) {
        let engine = PolicyEngine::default();
        let pack = engine
            .compile_cached(built_in_policy_pack(name).unwrap())
            .unwrap();
        (engine, pack)
    }

    #[test]
    fn cedar_deny_wins_over_permit() {
        let (engine, pack) = engine_and_pack("no-secret-egress");
        let request = PolicyRequest::new("agent", "secret.egress", "C:/secrets/key.txt");
        let decision = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert!(decision
            .policy_ids
            .iter()
            .any(|id| id == "deny-secret-egress"));
        assert!(decision.execution_binding.is_none());
    }

    #[test]
    fn unknown_capability_fails_closed_before_cedar() {
        let (engine, pack) = engine_and_pack("no-secret-egress");
        let request = PolicyRequest::new("agent", "root.magic", "*");
        let decision = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.reason_codes, vec!["UNKNOWN_CAPABILITY"]);
    }

    #[test]
    fn protected_main_force_push_is_denied_but_feature_branch_can_pass() {
        let (engine, pack) = engine_and_pack("protected-git-main");
        let main = engine
            .evaluate(
                &pack,
                &PolicyRequest::new("agent", "git.force_push", "origin/main"),
                None,
            )
            .unwrap();
        let feature = engine
            .evaluate(
                &pack,
                &PolicyRequest::new("agent", "git.force_push", "origin/feature/x"),
                None,
            )
            .unwrap();
        assert_eq!(main.decision, PolicyDecisionKind::Deny);
        assert_eq!(feature.decision, PolicyDecisionKind::Allow);
    }

    #[test]
    fn approval_is_one_time_expiring_and_bound_to_request_and_policy() {
        let (engine, pack) = engine_and_pack("safe-local-dev");
        let request = PolicyRequest::new("agent", "network.connect", "github.com:443");
        let first = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(first.decision, PolicyDecisionKind::RequireApproval);

        let registry = ApprovalRegistry::default();
        registry
            .issue(ApprovalGrant {
                grant_id: "synthetic-high-entropy-test-id".into(),
                request_hash: first.request_hash.clone(),
                policy_bundle_digest: pack.digest.clone(),
                expires_at_unix_ms: 2_000,
            })
            .unwrap();
        let verified = registry
            .consume(
                "synthetic-high-entropy-test-id",
                &first.request_hash,
                &pack.digest,
                1_000,
            )
            .unwrap();
        let allowed = engine.evaluate(&pack, &request, Some(&verified)).unwrap();
        assert_eq!(allowed.decision, PolicyDecisionKind::Allow);
        assert!(allowed.execution_binding.is_some());
        assert!(matches!(
            registry.consume(
                "synthetic-high-entropy-test-id",
                &first.request_hash,
                &pack.digest,
                1_001
            ),
            Err(PolicyError::ApprovalReplay(_))
        ));
    }

    #[test]
    fn approval_cannot_be_replayed_for_different_request() {
        let (_engine, pack) = engine_and_pack("safe-local-dev");
        let a = PolicyRequest::new("agent", "network.connect", "github.com:443");
        let b = PolicyRequest::new("agent", "network.connect", "example.com:443");
        let a_hash = request_digest(&a).unwrap();
        let b_hash = request_digest(&b).unwrap();
        assert_ne!(a_hash, b_hash);
        let registry = ApprovalRegistry::default();
        registry
            .issue(ApprovalGrant {
                grant_id: "grant-b".into(),
                request_hash: a_hash,
                policy_bundle_digest: pack.digest.clone(),
                expires_at_unix_ms: 10,
            })
            .unwrap();
        assert!(matches!(
            registry.consume("grant-b", &b_hash, &pack.digest, 1),
            Err(PolicyError::ApprovalRequestMismatch)
        ));
    }

    #[test]
    fn request_and_decision_hashes_are_stable_under_context_map_insertion_order() {
        let (engine, pack) = engine_and_pack("read-only-audit");
        let mut a = PolicyRequest::with_request_id(
            "req-stable",
            "agent",
            "fs.read",
            r"c:\\repo\\src\\lib.rs",
        );
        a.context.insert("z".into(), Value::Bool(true));
        a.context.insert("a".into(), Value::String("x".into()));
        a.session_path_summary = vec!["b".into(), "a".into(), "a".into()];
        let mut b =
            PolicyRequest::with_request_id("req-stable", "agent", "fs.read", "C:/repo/src/lib.rs");
        b.context.insert("a".into(), Value::String("x".into()));
        b.context.insert("z".into(), Value::Bool(true));
        b.session_path_summary = vec!["a".into(), "b".into()];
        let da = engine.evaluate(&pack, &a, None).unwrap();
        let db = engine.evaluate(&pack, &b, None).unwrap();
        assert_eq!(da.request_hash, db.request_hash);
        assert_eq!(da.decision_hash, db.decision_hash);
    }

    #[test]
    fn malformed_parent_traversal_is_not_authorized() {
        let (engine, pack) = engine_and_pack("read-only-audit");
        let request = PolicyRequest::new("agent", "fs.read", "../outside/secret.txt");
        assert!(matches!(
            engine.evaluate(&pack, &request, None),
            Err(PolicyError::Resource(_))
        ));
    }

    #[test]
    fn unicode_domain_normalization_binds_approval_to_ascii_host() {
        let (engine, pack) = engine_and_pack("safe-local-dev");
        let unicode = PolicyRequest::with_request_id(
            "req-idna",
            "agent",
            "network.connect",
            "https://bücher.example/path",
        );
        let ascii = PolicyRequest::with_request_id(
            "req-idna",
            "agent",
            "network.connect",
            "xn--bcher-kva.example:443",
        );
        assert_eq!(
            request_digest(&unicode).unwrap(),
            request_digest(&ascii).unwrap()
        );
        assert_eq!(
            engine.evaluate(&pack, &unicode, None).unwrap().decision,
            PolicyDecisionKind::RequireApproval
        );
    }

    #[test]
    fn cache_is_keyed_by_policy_digest() {
        let engine = PolicyEngine::new(2);
        let pack = built_in_policy_pack("read-only-audit").unwrap();
        let a = engine.compile_cached(pack.clone()).unwrap();
        let b = engine.compile_cached(pack).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn lint_detects_unknown_overlay_capability() {
        let mut pack = built_in_policy_pack("read-only-audit").unwrap();
        pack.approval_rules.push(OverlayRule {
            id: "bad".into(),
            actions: BTreeSet::from(["unknown.action".into()]),
            resource_pattern: None,
            required_context_keys: BTreeSet::new(),
        });
        assert!(lint_pack(&pack)
            .iter()
            .any(|line| line.contains("UNKNOWN_OVERLAY_CAPABILITY")));
    }

    #[test]
    fn missing_overlay_context_fails_closed() {
        let engine = PolicyEngine::default();
        let mut source = built_in_policy_pack("read-only-audit").unwrap();
        source.approval_rules.push(OverlayRule {
            id: "approval-with-ticket".into(),
            actions: BTreeSet::from(["fs.read".into()]),
            resource_pattern: Some("C:/repo/**".into()),
            required_context_keys: BTreeSet::from(["change_ticket".into()]),
        });
        let pack = engine.compile_cached(source).unwrap();
        let mut request = PolicyRequest::new("agent", "fs.read", "C:/repo/src/lib.rs");
        let denied = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(denied.decision, PolicyDecisionKind::Deny);
        assert_eq!(denied.reason_codes, vec!["MISSING_REQUIRED_CONTEXT"]);
        assert!(denied
            .diagnostics
            .iter()
            .any(|line| line.contains("change_ticket")));

        request
            .context
            .insert("change_ticket".into(), Value::String("CHG-42".into()));
        let gated = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(gated.decision, PolicyDecisionKind::RequireApproval);
    }

    #[test]
    fn cedar_deny_precedes_approval_and_observe_overlays() {
        let engine = PolicyEngine::default();
        let mut source = built_in_policy_pack("no-secret-egress").unwrap();
        let approval_scope = OverlayRule {
            id: "approval-secret".into(),
            actions: BTreeSet::from(["secret.egress".into()]),
            resource_pattern: Some("*".into()),
            required_context_keys: BTreeSet::new(),
        };
        let mut observe_scope = approval_scope.clone();
        observe_scope.id = "observe-secret".into();
        source.approval_rules.push(approval_scope);
        source.observe_rules.push(observe_scope);
        let pack = engine.compile_cached(source).unwrap();
        let decision = engine
            .evaluate(
                &pack,
                &PolicyRequest::new("agent", "secret.egress", "C:/secret.txt"),
                None,
            )
            .unwrap();
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.reason_codes, vec!["CEDAR_DENY"]);
    }

    #[test]
    fn approval_consume_is_atomic_under_race() {
        let registry = Arc::new(ApprovalRegistry::default());
        registry
            .issue(ApprovalGrant {
                grant_id: "race-grant".into(),
                request_hash: "request-hash".into(),
                policy_bundle_digest: "policy-hash".into(),
                expires_at_unix_ms: 10_000,
            })
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                registry
                    .consume("race-grant", "request-hash", "policy-hash", 1)
                    .is_ok()
            }));
        }
        barrier.wait();
        let successes = handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|success| *success)
            .count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn approval_is_expired_at_expiry_boundary() {
        let registry = ApprovalRegistry::default();
        registry
            .issue(ApprovalGrant {
                grant_id: "expiring".into(),
                request_hash: "r".into(),
                policy_bundle_digest: "p".into(),
                expires_at_unix_ms: 100,
            })
            .unwrap();
        assert!(matches!(
            registry.consume("expiring", "r", "p", 100),
            Err(PolicyError::ApprovalExpired(_))
        ));
    }

    #[test]
    fn policy_pack_digest_and_decision_ignore_cedar_policy_input_order() {
        let engine = PolicyEngine::default();
        let a = built_in_policy_pack("no-secret-egress").unwrap();
        let mut b = a.clone();
        b.cedar_policies.reverse();
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
        let a = engine.compile_cached(a).unwrap();
        let b = engine.compile_cached(b).unwrap();
        let request = PolicyRequest::new("agent", "secret.egress", "C:/secret.txt");
        let da = engine.evaluate(&a, &request, None).unwrap();
        let db = engine.evaluate(&b, &request, None).unwrap();
        assert_eq!(da.decision_hash, db.decision_hash);
        assert_eq!(da.policy_ids, db.policy_ids);
    }

    #[test]
    fn default_request_ids_are_distinct_for_repeated_actions() {
        let a = PolicyRequest::new("agent", "fs.read", "C:/repo/file.txt");
        let b = PolicyRequest::new("agent", "fs.read", "C:/repo/file.txt");
        assert_ne!(a.request_id, b.request_id);
    }

    #[test]
    fn canonical_policy_request_deserializes() {
        let request: PolicyRequest = serde_json::from_value(serde_json::json!({
            "schema_version": "1.0.0",
            "request_id": "req-1",
            "principal": "agent:test",
            "action": "fs.read",
            "resource": "workspace/src/**",
            "context": {"interactive": false}
        }))
        .unwrap();
        assert_eq!(request.request_id, "req-1");
        assert_eq!(request.schema_version, POLICY_SCHEMA_VERSION);
        assert!(request.capability.is_none());
        request_digest(&request).unwrap();
    }

    #[test]
    fn canonical_policy_decision_fields_are_emitted() {
        let (engine, pack) = engine_and_pack("read-only-audit");
        let request = PolicyRequest::with_request_id(
            "req-wire",
            "agent:test",
            "fs.read",
            "workspace/src/lib.rs",
        );
        let decision = engine.evaluate(&pack, &request, None).unwrap();
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["schema_version"], "1.0.0");
        assert_eq!(json["request_id"], "req-wire");
        assert_eq!(json["decision"], "ALLOW");
        assert!(json["decision_id"].as_str().unwrap().starts_with("dec-"));
        assert_eq!(json["decision_hash"].as_str().unwrap().len(), 64);
        assert_eq!(json["policy_bundle_digest"].as_str().unwrap().len(), 64);
        assert_eq!(json["request_digest"].as_str().unwrap().len(), 64);
        assert!(json.get("request_hash").is_none());
    }

    #[test]
    fn invalid_request_contract_fails_closed_before_cedar_evaluation() {
        let (engine, pack) = engine_and_pack("read-only-audit");
        let mut request = PolicyRequest::with_request_id(
            "req-old-schema",
            "agent:test",
            "fs.read",
            "workspace/file.txt",
        );
        request.schema_version = "0.1".into();
        let decision = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.reason_codes, vec!["UNSUPPORTED_REQUEST_SCHEMA"]);
        assert_eq!(decision.request_id, "req-old-schema");
        assert!(decision.execution_binding.is_none());
        assert!(matches!(
            request_digest(&request),
            Err(PolicyError::InvalidRequest(_))
        ));
    }

    #[test]
    fn embedded_capability_action_mismatch_fails_closed() {
        let (engine, pack) = engine_and_pack("read-only-audit");
        let mut request = PolicyRequest::with_request_id(
            "req-cap-mismatch",
            "agent:test",
            "fs.read",
            "workspace/file.txt",
        );
        request.capability = Some(
            Capability::new(
                "git.read",
                proofdrift_capabilities::ResourceSelector::any(),
                proofdrift_capabilities::CapabilitySource::Declared,
            )
            .unwrap(),
        );
        let decision = engine.evaluate(&pack, &request, None).unwrap();
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.reason_codes, vec!["CAPABILITY_ACTION_MISMATCH"]);
    }

    #[test]
    fn compiler_rejects_unknown_overlay_and_duplicate_rule_ids() {
        let mut unknown = built_in_policy_pack("read-only-audit").unwrap();
        unknown.approval_rules.push(OverlayRule {
            id: "approval-unknown".into(),
            actions: BTreeSet::from(["unknown.action".into()]),
            resource_pattern: None,
            required_context_keys: BTreeSet::new(),
        });
        assert!(matches!(
            CompiledPolicyPack::compile(unknown),
            Err(PolicyError::UnknownOverlayCapability(_, _))
        ));

        let mut duplicate = built_in_policy_pack("read-only-audit").unwrap();
        duplicate.approval_rules.push(OverlayRule {
            id: "allow-read-only".into(),
            actions: BTreeSet::from(["fs.read".into()]),
            resource_pattern: None,
            required_context_keys: BTreeSet::new(),
        });
        assert!(matches!(
            CompiledPolicyPack::compile(duplicate),
            Err(PolicyError::DuplicateRuleId(_))
        ));
    }

    #[test]
    fn checked_in_policy_pack_fixtures_deserialize_lint_and_compile() {
        let fixtures = [
            (
                "safe-local-dev",
                include_str!("../policy-packs/safe-local-dev.json"),
            ),
            (
                "read-only-audit",
                include_str!("../policy-packs/read-only-audit.json"),
            ),
            (
                "no-secret-egress",
                include_str!("../policy-packs/no-secret-egress.json"),
            ),
            (
                "protected-git-main",
                include_str!("../policy-packs/protected-git-main.json"),
            ),
            (
                "constrained-mcp",
                include_str!("../policy-packs/constrained-mcp.json"),
            ),
            (
                "ci-unattended",
                include_str!("../policy-packs/ci-unattended.json"),
            ),
        ];
        for (expected_name, json) in fixtures {
            let pack = PolicyPack::from_json(json).unwrap();
            assert_eq!(pack.name, expected_name);
            assert!(
                lint_pack(&pack).is_empty(),
                "fixture {expected_name} must lint cleanly"
            );
            CompiledPolicyPack::compile(pack).unwrap();
        }
    }
}
