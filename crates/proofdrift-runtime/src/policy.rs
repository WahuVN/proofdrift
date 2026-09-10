use crate::canonical::canonical_sha256;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
    Observe,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub schema_version: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(default)]
    pub context: Value,
    #[serde(default)]
    pub session_path_summary: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Value>,
}

impl PolicyRequest {
    pub fn new(
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        context: Value,
    ) -> Self {
        Self {
            schema_version: "0.1".to_owned(),
            principal: principal.into(),
            action: action.into(),
            resource: resource.into(),
            context,
            session_path_summary: Vec::new(),
            capability: None,
            provenance: None,
        }
    }

    pub fn digest(&self) -> Result<String, serde_json::Error> {
        canonical_sha256(&serde_json::to_value(self)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub schema_version: String,
    pub decision: Decision,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    pub decision_hash: String,
    pub policy_bundle_digest: String,
    pub request_digest: String,
}

impl PolicyDecision {
    pub fn bound(
        request: &PolicyRequest,
        decision: Decision,
        mut policy_ids: Vec<String>,
        mut reason_codes: Vec<String>,
        diagnostics: Vec<String>,
        policy_bundle_digest: impl Into<String>,
    ) -> Result<Self, serde_json::Error> {
        policy_ids.sort();
        policy_ids.dedup();
        reason_codes.sort();
        reason_codes.dedup();
        let policy_bundle_digest = policy_bundle_digest.into();
        let request_digest = request.digest()?;
        let decision_material = json!({
            "schema_version": "0.1",
            "request_digest": request_digest,
            "decision": decision,
            "policy_ids": policy_ids,
            "reason_codes": reason_codes,
            "diagnostics": diagnostics,
            "policy_bundle_digest": policy_bundle_digest,
        });
        let decision_hash = canonical_sha256(&decision_material)?;
        Ok(Self {
            schema_version: "0.1".to_owned(),
            decision,
            policy_ids,
            reason_codes,
            diagnostics,
            decision_hash,
            policy_bundle_digest,
            request_digest,
        })
    }
}

/// Boundary to the Cedar-backed policy engine.
///
/// The runtime only consumes deterministic decisions; it does not implement a competing
/// policy language.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, request: &PolicyRequest) -> Result<PolicyDecision, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_decision_is_stable_and_policy_bound() {
        let request = PolicyRequest::new("agent", "mcp.call", "srv::read", json!({"x": 1}));
        let a = PolicyDecision::bound(
            &request,
            Decision::Allow,
            vec!["p2".into(), "p1".into()],
            vec!["safe".into()],
            vec![],
            "bundle-a",
        )
        .unwrap();
        let b = PolicyDecision::bound(
            &request,
            Decision::Allow,
            vec!["p1".into(), "p2".into()],
            vec!["safe".into()],
            vec![],
            "bundle-a",
        )
        .unwrap();
        assert_eq!(a.decision_hash, b.decision_hash);

        let changed = PolicyDecision::bound(
            &request,
            Decision::Allow,
            vec!["p1".into(), "p2".into()],
            vec!["safe".into()],
            vec![],
            "bundle-b",
        )
        .unwrap();
        assert_ne!(a.decision_hash, changed.decision_hash);
    }
}
