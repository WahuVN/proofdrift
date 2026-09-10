use proofdrift_policy::{
    built_in_policy_pack, request_digest, ApprovalGrant, ApprovalRegistry, PolicyDecisionKind,
    PolicyEngine, PolicyError, PolicyRequest,
};
use serde_json::json;

#[test]
fn forged_provenance_changes_request_binding() -> Result<(), Box<dyn std::error::Error>> {
    let mut trusted = PolicyRequest::with_request_id(
        "req-provenance-binding",
        "agent:test",
        "network.connect",
        "github.com:443",
    );
    trusted.provenance = Some(json!({
        "artifact_id": "mcp:server:trusted",
        "content_digest": format!("sha256:{}", "a".repeat(64)),
        "provenance_status": "verified"
    }));

    let mut forged = trusted.clone();
    forged.provenance = Some(json!({
        "artifact_id": "mcp:server:trusted",
        "content_digest": format!("sha256:{}", "b".repeat(64)),
        "provenance_status": "declared"
    }));

    assert_ne!(request_digest(&trusted)?, request_digest(&forged)?);
    Ok(())
}

#[test]
fn removing_security_policy_changes_digest_and_behavior() -> Result<(), Box<dyn std::error::Error>>
{
    let engine = PolicyEngine::default();
    let original = built_in_policy_pack("no-secret-egress").ok_or("missing built-in policy")?;
    let original_digest = original.digest()?;
    let original_compiled = engine.compile_cached(original.clone())?;
    let request = PolicyRequest::with_request_id(
        "req-policy-downgrade",
        "agent:test",
        "secret.egress",
        "workspace/synthetic-secret.txt",
    );
    assert_eq!(
        engine
            .evaluate(&original_compiled, &request, None)?
            .decision,
        PolicyDecisionKind::Deny
    );

    let mut downgraded = original;
    downgraded
        .cedar_policies
        .retain(|policy| policy.id != "deny-secret-egress");
    let downgraded_digest = downgraded.digest()?;
    assert_ne!(original_digest, downgraded_digest);

    let downgraded_compiled = engine.compile_cached(downgraded)?;
    assert_eq!(
        engine
            .evaluate(&downgraded_compiled, &request, None)?
            .decision,
        PolicyDecisionKind::Allow
    );
    Ok(())
}

#[test]
fn approval_bound_to_original_policy_cannot_cross_downgrade(
) -> Result<(), Box<dyn std::error::Error>> {
    let original = built_in_policy_pack("safe-local-dev").ok_or("missing built-in policy")?;
    let mut downgraded = original.clone();
    downgraded.approval_rules.clear();

    let request = PolicyRequest::with_request_id(
        "req-approval-downgrade",
        "agent:test",
        "network.connect",
        "github.com:443",
    );
    let request_hash = request_digest(&request)?;
    let original_digest = original.digest()?;
    let downgraded_digest = downgraded.digest()?;
    assert_ne!(original_digest, downgraded_digest);

    let registry = ApprovalRegistry::default();
    registry.issue(ApprovalGrant {
        grant_id: "synthetic-policy-bound-grant".into(),
        request_hash: request_hash.clone(),
        policy_bundle_digest: original_digest.clone(),
        expires_at_unix_ms: 10_000,
    })?;

    assert!(matches!(
        registry.consume(
            "synthetic-policy-bound-grant",
            &request_hash,
            &downgraded_digest,
            1
        ),
        Err(PolicyError::ApprovalPolicyMismatch)
    ));
    assert!(registry
        .consume(
            "synthetic-policy-bound-grant",
            &request_hash,
            &original_digest,
            2
        )
        .is_ok());
    Ok(())
}
