use proofdrift_schema::{canonical_json_bytes, RiskComponent, RiskScoreCard, TrustReport};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("risk score arithmetic overflow")]
    ScoreOverflow,
}

/// Normalize every report collection whose ordering is semantically irrelevant.
/// This keeps JSON output stable across scanner/runtime scheduling differences.
pub fn normalize_trust_report(report: &mut TrustReport) {
    report.findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    report.capabilities.sort_by(|a, b| {
        a.capability_id
            .cmp(&b.capability_id)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.resource_selector.cmp(&b.resource_selector))
    });
    report
        .policy_decisions
        .sort_by(|a, b| a.decision_id.cmp(&b.decision_id));
    report.test_evidence.sort_by(|a, b| {
        a.command
            .cmp(&b.command)
            .then_with(|| a.environment_fingerprint.cmp(&b.environment_fingerprint))
    });
    report.residual_risks.sort();
    report.residual_risks.dedup();
    report.declared_vs_observed_drift.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.change_type.cmp(&b.change_type))
            .then_with(|| a.artifact_id.cmp(&b.artifact_id))
            .then_with(|| a.capability_id.cmp(&b.capability_id))
            .then_with(|| value_key(&a.before).cmp(&value_key(&b.before)))
            .then_with(|| value_key(&a.after).cmp(&value_key(&b.after)))
    });
    if let Some(score_card) = &mut report.score_card {
        score_card
            .components
            .sort_by(|a, b| a.component_id.cmp(&b.component_id));
    }
}

fn value_key(value: &Option<Value>) -> Vec<u8> {
    canonical_json_bytes(value.as_ref().unwrap_or(&Value::Null))
}

/// Produce an explicitly decomposed integer score from named components.
///
/// This helper does not claim probability or calibrated risk. Each component uses a
/// milli-weight (`1000 == 1.0`) and remains visible in the resulting score card.
pub fn score_from_components(
    mut components: Vec<RiskComponent>,
) -> Result<RiskScoreCard, ReportError> {
    components.sort_by(|a, b| a.component_id.cmp(&b.component_id));
    let mut weighted_sum: i128 = 0;
    for component in &components {
        let product = i128::from(component.value)
            .checked_mul(i128::from(component.weight_milli))
            .ok_or(ReportError::ScoreOverflow)?;
        weighted_sum = weighted_sum
            .checked_add(product)
            .ok_or(ReportError::ScoreOverflow)?;
    }
    let total_i128 = weighted_sum / 1000;
    let total = i64::try_from(total_i128).map_err(|_| ReportError::ScoreOverflow)?;
    Ok(RiskScoreCard {
        formula: "sum(component.value * component.weight_milli) / 1000".to_owned(),
        total,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn report_normalization_is_deterministic_for_set_like_order() {
        let capability = |id: &str, resource: &str| {
            json!({
                "schema_version": "1.0.0",
                "capability_id": id,
                "action_family": id,
                "resource_selector": resource,
                "source": "inferred"
            })
        };
        let mut first: TrustReport = serde_json::from_value(json!({
            "schema_version": "1.0.0",
            "scope": {"workspace": "fixture"},
            "capabilities": [
                capability("network.connect", "github.com/**"),
                capability("fs.read", "workspace/**")
            ],
            "residual_risks": ["z-risk", "a-risk", "z-risk"]
        }))
        .unwrap();
        let mut second: TrustReport = serde_json::from_value(json!({
            "schema_version": "1.0.0",
            "scope": {"workspace": "fixture"},
            "capabilities": [
                capability("fs.read", "workspace/**"),
                capability("network.connect", "github.com/**")
            ],
            "residual_risks": ["a-risk", "z-risk"]
        }))
        .unwrap();

        normalize_trust_report(&mut first);
        normalize_trust_report(&mut second);
        assert_eq!(first, second);
    }

    #[test]
    fn score_is_explainable_and_order_independent() {
        let a = RiskComponent {
            component_id: "b".to_owned(),
            value: 20,
            weight_milli: 500,
            rationale: "fixture".to_owned(),
            evidence_refs: vec!["e2".to_owned()],
        };
        let b = RiskComponent {
            component_id: "a".to_owned(),
            value: 10,
            weight_milli: 1000,
            rationale: "fixture".to_owned(),
            evidence_refs: vec!["e1".to_owned()],
        };
        let first = score_from_components(vec![a.clone(), b.clone()]).unwrap();
        let second = score_from_components(vec![b, a]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.total, 20);
        assert_eq!(first.components[0].component_id, "a");
    }
}
