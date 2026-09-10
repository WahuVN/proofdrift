use proofdrift_schema::{
    canonical_json_bytes, canonical_sha256_excluding, ArtifactIdentity, BaselineSnapshot,
    Capability, CapabilitySource, Severity, TrustDiff, TrustDiffChange, TrustDiffChangeType,
    SCHEMA_VERSION,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("duplicate artifact id in {side}: {artifact_id}")]
    DuplicateArtifact {
        side: &'static str,
        artifact_id: String,
    },
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] proofdrift_schema::CanonicalError),
}

pub fn diff_snapshots(
    baseline: &BaselineSnapshot,
    current: &BaselineSnapshot,
) -> Result<TrustDiff, DiffError> {
    let baseline_digest = snapshot_digest(baseline)?;
    let current_digest = snapshot_digest(current)?;
    let before_artifacts = artifact_map("baseline", &baseline.artifacts)?;
    let after_artifacts = artifact_map("current", &current.artifacts)?;
    let mut changes = Vec::new();

    let artifact_ids: BTreeSet<_> = before_artifacts
        .keys()
        .chain(after_artifacts.keys())
        .copied()
        .collect();
    for id in artifact_ids {
        match (before_artifacts.get(id), after_artifacts.get(id)) {
            (None, Some(after)) => changes.push(change(
                TrustDiffChangeType::ComponentAdded,
                Severity::Medium,
                Some(id),
                None,
                None,
                Some(serde_json::to_value(after).expect("ArtifactIdentity serializes")),
                "Component is present in current state but not in baseline.",
            )),
            (Some(before), None) => changes.push(change(
                TrustDiffChangeType::ComponentRemoved,
                Severity::Low,
                Some(id),
                None,
                Some(serde_json::to_value(before).expect("ArtifactIdentity serializes")),
                None,
                "Component from baseline is absent in current state.",
            )),
            (Some(before), Some(after)) => compare_artifact(id, before, after, &mut changes)?,
            (None, None) => unreachable!(),
        }
    }

    compare_capabilities(baseline, current, &mut changes);
    compare_capability_source_mismatches(baseline, current, &mut changes);

    if baseline.policy_digest != current.policy_digest {
        changes.push(change(
            TrustDiffChangeType::PolicyChanged,
            Severity::High,
            None,
            None,
            baseline.policy_digest.clone().map(Value::String),
            current.policy_digest.clone().map(Value::String),
            "Policy bundle digest changed between baseline and current state.",
        ));
    }

    if baseline.enforcement_coverage != current.enforcement_coverage {
        changes.push(change(
            TrustDiffChangeType::EnforcementCoverageChanged,
            Severity::High,
            None,
            None,
            Some(serde_json::to_value(&baseline.enforcement_coverage).expect("map serializes")),
            Some(serde_json::to_value(&current.enforcement_coverage).expect("map serializes")),
            "Enforcement coverage changed; inspect per-boundary levels before trusting isolation claims.",
        ));
    }

    sort_changes(&mut changes);
    Ok(TrustDiff {
        schema_version: SCHEMA_VERSION.to_owned(),
        baseline_name: baseline.name.clone(),
        baseline_digest,
        current_digest,
        changes,
        extensions: Default::default(),
    })
}

fn snapshot_digest(
    snapshot: &BaselineSnapshot,
) -> Result<String, proofdrift_schema::CanonicalError> {
    // Scanner/runtime discovery order is not semantically meaningful. Normalize all
    // set-like collections before hashing so parallel discovery cannot create false
    // baseline drift.
    let mut normalized = snapshot.clone();
    normalized
        .artifacts
        .sort_by(|a, b| a.artifact_id.cmp(&b.artifact_id));
    for capability in &mut normalized.capabilities {
        capability.evidence_refs.sort();
        capability.evidence_refs.dedup();
        capability.risk_tags.sort();
        capability.risk_tags.dedup();
    }
    normalized
        .capabilities
        .sort_by_key(normalized_capability_bytes);
    canonical_sha256_excluding(&normalized, &["digest", "name", "created_at"])
}

fn normalized_capability_bytes(capability: &Capability) -> Vec<u8> {
    let mut normalized = capability.clone();
    normalized.evidence_refs.sort();
    normalized.evidence_refs.dedup();
    normalized.risk_tags.sort();
    normalized.risk_tags.dedup();
    canonical_json_bytes(
        &serde_json::to_value(normalized).expect("Capability serialization cannot fail"),
    )
}

fn artifact_map<'a>(
    side: &'static str,
    artifacts: &'a [ArtifactIdentity],
) -> Result<BTreeMap<&'a str, &'a ArtifactIdentity>, DiffError> {
    let mut map = BTreeMap::new();
    for artifact in artifacts {
        if map
            .insert(artifact.artifact_id.as_str(), artifact)
            .is_some()
        {
            return Err(DiffError::DuplicateArtifact {
                side,
                artifact_id: artifact.artifact_id.clone(),
            });
        }
    }
    Ok(map)
}

fn compare_artifact(
    id: &str,
    before: &ArtifactIdentity,
    after: &ArtifactIdentity,
    changes: &mut Vec<TrustDiffChange>,
) -> Result<(), DiffError> {
    let mut emitted_specific = false;
    if before.content_digest != after.content_digest {
        emitted_specific = true;
        changes.push(change(
            TrustDiffChangeType::HashDrift,
            Severity::High,
            Some(id),
            None,
            before.content_digest.clone().map(Value::String),
            after.content_digest.clone().map(Value::String),
            "Resolved component content digest changed.",
        ));
    }
    if before.source_uri != after.source_uri
        || before.resolved_revision != after.resolved_revision
        || before.version != after.version
    {
        emitted_specific = true;
        changes.push(change(
            TrustDiffChangeType::SourceRefDrift,
            Severity::High,
            Some(id),
            None,
            Some(json!({
                "source_uri": before.source_uri,
                "resolved_revision": before.resolved_revision,
                "version": before.version,
            })),
            Some(json!({
                "source_uri": after.source_uri,
                "resolved_revision": after.resolved_revision,
                "version": after.version,
            })),
            "Source, ref, resolved revision, or version changed.",
        ));
    }

    if !emitted_specific
        && canonical_sha256_excluding(before, &[])? != canonical_sha256_excluding(after, &[])?
    {
        changes.push(change(
            TrustDiffChangeType::ComponentChanged,
            Severity::Medium,
            Some(id),
            None,
            Some(serde_json::to_value(before).expect("ArtifactIdentity serializes")),
            Some(serde_json::to_value(after).expect("ArtifactIdentity serializes")),
            "Component metadata changed while source/hash identity stayed stable.",
        ));
    }
    Ok(())
}

fn compare_capabilities(
    baseline: &BaselineSnapshot,
    current: &BaselineSnapshot,
    changes: &mut Vec<TrustDiffChange>,
) {
    let before = capability_groups(&baseline.capabilities);
    let after = capability_groups(&current.capabilities);
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();

    for key in keys {
        match (before.get(&key), after.get(&key)) {
            (None, Some(capabilities)) => {
                for cap in sorted_capabilities(capabilities) {
                    changes.push(capability_change(
                        TrustDiffChangeType::CapabilityAdded,
                        capability_severity(cap),
                        cap,
                        None,
                        Some(capability_semantics(cap)),
                        "Capability is newly present in current state.",
                    ));
                }
            }
            (Some(capabilities), None) => {
                for cap in sorted_capabilities(capabilities) {
                    changes.push(capability_change(
                        TrustDiffChangeType::CapabilityRemoved,
                        Severity::Low,
                        cap,
                        Some(capability_semantics(cap)),
                        None,
                        "Capability from baseline is no longer present.",
                    ));
                }
            }
            (Some(old), Some(new)) => compare_capability_group(old, new, changes),
            (None, None) => unreachable!(),
        }
    }
}

fn compare_capability_group(
    old: &[&Capability],
    new: &[&Capability],
    changes: &mut Vec<TrustDiffChange>,
) {
    let old = sorted_capabilities(old);
    let new = sorted_capabilities(new);
    let mut old_matched = vec![false; old.len()];
    let mut new_matched = vec![false; new.len()];

    // Remove exact semantic matches first. This prevents a stable sibling resource
    // from being paired with the one resource that actually expanded/reduced.
    for (old_index, old_cap) in old.iter().enumerate() {
        if let Some((new_index, new_cap)) = new.iter().enumerate().find(|(new_index, new_cap)| {
            !new_matched[*new_index]
                && capability_semantics(old_cap) == capability_semantics(new_cap)
        }) {
            if normalized_capability_bytes(old_cap) != normalized_capability_bytes(new_cap) {
                changes.push(capability_change(
                    TrustDiffChangeType::ComponentChanged,
                    Severity::Medium,
                    new_cap,
                    Some(serde_json::to_value(*old_cap).expect("Capability serializes")),
                    Some(serde_json::to_value(*new_cap).expect("Capability serializes")),
                    "Capability evidence/risk metadata changed while action semantics stayed stable.",
                ));
            }
            old_matched[old_index] = true;
            new_matched[new_index] = true;
        }
    }

    let remaining_old: Vec<_> = old
        .iter()
        .enumerate()
        .filter_map(|(index, cap)| (!old_matched[index]).then_some(*cap))
        .collect();
    let remaining_new: Vec<_> = new
        .iter()
        .enumerate()
        .filter_map(|(index, cap)| (!new_matched[index]).then_some(*cap))
        .collect();

    let pair_count = remaining_old.len().min(remaining_new.len());
    for index in 0..pair_count {
        compare_capability_pair(remaining_old[index], remaining_new[index], changes);
    }
    for cap in &remaining_old[pair_count..] {
        changes.push(capability_change(
            TrustDiffChangeType::CapabilityRemoved,
            Severity::Low,
            cap,
            Some(capability_semantics(cap)),
            None,
            "Capability from baseline is no longer present.",
        ));
    }
    for cap in &remaining_new[pair_count..] {
        changes.push(capability_change(
            TrustDiffChangeType::CapabilityAdded,
            capability_severity(cap),
            cap,
            None,
            Some(capability_semantics(cap)),
            "Capability is newly present in current state.",
        ));
    }
}

fn compare_capability_pair(old: &Capability, new: &Capability, changes: &mut Vec<TrustDiffChange>) {
    if old.action_family != new.action_family {
        changes.push(capability_change(
            TrustDiffChangeType::CapabilityExpanded,
            capability_severity(new),
            new,
            Some(capability_semantics(old)),
            Some(capability_semantics(new)),
            "Capability action family changed; conservatively review as possible expansion.",
        ));
        return;
    }

    if old.resource_selector != new.resource_selector {
        let (kind, severity, explanation) = if selector_covers(
            &new.resource_selector,
            &old.resource_selector,
        ) {
            (
                TrustDiffChangeType::CapabilityExpanded,
                capability_severity(new),
                "Capability resource selector expanded.",
            )
        } else if selector_covers(&old.resource_selector, &new.resource_selector) {
            (
                TrustDiffChangeType::CapabilityReduced,
                Severity::Low,
                "Capability resource selector became narrower.",
            )
        } else {
            (
                    TrustDiffChangeType::CapabilityExpanded,
                    capability_severity(new),
                    "Capability resource selector changed to an incomparable scope; review as potential expansion.",
                )
        };
        changes.push(capability_change(
            kind,
            severity,
            new,
            Some(Value::String(old.resource_selector.clone())),
            Some(Value::String(new.resource_selector.clone())),
            explanation,
        ));
    }

    if old.constraints != new.constraints {
        changes.push(capability_change(
            TrustDiffChangeType::CapabilityExpanded,
            capability_severity(new),
            new,
            Some(serde_json::to_value(&old.constraints).expect("map serializes")),
            Some(serde_json::to_value(&new.constraints).expect("map serializes")),
            "Capability constraints changed; conservatively review as possible expansion.",
        ));
    }
}

fn compare_capability_source_mismatches(
    baseline: &BaselineSnapshot,
    current: &BaselineSnapshot,
    changes: &mut Vec<TrustDiffChange>,
) {
    let baseline_mismatches = capability_source_mismatches(baseline);
    let current_mismatches = capability_source_mismatches(current);
    for (key, current_change) in current_mismatches {
        let unchanged = baseline_mismatches
            .get(&key)
            .is_some_and(|baseline_change| {
                baseline_change.before == current_change.before
                    && baseline_change.after == current_change.after
            });
        if !unchanged {
            changes.push(current_change);
        }
    }
}

fn capability_source_mismatches(snapshot: &BaselineSnapshot) -> BTreeMap<String, TrustDiffChange> {
    let declared_ids: BTreeSet<_> = snapshot
        .capabilities
        .iter()
        .filter(|cap| cap.source == CapabilitySource::Declared)
        .map(|cap| cap.capability_id.clone())
        .collect();
    let mut result = BTreeMap::new();

    for capability_id in declared_ids {
        let declared = semantics_for_source(snapshot, &capability_id, CapabilitySource::Declared);
        for (other_source, change_type, label) in [
            (
                CapabilitySource::Inferred,
                TrustDiffChangeType::DeclaredInferredMismatch,
                "declared-inferred",
            ),
            (
                CapabilitySource::Observed,
                TrustDiffChangeType::DeclaredObservedMismatch,
                "declared-observed",
            ),
        ] {
            let other = semantics_for_source(snapshot, &capability_id, other_source);
            if other.is_empty() || declared == other {
                continue;
            }
            let Some(representative) = snapshot
                .capabilities
                .iter()
                .find(|cap| cap.capability_id == capability_id && cap.source == other_source)
            else {
                continue;
            };
            result.insert(
                format!("{capability_id}:{label}"),
                capability_change(
                    change_type,
                    capability_severity(representative),
                    representative,
                    Some(Value::Array(declared.clone())),
                    Some(Value::Array(other)),
                    "Declared capability semantics do not match another evidence view.",
                ),
            );
        }
    }
    result
}

fn semantics_for_source(
    snapshot: &BaselineSnapshot,
    capability_id: &str,
    source: CapabilitySource,
) -> Vec<Value> {
    let mut values: Vec<_> = snapshot
        .capabilities
        .iter()
        .filter(|cap| cap.capability_id == capability_id && cap.source == source)
        .map(capability_semantics)
        .collect();
    values.sort_by_key(canonical_json_bytes);
    values.dedup();
    values
}

fn capability_semantics(capability: &Capability) -> Value {
    json!({
        "action_family": capability.action_family.clone(),
        "resource_selector": capability.resource_selector.clone(),
        "constraints": capability.constraints.clone(),
    })
}

fn capability_groups(capabilities: &[Capability]) -> BTreeMap<String, Vec<&Capability>> {
    let mut groups: BTreeMap<String, Vec<&Capability>> = BTreeMap::new();
    for cap in capabilities {
        groups
            .entry(format!(
                "{}::{}",
                cap.capability_id,
                source_key(&cap.source)
            ))
            .or_default()
            .push(cap);
    }
    groups
}

fn sorted_capabilities<'a>(capabilities: &[&'a Capability]) -> Vec<&'a Capability> {
    let mut values = capabilities.to_vec();
    values.sort_by_key(|cap| canonical_json_bytes(&capability_semantics(cap)));
    values
}
fn source_key(source: &CapabilitySource) -> &'static str {
    match source {
        CapabilitySource::Declared => "declared",
        CapabilitySource::Inferred => "inferred",
        CapabilitySource::Observed => "observed",
    }
}

fn selector_covers(wider: &str, narrower: &str) -> bool {
    if wider == narrower || matches!(wider, "*" | "**" | "*/**") {
        return true;
    }
    if let Some(prefix) = wider.strip_suffix("/**") {
        return narrower == prefix || narrower.starts_with(&format!("{prefix}/"));
    }
    false
}

fn capability_severity(cap: &Capability) -> Severity {
    let action = cap.action_family.as_str();
    if action.starts_with("secret.")
        || action == "money.spend"
        || action == "identity.impersonate"
        || action == "git.force_push"
        || action == "cloud.mutate"
    {
        Severity::Critical
    } else if action.starts_with("network.")
        || action == "process.exec"
        || action == "fs.delete"
        || action == "git.push"
        || action == "db.write"
    {
        Severity::High
    } else if action == "fs.write" || action == "mcp.call" || action == "browser.submit" {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn change(
    change_type: TrustDiffChangeType,
    severity: Severity,
    artifact_id: Option<&str>,
    capability_id: Option<&str>,
    before: Option<Value>,
    after: Option<Value>,
    explanation: &str,
) -> TrustDiffChange {
    TrustDiffChange {
        change_type,
        severity,
        artifact_id: artifact_id.map(str::to_owned),
        capability_id: capability_id.map(str::to_owned),
        before,
        after,
        evidence_refs: vec![],
        explanation: explanation.to_owned(),
        extensions: Default::default(),
    }
}

fn capability_change(
    change_type: TrustDiffChangeType,
    severity: Severity,
    capability: &Capability,
    before: Option<Value>,
    after: Option<Value>,
    explanation: &str,
) -> TrustDiffChange {
    change(
        change_type,
        severity,
        None,
        Some(capability.capability_id.as_str()),
        before,
        after,
        explanation,
    )
}

fn sort_changes(changes: &mut [TrustDiffChange]) {
    changes.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.change_type.cmp(&b.change_type))
            .then_with(|| a.artifact_id.cmp(&b.artifact_id))
            .then_with(|| a.capability_id.cmp(&b.capability_id))
            .then_with(|| {
                canonical_json_bytes(&a.before.clone().unwrap_or(Value::Null)).cmp(
                    &canonical_json_bytes(&b.before.clone().unwrap_or(Value::Null)),
                )
            })
            .then_with(|| {
                canonical_json_bytes(&a.after.clone().unwrap_or(Value::Null)).cmp(
                    &canonical_json_bytes(&b.after.clone().unwrap_or(Value::Null)),
                )
            })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofdrift_schema::{ArtifactType, ProvenanceStatus};

    fn artifact(id: &str, hash: &str, rev: &str) -> ArtifactIdentity {
        ArtifactIdentity {
            schema_version: SCHEMA_VERSION.to_owned(),
            artifact_id: id.to_owned(),
            artifact_type: ArtifactType::Skill,
            name: id.to_owned(),
            version: None,
            source_uri: Some("https://example.invalid/repo".to_owned()),
            resolved_revision: Some(rev.to_owned()),
            content_digest: Some(hash.to_owned()),
            local_path: None,
            provenance_status: ProvenanceStatus::Verified,
            metadata: Default::default(),
            extensions: Default::default(),
        }
    }

    fn capability(selector: &str) -> Capability {
        Capability {
            schema_version: SCHEMA_VERSION.to_owned(),
            capability_id: "network.connect".to_owned(),
            action_family: "network.connect".to_owned(),
            resource_selector: selector.to_owned(),
            constraints: Default::default(),
            source: CapabilitySource::Inferred,
            evidence_refs: vec!["fixture".to_owned()],
            risk_tags: vec!["network".to_owned()],
            extensions: Default::default(),
        }
    }

    fn snapshot(name: &str) -> BaselineSnapshot {
        BaselineSnapshot {
            schema_version: SCHEMA_VERSION.to_owned(),
            name: name.to_owned(),
            created_at: "2026-09-10T00:00:00Z".to_owned(),
            digest: None,
            artifacts: vec![],
            capabilities: vec![],
            policy_digest: Some("sha256:policy1".to_owned()),
            enforcement_coverage: Default::default(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn detects_hash_ref_and_capability_expansion() {
        let mut before = snapshot("trusted-main");
        before
            .artifacts
            .push(artifact("skill:a", "sha256:111", "abc"));
        before.capabilities.push(capability("github.com/api/**"));
        let mut after = before.clone();
        after.artifacts[0].content_digest = Some("sha256:222".to_owned());
        after.artifacts[0].resolved_revision = Some("def".to_owned());
        after.capabilities[0].resource_selector = "**".to_owned();
        let diff = diff_snapshots(&before, &after).unwrap();
        assert!(diff
            .changes
            .iter()
            .any(|c| c.change_type == TrustDiffChangeType::HashDrift));
        assert!(diff
            .changes
            .iter()
            .any(|c| c.change_type == TrustDiffChangeType::SourceRefDrift));
        assert!(diff
            .changes
            .iter()
            .any(|c| c.change_type == TrustDiffChangeType::CapabilityExpanded));
    }

    #[test]
    fn diff_order_and_digest_are_deterministic() {
        let mut before = snapshot("trusted-main");
        before.artifacts = vec![
            artifact("b", "sha256:b", "1"),
            artifact("a", "sha256:a", "1"),
        ];
        let mut after = before.clone();
        after.artifacts.reverse();
        after.artifacts[0].content_digest = Some("sha256:changed".to_owned());
        let first = diff_snapshots(&before, &after).unwrap();
        let second = diff_snapshots(&before, &after).unwrap();
        assert_eq!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
    }

    #[test]
    fn discovery_order_label_and_timestamp_do_not_change_state_digest() {
        let mut before = snapshot("trusted-main");
        before.artifacts = vec![
            artifact("b", "sha256:b", "1"),
            artifact("a", "sha256:a", "1"),
        ];
        before.capabilities = vec![capability("github.com/api/**")];
        let mut after = before.clone();
        after.name = "current-scan".to_owned();
        after.created_at = "2026-09-10T01:00:00Z".to_owned();
        after.artifacts.reverse();
        let diff = diff_snapshots(&before, &after).unwrap();
        assert_eq!(diff.baseline_digest, diff.current_digest);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn newly_observed_declared_mismatch_is_explicit() {
        let mut before = snapshot("trusted-main");
        let mut declared = capability("github.com/api/**");
        declared.source = CapabilitySource::Declared;
        before.capabilities.push(declared.clone());
        let mut after = before.clone();
        let mut observed = declared;
        observed.source = CapabilitySource::Observed;
        observed.resource_selector = "**".to_owned();
        after.capabilities.push(observed);
        let diff = diff_snapshots(&before, &after).unwrap();
        assert!(diff
            .changes
            .iter()
            .any(|change| { change.change_type == TrustDiffChangeType::DeclaredObservedMismatch }));
    }

    #[test]
    fn parallel_discovery_and_set_order_do_not_create_false_capability_drift() {
        let mut first = capability("github.com/api/**");
        first.evidence_refs = vec!["z".to_owned(), "a".to_owned()];
        first.risk_tags = vec!["network".to_owned(), "egress".to_owned()];
        let mut second = capability("internal/**");
        second.evidence_refs = vec!["b".to_owned(), "a".to_owned()];

        let mut before = snapshot("trusted-main");
        before.capabilities = vec![first, second];
        let mut after = before.clone();
        after.capabilities.reverse();
        for cap in &mut after.capabilities {
            cap.evidence_refs.reverse();
            cap.risk_tags.reverse();
        }

        let diff = diff_snapshots(&before, &after).unwrap();
        assert_eq!(diff.baseline_digest, diff.current_digest);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn multiple_resources_under_same_capability_id_are_compared_independently() {
        let mut before = snapshot("trusted-main");
        before.capabilities = vec![capability("github.com/api/**"), capability("internal/**")];
        let mut after = before.clone();
        after.capabilities[0].resource_selector = "**".to_owned();
        after.capabilities.reverse();

        let diff = diff_snapshots(&before, &after).unwrap();
        assert_eq!(
            diff.changes
                .iter()
                .filter(|change| change.change_type == TrustDiffChangeType::CapabilityExpanded)
                .count(),
            1
        );
        assert!(!diff
            .changes
            .iter()
            .any(|change| change.change_type == TrustDiffChangeType::CapabilityAdded));
        assert!(!diff
            .changes
            .iter()
            .any(|change| change.change_type == TrustDiffChangeType::CapabilityRemoved));
    }

    #[test]
    fn capability_evidence_metadata_change_is_explained() {
        let mut before = snapshot("trusted-main");
        before.capabilities = vec![capability("github.com/api/**")];
        let mut after = before.clone();
        after.capabilities[0].evidence_refs = vec!["runtime-observation".to_owned()];

        let diff = diff_snapshots(&before, &after).unwrap();
        assert_ne!(diff.baseline_digest, diff.current_digest);
        assert!(diff.changes.iter().any(|change| {
            change.change_type == TrustDiffChangeType::ComponentChanged
                && change.capability_id.as_deref() == Some("network.connect")
        }));
    }
}
