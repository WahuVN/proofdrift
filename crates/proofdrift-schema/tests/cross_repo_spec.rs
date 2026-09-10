use proofdrift_schema::{
    from_json_slice_bounded, AgentEvent, ArtifactIdentity, BaselineSnapshot, BundleManifest,
    Capability, DriftFinding, EvaluationDecision, EvidenceEnvelope, EvidenceReference,
    EvidenceValue, Finding, PatchImpact, PolicyDecision, PolicyRequest, ProvenanceEdge,
    TestEvidence, TrustDiff, TrustReport, SCHEMA_VERSION,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn parse_example<T: DeserializeOwned>(
    root: &Path,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = root
        .join("contracts")
        .join("examples")
        .join("valid")
        .join(format!("{name}.valid.json"));
    let bytes = fs::read(&path)?;
    let _: T = from_json_slice_bounded(&bytes, 2 * 1024 * 1024)?;
    Ok(())
}

#[test]
fn checked_in_spec_examples_deserialize_with_engine_contracts(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(spec_dir) = std::env::var_os("PROOFDRIFT_SPEC_DIR").map(PathBuf::from) else {
        eprintln!("PROOFDRIFT_SPEC_DIR not set; cross-repo spec conformance test skipped");
        return Ok(());
    };

    let index: Value = serde_json::from_slice(&fs::read(
        spec_dir
            .join("contracts")
            .join("schemas")
            .join("index.json"),
    )?)?;
    assert_eq!(index["schema_version"], SCHEMA_VERSION);
    assert_eq!(index["canonicalization"], "proofdrift-json-v1");

    parse_example::<AgentEvent>(&spec_dir, "agent-event")?;
    parse_example::<ArtifactIdentity>(&spec_dir, "artifact-identity")?;
    parse_example::<BaselineSnapshot>(&spec_dir, "baseline-snapshot")?;
    parse_example::<BundleManifest>(&spec_dir, "bundle-manifest")?;
    parse_example::<Capability>(&spec_dir, "capability")?;
    parse_example::<EvidenceEnvelope>(&spec_dir, "evidence-envelope")?;
    parse_example::<EvidenceReference>(&spec_dir, "evidence-reference")?;
    parse_example::<EvidenceValue<Value>>(&spec_dir, "evidence-value")?;
    parse_example::<DriftFinding>(&spec_dir, "drift-finding")?;
    parse_example::<EvaluationDecision>(&spec_dir, "evaluation-decision")?;
    parse_example::<Finding>(&spec_dir, "finding")?;
    parse_example::<Value>(&spec_dir, "fixture-case")?;
    parse_example::<PatchImpact>(&spec_dir, "patch-impact")?;
    parse_example::<PolicyDecision>(&spec_dir, "policy-decision")?;
    parse_example::<PolicyRequest>(&spec_dir, "policy-request")?;
    parse_example::<ProvenanceEdge>(&spec_dir, "provenance-edge")?;
    parse_example::<TestEvidence>(&spec_dir, "test-evidence")?;
    parse_example::<TrustDiff>(&spec_dir, "trust-diff")?;
    parse_example::<TrustReport>(&spec_dir, "trust-report")?;
    Ok(())
}
