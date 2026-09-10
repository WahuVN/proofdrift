use proofdrift_provenance::adapters::{
    apm, cargo_lock, git, github, huggingface, mcp, npm_lock, pnpm_lock,
};
use proofdrift_provenance::bom::{to_cyclonedx_16_json, to_spdx_23_json};
use proofdrift_provenance::{
    detect_drift, ArtifactIdentity, ArtifactType, DriftKind, EvidenceKind, ProvenanceEdge,
    ProvenanceGraph, ProvenanceRelation, ProvenanceStatus,
};

fn owner() -> ArtifactIdentity {
    let mut a = ArtifactIdentity::new("repo:demo", ArtifactType::Repo, "demo");
    a.source_uri = Some("https://example.test/demo".into());
    a.content_digest =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    a.provenance_status = ProvenanceStatus::Verified;
    a
}

#[test]
fn graph_is_deterministic_and_queries_explain_chain() {
    let mut g = ProvenanceGraph::default();
    let a = owner();
    let mut b = ArtifactIdentity::new("pkg:b", ArtifactType::Package, "b");
    b.source_uri = Some("https://e/b".into());
    b.content_digest = Some("sha256:bb".into());
    let mut c = ArtifactIdentity::new("file:c", ArtifactType::File, "c");
    c.source_uri = Some("https://e/c".into());
    c.content_digest = Some("sha256:cc".into());
    g.add_artifact(c).unwrap();
    g.add_artifact(a).unwrap();
    g.add_artifact(b).unwrap();
    g.add_edge(ProvenanceEdge {
        from_artifact_id: "repo:demo".into(),
        relation: ProvenanceRelation::DependsOn,
        to_artifact_id: "pkg:b".into(),
        evidence_kind: EvidenceKind::Observed,
        source: "fixture".into(),
        verified: true,
        confidence: Some(1.0),
    })
    .unwrap();
    g.add_edge(ProvenanceEdge {
        from_artifact_id: "pkg:b".into(),
        relation: ProvenanceRelation::Includes,
        to_artifact_id: "file:c".into(),
        evidence_kind: EvidenceKind::Declared,
        source: "fixture".into(),
        verified: false,
        confidence: Some(0.8),
    })
    .unwrap();
    assert_eq!(g.to_json_pretty().unwrap(), g.to_json_pretty().unwrap());
    let paths = g.why_is_this_here("file:c", 8);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].artifact_ids, vec!["repo:demo", "pkg:b", "file:c"]);
    assert!(!paths[0].fully_verified);
    assert_eq!(g.what_loads_this("file:c"), vec!["pkg:b"]);
    assert_eq!(g.show_unverified_chain().len(), 1);
}

#[test]
fn rejects_missing_edge_target_and_bad_confidence() {
    let mut g = ProvenanceGraph::default();
    g.add_artifact(owner()).unwrap();
    assert!(g
        .add_edge(ProvenanceEdge {
            from_artifact_id: "repo:demo".into(),
            relation: ProvenanceRelation::Loads,
            to_artifact_id: "missing".into(),
            evidence_kind: EvidenceKind::Observed,
            source: "x".into(),
            verified: false,
            confidence: None
        })
        .is_err());
    let b = ArtifactIdentity::new("b", ArtifactType::File, "b");
    g.add_artifact(b).unwrap();
    assert!(g
        .add_edge(ProvenanceEdge {
            from_artifact_id: "repo:demo".into(),
            relation: ProvenanceRelation::Loads,
            to_artifact_id: "b".into(),
            evidence_kind: EvidenceKind::Observed,
            source: "x".into(),
            verified: false,
            confidence: Some(1.1)
        })
        .is_err());
}

#[test]
fn apm_lock_declared_unverified_and_future_version_fails_closed() {
    let text="lockfile_version: '2'\ndependencies:\n- repo_url: https://user:secret@example.test/acme/pkg.git\n  name: pkg\n  version: 1.2.3\n  resolved_commit: deadbeef\n  content_hash: abcdef\n  declared_license: MIT\n";
    let g = apm::ingest_apm_lock(text, owner()).unwrap();
    let p = g.artifacts.values().find(|a| a.name == "pkg").unwrap();
    assert_eq!(p.provenance_status, ProvenanceStatus::Declared);
    assert_eq!(
        p.source_uri.as_deref(),
        Some("https://example.test/acme/pkg.git")
    );
    assert!(g.edges.iter().any(|e| !e.verified));
    assert!(apm::ingest_apm_lock("lockfile_version: '99'\ndependencies: []\n", owner()).is_err());
}

#[test]
fn cargo_lock_ingest_records_checksum_without_trusting_package() {
    let text="version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abcd\"\n";
    let g = cargo_lock::ingest_cargo_lock(text, owner()).unwrap();
    let p = g.artifacts.get("cargo:package:serde@1.0.0").unwrap();
    assert_eq!(p.content_digest.as_deref(), Some("sha256:abcd"));
    assert_eq!(p.provenance_status, ProvenanceStatus::Declared);
}

#[test]
fn mcp_tool_fingerprint_ignores_object_and_tool_order() {
    let a = r#"{"name":"srv","source":"https://u:token@example.test/s","tools":[{"name":"b","inputSchema":{"type":"object","properties":{"z":{"type":"string"},"a":{"type":"number"}}}},{"name":"a"}]}"#;
    let b = r#"{"name":"srv","source":"https://example.test/s","tools":[{"name":"a"},{"inputSchema":{"properties":{"a":{"type":"number"},"z":{"type":"string"}},"type":"object"},"name":"b"}]}"#;
    let ga = mcp::ingest_recorded_registry_json(a).unwrap();
    let gb = mcp::ingest_recorded_registry_json(b).unwrap();
    assert_eq!(
        ga.artifacts["mcp:server:srv"].metadata["tool_schema_digest"],
        gb.artifacts["mcp:server:srv"].metadata["tool_schema_digest"]
    );
    assert_eq!(
        ga.artifacts["mcp:server:srv"].source_uri.as_deref(),
        Some("https://example.test/s")
    );
}

#[test]
fn external_metadata_never_becomes_verified() {
    let gh = r#"{"repository":{"full_name":"acme/repo","html_url":"https://u:t@github.com/acme/repo","license":{"spdx_id":"MIT"}},"commit":{"sha":"abc"}}"#;
    let g = github::ingest_recorded_json(gh).unwrap();
    assert!(g
        .artifacts
        .values()
        .all(|a| a.provenance_status != ProvenanceStatus::Verified));
    let hf = r#"{"id":"acme/model","sha":"rev","license":"apache-2.0","base_model":["base/model"],"datasets":["ds/x"],"siblings":[{"rfilename":"model.safetensors","blob_id":"blob"}]}"#;
    let h = huggingface::ingest_recorded_model_card(hf).unwrap();
    assert!(h
        .artifacts
        .values()
        .all(|a| a.provenance_status != ProvenanceStatus::Verified));
}

#[test]
fn drift_covers_source_hash_schema_lineage_license_and_edges() {
    let mut before = ProvenanceGraph::default();
    let mut a = owner();
    a.metadata.insert("license".into(), "MIT".into());
    a.metadata
        .insert("tool_schema_digest".into(), "sha256:1".into());
    a.metadata.insert("lineage".into(), "base-a".into());
    before.add_artifact(a).unwrap();
    let mut b = ArtifactIdentity::new("dep", ArtifactType::Package, "dep");
    b.source_uri = Some("https://e/dep".into());
    b.content_digest = Some("sha256:1".into());
    before.add_artifact(b).unwrap();
    before
        .add_edge(ProvenanceEdge {
            from_artifact_id: "repo:demo".into(),
            relation: ProvenanceRelation::DependsOn,
            to_artifact_id: "dep".into(),
            evidence_kind: EvidenceKind::Declared,
            source: "lock".into(),
            verified: false,
            confidence: None,
        })
        .unwrap();
    let mut after = before.clone();
    let aa = after.artifacts.get_mut("repo:demo").unwrap();
    aa.source_uri = Some("https://e/changed".into());
    aa.content_digest = Some("sha256:2".into());
    aa.metadata.insert("license".into(), "Apache-2.0".into());
    aa.metadata
        .insert("tool_schema_digest".into(), "sha256:2".into());
    aa.metadata.insert("lineage".into(), "base-b".into());
    after.edges.clear();
    let kinds: Vec<_> = detect_drift(&before, &after)
        .into_iter()
        .map(|d| d.kind)
        .collect();
    for k in [
        DriftKind::SourceRefDrift,
        DriftKind::HashDrift,
        DriftKind::LicenseMetadataDrift,
        DriftKind::ToolSchemaDrift,
        DriftKind::LineageDrift,
        DriftKind::EdgeRemoved,
    ] {
        assert!(kinds.contains(&k), "missing {k:?}");
    }
}

#[test]
fn bom_exports_are_standard_shaped() {
    let mut g = ProvenanceGraph::default();
    g.add_artifact(owner()).unwrap();
    let spdx = to_spdx_23_json(&g, "demo");
    assert_eq!(spdx["spdxVersion"], "SPDX-2.3");
    assert_eq!(spdx["dataLicense"], "CC0-1.0");
    let cdx = to_cyclonedx_16_json(&g);
    assert_eq!(cdx["bomFormat"], "CycloneDX");
    assert_eq!(cdx["specVersion"], "1.6");
}

#[test]
fn git_remote_normalization_strips_credentials() {
    assert_eq!(
        git::normalize_remote("https://user:token@GitHub.com/Acme/Repo.git"),
        "https://github.com/acme/repo"
    );
    assert_eq!(
        git::normalize_remote("git@GitHub.com:Acme/Repo.git"),
        "https://github.com/acme/repo"
    );
}

#[test]
fn npm_lock_v3_ingest_is_deterministic_and_redacts_credentials() {
    let json = r#"{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/@scope/pkg":{"version":"2.1.0","resolved":"https://u:secret@registry.example.test/@scope/pkg.tgz","integrity":"sha512-abc","license":"MIT"},"node_modules/z":{"version":"1.0.0","resolved":"https://registry.example.test/z.tgz","integrity":"sha256-def","dev":true}}}"#;
    let g = npm_lock::ingest_package_lock(json, owner()).unwrap();
    assert_eq!(g.artifacts.len(), 3);
    let p = g.artifacts.get("npm:package:@scope/pkg@2.1.0").unwrap();
    assert_eq!(
        p.source_uri.as_deref(),
        Some("https://registry.example.test/@scope/pkg.tgz")
    );
    assert_eq!(p.content_digest.as_deref(), Some("sri:sha512-abc"));
    assert_eq!(
        p.metadata.get("license").and_then(|v| v.as_str()),
        Some("MIT")
    );
    assert!(npm_lock::ingest_package_lock(r#"{"lockfileVersion":99}"#, owner()).is_err());
}

#[test]
fn explain_query_terminates_on_cycles() {
    let mut g = ProvenanceGraph::default();
    for id in ["a", "b", "c"] {
        g.add_artifact(ArtifactIdentity::new(id, ArtifactType::Package, id))
            .unwrap();
    }
    for (from, to) in [("a", "b"), ("b", "c"), ("c", "a")] {
        g.add_edge(ProvenanceEdge {
            from_artifact_id: from.into(),
            relation: ProvenanceRelation::DependsOn,
            to_artifact_id: to.into(),
            evidence_kind: EvidenceKind::Declared,
            source: "cycle".into(),
            verified: false,
            confidence: None,
        })
        .unwrap();
    }
    assert!(g.why_is_this_here("c", 16).is_empty());
}

#[test]
fn explain_query_respects_path_cap() {
    let mut g = ProvenanceGraph::default();
    g.add_artifact(ArtifactIdentity::new("leaf", ArtifactType::File, "leaf"))
        .unwrap();
    for i in 0..32 {
        let root = format!("root:{i:02}");
        g.add_artifact(ArtifactIdentity::new(&root, ArtifactType::Repo, &root))
            .unwrap();
        g.add_edge(ProvenanceEdge {
            from_artifact_id: root,
            relation: ProvenanceRelation::Includes,
            to_artifact_id: "leaf".into(),
            evidence_kind: EvidenceKind::Declared,
            source: "fan-in".into(),
            verified: false,
            confidence: None,
        })
        .unwrap();
    }
    assert_eq!(g.why_is_this_here_bounded("leaf", 4, 5).len(), 5);
    assert!(g.why_is_this_here_bounded("leaf", 4, 0).is_empty());
}

#[test]
fn strict_graph_json_rejects_future_schema_and_invalid_edges() {
    let mut g = ProvenanceGraph::default();
    g.add_artifact(ArtifactIdentity::new("a", ArtifactType::Repo, "a"))
        .unwrap();
    let valid = g.to_json_pretty().unwrap();
    assert_eq!(ProvenanceGraph::from_json_strict(&valid).unwrap(), g);

    let future = valid.replace("\"schema_version\": \"0.1\"", "\"schema_version\": \"99\"");
    assert!(ProvenanceGraph::from_json_strict(&future).is_err());

    let invalid_edge = r#"{"schema_version":"0.1","artifacts":{"a":{"schema_version":"0.1","artifact_id":"a","artifact_type":"repo","name":"a","provenance_status":"unknown","metadata":{}}},"edges":[{"from_artifact_id":"a","relation":"depends_on","to_artifact_id":"missing","evidence_kind":"declared","source":"fixture","verified":false}]}"#;
    assert!(ProvenanceGraph::from_json_strict(invalid_edge).is_err());
}

#[test]
fn recorded_metadata_limits_fail_closed() {
    let huge = "x".repeat(8 * 1024 * 1024 + 1);
    assert!(github::ingest_recorded_json(&huge).is_err());
    assert!(huggingface::ingest_recorded_model_card(&huge).is_err());
    assert!(mcp::ingest_recorded_registry_json(&huge).is_err());

    let tools: Vec<_> = (0..10_001)
        .map(|i| serde_json::json!({"name": format!("tool-{i}")}))
        .collect();
    let mcp_json = serde_json::json!({"name":"srv","tools":tools}).to_string();
    assert!(mcp::ingest_recorded_registry_json(&mcp_json).is_err());
}

#[test]
fn pnpm_lock_ingest_handles_scoped_packages_integrity_and_redaction() {
    let yaml = r#"lockfileVersion: '9.0'
packages:
  '@scope/pkg@2.1.0':
    resolution:
      integrity: sha512-abc
      tarball: https://u:secret@registry.example.test/@scope/pkg.tgz
  'plain@1.0.0':
    resolution:
      integrity: sha256-def
    dev: true
"#;
    let g = pnpm_lock::ingest_pnpm_lock(yaml, owner()).unwrap();
    let scoped = g.artifacts.get("pnpm:package:@scope/pkg@2.1.0").unwrap();
    assert_eq!(scoped.content_digest.as_deref(), Some("sri:sha512-abc"));
    assert_eq!(
        scoped.source_uri.as_deref(),
        Some("https://registry.example.test/@scope/pkg.tgz")
    );
    assert_eq!(scoped.provenance_status, ProvenanceStatus::Declared);
    assert_eq!(
        g.artifacts["pnpm:package:plain@1.0.0"].metadata["dev"],
        true
    );
    assert!(
        pnpm_lock::ingest_pnpm_lock("lockfileVersion: '99.0'\npackages: {}\n", owner()).is_err()
    );
}
