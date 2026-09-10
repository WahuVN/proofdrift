use proofdrift_provenance::{
    ArtifactIdentity, ArtifactType, EvidenceKind, ProvenanceEdge, ProvenanceGraph,
    ProvenanceRelation,
};
use proofdrift_registry::LocalRegistry;

#[test]
fn sqlite_roundtrip_is_lossless_and_replace_works() {
    let mut g = ProvenanceGraph::default();
    g.add_artifact(ArtifactIdentity::new("a", ArtifactType::Repo, "a"))
        .unwrap();
    g.add_artifact(ArtifactIdentity::new("b", ArtifactType::Package, "b"))
        .unwrap();
    g.add_edge(ProvenanceEdge {
        from_artifact_id: "a".into(),
        relation: ProvenanceRelation::DependsOn,
        to_artifact_id: "b".into(),
        evidence_kind: EvidenceKind::Declared,
        source: "fixture".into(),
        verified: false,
        confidence: None,
    })
    .unwrap();
    let mut db = LocalRegistry::open_in_memory().unwrap();
    db.replace_graph(&g).unwrap();
    assert_eq!(db.load_graph().unwrap(), g);
    assert_eq!(db.get_artifact("b").unwrap().unwrap().name, "b");
    assert_eq!(db.incoming_edges("b").unwrap().len(), 1);
    assert_eq!(db.outgoing_edges("a").unwrap().len(), 1);
    assert_eq!(db.unverified_edges().unwrap().len(), 1);
    let empty = ProvenanceGraph::default();
    db.replace_graph(&empty).unwrap();
    assert_eq!(db.load_graph().unwrap(), empty);
    assert!(db.get_artifact("b").unwrap().is_none());
}

#[test]
fn opens_and_upgrades_legacy_registry_schema() {
    let path = std::env::temp_dir().join(format!(
        "proofdrift-registry-legacy-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY, json TEXT NOT NULL); CREATE TABLE edges (edge_key TEXT PRIMARY KEY, json TEXT NOT NULL);").unwrap();
    }
    let mut db = LocalRegistry::open(&path).unwrap();
    let mut graph = ProvenanceGraph::default();
    graph
        .add_artifact(ArtifactIdentity::new(
            "legacy:a",
            ArtifactType::Repo,
            "legacy",
        ))
        .unwrap();
    db.replace_graph(&graph).unwrap();
    assert_eq!(db.get_artifact("legacy:a").unwrap().unwrap().name, "legacy");
    drop(db);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn immutable_snapshots_support_baseline_current_diff() {
    let db = LocalRegistry::open_in_memory().unwrap();
    let mut baseline = ProvenanceGraph::default();
    baseline
        .add_artifact(ArtifactIdentity::new("a", ArtifactType::Repo, "a"))
        .unwrap();
    let mut current = baseline.clone();
    current
        .add_artifact(ArtifactIdentity::new("b", ArtifactType::Package, "b"))
        .unwrap();
    current
        .add_edge(ProvenanceEdge {
            from_artifact_id: "a".into(),
            relation: ProvenanceRelation::DependsOn,
            to_artifact_id: "b".into(),
            evidence_kind: EvidenceKind::Declared,
            source: "fixture".into(),
            verified: false,
            confidence: None,
        })
        .unwrap();

    let baseline_info = db.save_snapshot("baseline", &baseline).unwrap();
    db.save_snapshot("current", &current).unwrap();
    let snapshots = db.list_snapshots().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert!(baseline_info.content_digest.starts_with("sha256:"));
    assert_eq!(snapshots[0].content_digest.len(), 71);
    assert_eq!(db.load_snapshot("baseline").unwrap(), baseline);
    assert!(!db.diff_snapshots("baseline", "current").unwrap().is_empty());
    assert!(db.save_snapshot("baseline", &current).is_err());
    assert!(db.save_snapshot("   ", &current).is_err());
    assert!(db.load_snapshot("missing").is_err());
}

#[test]
fn legacy_snapshot_schema_backfills_digest_without_losing_graph() {
    let path = std::env::temp_dir().join(format!(
        "proofdrift-registry-old-snapshot-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut graph = ProvenanceGraph::default();
    graph
        .add_artifact(ArtifactIdentity::new(
            "legacy:s",
            ArtifactType::Repo,
            "legacy",
        ))
        .unwrap();
    let json = graph.to_json_pretty().unwrap();
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE artifacts (artifact_id TEXT PRIMARY KEY, json TEXT NOT NULL); CREATE TABLE edges (edge_key TEXT PRIMARY KEY, json TEXT NOT NULL); CREATE TABLE snapshots (name TEXT PRIMARY KEY, created_unix_ms INTEGER NOT NULL, json TEXT NOT NULL);").unwrap();
        conn.execute(
            "INSERT INTO snapshots(name,created_unix_ms,json) VALUES ('old',1,?1)",
            [&json],
        )
        .unwrap();
    }
    {
        let db = LocalRegistry::open(&path).unwrap();
        assert_eq!(db.load_snapshot("old").unwrap(), graph);
        assert!(db.list_snapshots().unwrap()[0]
            .content_digest
            .starts_with("sha256:"));
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn snapshot_digest_detects_tampering() {
    let path = std::env::temp_dir().join(format!(
        "proofdrift-registry-snapshot-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut graph = ProvenanceGraph::default();
    graph
        .add_artifact(ArtifactIdentity::new("a", ArtifactType::Repo, "a"))
        .unwrap();
    {
        let db = LocalRegistry::open(&path).unwrap();
        db.save_snapshot("clean", &graph).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE snapshots SET json=?1 WHERE name='clean'", ["{}"])
            .unwrap();
    }
    {
        let db = LocalRegistry::open(&path).unwrap();
        assert!(db.load_snapshot("clean").is_err());
    }
    std::fs::remove_file(path).unwrap();
}
