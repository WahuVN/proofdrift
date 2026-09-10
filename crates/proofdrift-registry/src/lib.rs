//! Local-only SQLite registry for provenance graphs.
//! No hosted service or network behavior is implemented here.

use proofdrift_provenance::{ArtifactIdentity, ProvenanceEdge, ProvenanceGraph};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("sqlite error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("graph error: {0}")]
    Graph(#[from] proofdrift_provenance::GraphError),
    #[error("snapshot name must not be empty")]
    EmptySnapshotName,
    #[error("snapshot not found: {0}")]
    SnapshotNotFound(String),
    #[error("system clock is before UNIX epoch")]
    ClockBeforeEpoch,
    #[error("snapshot integrity mismatch: {0}")]
    SnapshotIntegrityMismatch(String),
}

pub struct LocalRegistry {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    pub created_unix_ms: u64,
    pub content_digest: String,
}

fn snapshot_digest(json: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(json.as_bytes()))
}

impl LocalRegistry {
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        let conn = Connection::open_in_memory()?;
        let this = Self { conn };
        this.migrate()?;
        Ok(this)
    }
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, RegistryError> {
        let conn = Connection::open(path)?;
        let this = Self { conn };
        this.migrate()?;
        Ok(this)
    }

    fn migrate(&self) -> Result<(), RegistryError> {
        self.conn.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS artifacts (artifact_id TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS edges (edge_key TEXT PRIMARY KEY, json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS snapshots (name TEXT PRIMARY KEY, created_unix_ms INTEGER NOT NULL, json TEXT NOT NULL, content_digest TEXT NOT NULL DEFAULT '');"
        )?;
        self.ensure_column("artifacts", "artifact_type", "TEXT NOT NULL DEFAULT ''")?;
        self.ensure_column("artifacts", "name", "TEXT NOT NULL DEFAULT ''")?;
        self.ensure_column("artifacts", "provenance_status", "TEXT NOT NULL DEFAULT ''")?;
        self.ensure_column("edges", "from_artifact_id", "TEXT NOT NULL DEFAULT ''")?;
        self.ensure_column("edges", "to_artifact_id", "TEXT NOT NULL DEFAULT ''")?;
        self.ensure_column("edges", "verified", "INTEGER NOT NULL DEFAULT 0")?;
        self.ensure_column("snapshots", "content_digest", "TEXT NOT NULL DEFAULT ''")?;
        self.backfill_snapshot_digests()?;
        self.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_type_name ON artifacts(artifact_type,name);
             CREATE INDEX IF NOT EXISTS idx_artifacts_status ON artifacts(provenance_status);
             CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_artifact_id);
             CREATE INDEX IF NOT EXISTS idx_edges_to ON edges(to_artifact_id);
             CREATE INDEX IF NOT EXISTS idx_edges_verified ON edges(verified);",
        )?;
        Ok(())
    }

    fn ensure_column(
        &self,
        table: &str,
        column: &str,
        definition: &str,
    ) -> Result<(), RegistryError> {
        let pragma = format!("PRAGMA table_info({table})");
        let mut stmt = self.conn.prepare(&pragma)?;
        let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
        for existing in columns {
            if existing? == column {
                return Ok(());
            }
        }
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        self.conn.execute_batch(&sql)?;
        Ok(())
    }

    fn backfill_snapshot_digests(&self) -> Result<(), RegistryError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name,json FROM snapshots WHERE content_digest='' ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut updates = Vec::new();
        for row in rows {
            let (name, json) = row?;
            updates.push((name, snapshot_digest(&json)));
        }
        drop(stmt);
        for (name, digest) in updates {
            self.conn.execute(
                "UPDATE snapshots SET content_digest=?1 WHERE name=?2 AND content_digest=''",
                params![digest, name],
            )?;
        }
        Ok(())
    }

    pub fn replace_graph(&mut self, graph: &ProvenanceGraph) -> Result<(), RegistryError> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM edges", [])?;
        tx.execute("DELETE FROM artifacts", [])?;
        for (id, artifact) in &graph.artifacts {
            tx.execute(
                "INSERT INTO artifacts(artifact_id,artifact_type,name,provenance_status,json) VALUES (?1,?2,?3,?4,?5)",
                params![id, format!("{:?}", artifact.artifact_type), artifact.name, format!("{:?}", artifact.provenance_status), serde_json::to_string(artifact)?]
            )?;
        }
        for edge in &graph.edges {
            tx.execute(
                "INSERT INTO edges(edge_key,from_artifact_id,to_artifact_id,verified,json) VALUES (?1,?2,?3,?4,?5)",
                params![edge.key(), edge.from_artifact_id, edge.to_artifact_id, i64::from(edge.verified), serde_json::to_string(edge)?]
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_graph(&self) -> Result<ProvenanceGraph, RegistryError> {
        let mut graph = ProvenanceGraph::default();
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM artifacts ORDER BY artifact_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            graph.add_artifact(serde_json::from_str::<ArtifactIdentity>(&row?)?)?;
        }
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM edges ORDER BY edge_key")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for row in rows {
            graph.add_edge(serde_json::from_str::<ProvenanceEdge>(&row?)?)?;
        }
        Ok(graph)
    }

    pub fn get_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ArtifactIdentity>, RegistryError> {
        let raw = self
            .conn
            .query_row(
                "SELECT json FROM artifacts WHERE artifact_id=?1",
                [artifact_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        raw.map(|json| serde_json::from_str(&json).map_err(RegistryError::from))
            .transpose()
    }

    pub fn incoming_edges(&self, artifact_id: &str) -> Result<Vec<ProvenanceEdge>, RegistryError> {
        self.edge_query(
            "SELECT json FROM edges WHERE to_artifact_id=?1 ORDER BY edge_key",
            artifact_id,
        )
    }

    pub fn outgoing_edges(&self, artifact_id: &str) -> Result<Vec<ProvenanceEdge>, RegistryError> {
        self.edge_query(
            "SELECT json FROM edges WHERE from_artifact_id=?1 ORDER BY edge_key",
            artifact_id,
        )
    }

    pub fn unverified_edges(&self) -> Result<Vec<ProvenanceEdge>, RegistryError> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM edges WHERE verified=0 ORDER BY edge_key")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    pub fn save_snapshot(
        &self,
        name: &str,
        graph: &ProvenanceGraph,
    ) -> Result<SnapshotInfo, RegistryError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(RegistryError::EmptySnapshotName);
        }
        let created_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| RegistryError::ClockBeforeEpoch)?
            .as_millis() as u64;
        let json = graph.to_json_pretty()?;
        let content_digest = snapshot_digest(&json);
        self.conn.execute(
            "INSERT INTO snapshots(name,created_unix_ms,json,content_digest) VALUES (?1,?2,?3,?4)",
            params![name, created_unix_ms, json, content_digest],
        )?;
        Ok(SnapshotInfo {
            name: name.to_string(),
            created_unix_ms,
            content_digest,
        })
    }

    pub fn load_snapshot(&self, name: &str) -> Result<ProvenanceGraph, RegistryError> {
        let raw = self
            .conn
            .query_row(
                "SELECT json,content_digest FROM snapshots WHERE name=?1",
                [name],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (json, expected_digest) =
            raw.ok_or_else(|| RegistryError::SnapshotNotFound(name.to_string()))?;
        if snapshot_digest(&json) != expected_digest {
            return Err(RegistryError::SnapshotIntegrityMismatch(name.to_string()));
        }
        Ok(ProvenanceGraph::from_json_strict(&json)?)
    }

    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>, RegistryError> {
        let mut stmt = self.conn.prepare(
            "SELECT name,created_unix_ms,content_digest FROM snapshots ORDER BY created_unix_ms,name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SnapshotInfo {
                name: row.get(0)?,
                created_unix_ms: row.get::<_, u64>(1)?,
                content_digest: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn diff_snapshots(
        &self,
        baseline: &str,
        current: &str,
    ) -> Result<Vec<proofdrift_provenance::ProvenanceDrift>, RegistryError> {
        let baseline = self.load_snapshot(baseline)?;
        let current = self.load_snapshot(current)?;
        Ok(current.what_changed_since(&baseline))
    }

    fn edge_query(
        &self,
        sql: &str,
        artifact_id: &str,
    ) -> Result<Vec<ProvenanceEdge>, RegistryError> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([artifact_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }
}
