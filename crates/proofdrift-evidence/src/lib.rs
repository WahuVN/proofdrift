//! Evidence persistence, redaction, hash chaining and safe `.proofdrift` bundles.
//! Security properties are deliberately narrow: integrity evidence is not a
//! correctness proof and timestamps are not treated as a trusted clock.

use regex::Regex;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};
use thiserror::Error;
use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const SCHEMA_VERSION: &str = "0.1";
pub const GENESIS_HASH: &str = "GENESIS";

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("invalid evidence: {0}")]
    Invalid(String),
    #[error("bundle limit exceeded: {0}")]
    Limit(String),
}

pub type Result<T> = std::result::Result<T, EvidenceError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentEventInput {
    pub event_id: String,
    pub session_id: String,
    pub timestamp_wall: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_monotonic_ns: Option<u64>,
    pub actor: String,
    pub adapter_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
    pub event_type: String,
    pub proposed_action: String,
    pub resource: String,
    #[serde(default)]
    pub normalized_args: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    pub outcome: String,
    pub enforcement_level: String,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StoredEvent {
    pub schema_version: String,
    #[serde(flatten)]
    pub event: AgentEventInput,
    pub sequence: u64,
    pub prev_event_hash: String,
    pub event_hash: String,
    #[serde(default)]
    pub redactions: Vec<RedactionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionRecord {
    pub json_path: String,
    pub reason: String,
    pub source_category: String,
}

#[derive(Clone, Debug)]
pub struct Redactor {
    key_pattern: Regex,
    bearer_pattern: Regex,
    generic_token_pattern: Regex,
    synthetic_secrets: Vec<String>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl Redactor {
    pub fn new(synthetic_secrets: Vec<String>) -> Self {
        Self {
            key_pattern: Regex::new("(?i)(secret|token|password|passwd|cookie|authorization|api[_-]?key|private[_-]?key|credential)").unwrap(),
            bearer_pattern: Regex::new("(?i)bearer\\s+[A-Za-z0-9._~+/-]{8,}={0,2}").unwrap(),
            generic_token_pattern: Regex::new("(?i)(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})").unwrap(),
            synthetic_secrets,
        }
    }

    pub fn redact_value(&self, value: &Value) -> (Value, Vec<RedactionRecord>) {
        let mut out = value.clone();
        let mut records = Vec::new();
        self.walk(&mut out, "$", None, &mut records);
        (out, records)
    }

    fn walk(
        &self,
        value: &mut Value,
        path: &str,
        key: Option<&str>,
        records: &mut Vec<RedactionRecord>,
    ) {
        if let Some(k) = key {
            if self.key_pattern.is_match(k) {
                if !value.is_null() {
                    *value = Value::String("[REDACTED]".into());
                    records.push(RedactionRecord {
                        json_path: path.into(),
                        reason: "sensitive_key".into(),
                        source_category: "credential".into(),
                    });
                }
                return;
            }
        }
        match value {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    let p = format!("{}.{}", path, escape_path(k));
                    self.walk(v, &p, Some(k), records);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter_mut().enumerate() {
                    self.walk(item, &format!("{}[{}]", path, i), None, records);
                }
            }
            Value::String(s) => {
                let original = s.clone();
                let mut redacted = self
                    .bearer_pattern
                    .replace_all(&original, "[REDACTED]")
                    .to_string();
                redacted = self
                    .generic_token_pattern
                    .replace_all(&redacted, "[REDACTED]")
                    .to_string();
                for secret in self.synthetic_secrets.iter().filter(|s| !s.is_empty()) {
                    redacted = redacted.replace(secret, "[REDACTED]");
                }
                if redacted != original {
                    *s = redacted;
                    records.push(RedactionRecord {
                        json_path: path.into(),
                        reason: "secret_value_pattern".into(),
                        source_category: "payload".into(),
                    });
                }
            }
            _ => {}
        }
    }
}

fn escape_path(s: &str) -> String {
    s.replace('~', "~0").replace('.', "~1")
}

pub struct EvidenceStore {
    conn: Connection,
    redactor: Redactor,
}

impl EvidenceStore {
    pub fn open(path: impl AsRef<Path>, redactor: Redactor) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self { conn, redactor })
    }

    pub fn open_memory(redactor: Redactor) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self { conn, redactor })
    }

    /// Appends one event atomically. Sequence and previous hash are allocated
    /// inside an IMMEDIATE transaction, preventing two writers in this process
    /// from creating the same sequence when each has its own SQLite connection.
    pub fn append(&mut self, input: AgentEventInput) -> Result<StoredEvent> {
        validate_input(&input)?;
        let (args, mut redactions) = self.redactor.redact_value(&input.normalized_args);
        let (resource_value, resource_redactions) = self
            .redactor
            .redact_value(&Value::String(input.resource.clone()));
        redactions.extend(resource_redactions.into_iter().map(|mut r| {
            r.json_path = "$.resource".into();
            r
        }));
        let mut clean = input;
        clean.normalized_args = args;
        clean.resource = resource_value.as_str().unwrap_or("[REDACTED]").to_string();

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (next_sequence, prev_hash): (u64, String) = tx.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1, COALESCE((SELECT event_hash FROM events WHERE session_id=?1 ORDER BY sequence DESC LIMIT 1), ?2) FROM events WHERE session_id=?1",
            params![clean.session_id, GENESIS_HASH],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let event_hash = compute_event_hash(&clean, next_sequence, &prev_hash, &redactions)?;
        let payload = serde_json::to_string(&clean)?;
        let redactions_json = serde_json::to_string(&redactions)?;
        tx.execute(
            "INSERT INTO events(session_id, sequence, event_id, prev_event_hash, event_hash, payload_json, redactions_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![clean.session_id, next_sequence, clean.event_id, prev_hash, event_hash, payload, redactions_json],
        )?;
        tx.commit()?;
        Ok(StoredEvent {
            schema_version: SCHEMA_VERSION.into(),
            event: clean,
            sequence: next_sequence,
            prev_event_hash: prev_hash,
            event_hash,
            redactions,
        })
    }

    pub fn append_batch(
        &mut self,
        inputs: Vec<AgentEventInput>,
        max_batch: usize,
    ) -> Result<Vec<StoredEvent>> {
        if max_batch == 0 || inputs.len() > max_batch {
            return Err(EvidenceError::Limit(format!(
                "batch count {} > {}",
                inputs.len(),
                max_batch
            )));
        }
        if inputs.is_empty() {
            return Ok(Vec::new());
        }

        let mut cleaned = Vec::with_capacity(inputs.len());
        for input in inputs {
            validate_input(&input)?;
            let (args, mut redactions) = self.redactor.redact_value(&input.normalized_args);
            let (resource_value, resource_redactions) = self
                .redactor
                .redact_value(&Value::String(input.resource.clone()));
            redactions.extend(resource_redactions.into_iter().map(|mut r| {
                r.json_path = "$.resource".into();
                r
            }));
            let mut clean = input;
            clean.normalized_args = args;
            clean.resource = resource_value.as_str().unwrap_or("[REDACTED]").to_string();
            cleaned.push((clean, redactions));
        }

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut out = Vec::with_capacity(cleaned.len());
        for (clean, redactions) in cleaned {
            let (next_sequence, prev_hash): (u64, String) = tx.query_row(
                "SELECT COALESCE(MAX(sequence),0)+1, COALESCE((SELECT event_hash FROM events WHERE session_id=?1 ORDER BY sequence DESC LIMIT 1), ?2) FROM events WHERE session_id=?1",
                params![clean.session_id, GENESIS_HASH],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let event_hash = compute_event_hash(&clean, next_sequence, &prev_hash, &redactions)?;
            let payload = serde_json::to_string(&clean)?;
            let redactions_json = serde_json::to_string(&redactions)?;
            tx.execute(
                "INSERT INTO events(session_id, sequence, event_id, prev_event_hash, event_hash, payload_json, redactions_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![clean.session_id, next_sequence, clean.event_id, prev_hash, event_hash, payload, redactions_json],
            )?;
            out.push(StoredEvent {
                schema_version: SCHEMA_VERSION.into(),
                event: clean,
                sequence: next_sequence,
                prev_event_hash: prev_hash,
                event_hash,
                redactions,
            });
        }
        tx.commit()?;
        Ok(out)
    }

    pub fn load_session(&self, session_id: &str) -> Result<Vec<StoredEvent>> {
        let mut stmt = self.conn.prepare("SELECT sequence, prev_event_hash, event_hash, payload_json, redactions_json FROM events WHERE session_id=?1 ORDER BY sequence")?;
        let rows = stmt.query_map([session_id], |row| {
            let sequence: u64 = row.get(0)?;
            let prev_event_hash: String = row.get(1)?;
            let event_hash: String = row.get(2)?;
            let payload: String = row.get(3)?;
            let redactions: String = row.get(4)?;
            Ok((sequence, prev_event_hash, event_hash, payload, redactions))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, prev_event_hash, event_hash, payload, redactions) = row?;
            out.push(StoredEvent {
                schema_version: SCHEMA_VERSION.into(),
                event: serde_json::from_str(&payload)?,
                sequence,
                prev_event_hash,
                event_hash,
                redactions: serde_json::from_str(&redactions)?,
            });
        }
        Ok(out)
    }

    /// Returns known session identifiers in deterministic order without
    /// exposing event payloads. This is used by the local CLI report view.
    pub fn list_sessions(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT session_id FROM events ORDER BY session_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn verify_session(&self, session_id: &str) -> Result<ChainVerification> {
        verify_chain(&self.load_session(session_id)?)
    }

    pub fn checkpoint(&self) -> Result<()> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS events(\n        session_id TEXT NOT NULL,\n        sequence INTEGER NOT NULL CHECK(sequence > 0),\n        event_id TEXT NOT NULL,\n        prev_event_hash TEXT NOT NULL,\n        event_hash TEXT NOT NULL,\n        payload_json TEXT NOT NULL,\n        redactions_json TEXT NOT NULL DEFAULT '[]',\n        PRIMARY KEY(session_id, sequence),\n        UNIQUE(session_id, event_id)\n    ); CREATE INDEX IF NOT EXISTS idx_events_hash ON events(session_id,event_hash);")?;
    Ok(())
}

fn validate_input(e: &AgentEventInput) -> Result<()> {
    for (name, value) in [
        ("event_id", &e.event_id),
        ("session_id", &e.session_id),
        ("timestamp_wall", &e.timestamp_wall),
        ("actor", &e.actor),
        ("adapter_id", &e.adapter_id),
        ("event_type", &e.event_type),
        ("proposed_action", &e.proposed_action),
        ("resource", &e.resource),
        ("outcome", &e.outcome),
        ("enforcement_level", &e.enforcement_level),
    ] {
        if value.trim().is_empty() {
            return Err(EvidenceError::Invalid(format!("{name} is empty")));
        }
    }
    if !matches!(
        e.enforcement_level.as_str(),
        "L0" | "L1" | "L2" | "L3" | "OBSERVE_ONLY"
    ) {
        return Err(EvidenceError::Invalid("unknown enforcement_level".into()));
    }
    Ok(())
}

pub fn canonical_json(value: &Value) -> String {
    fn normalize(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut sorted = BTreeMap::new();
                for (k, v) in m {
                    sorted.insert(k.clone(), normalize(v));
                }
                serde_json::to_value(sorted).expect("BTreeMap serializes")
            }
            Value::Array(a) => Value::Array(a.iter().map(normalize).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_string(&normalize(value)).expect("JSON value serializes")
}

fn compute_event_hash(
    input: &AgentEventInput,
    sequence: u64,
    prev: &str,
    redactions: &[RedactionRecord],
) -> Result<String> {
    let mut object = Map::new();
    object.insert(
        "schema_version".into(),
        Value::String(SCHEMA_VERSION.into()),
    );
    object.insert("event".into(), serde_json::to_value(input)?);
    object.insert("sequence".into(), Value::from(sequence));
    object.insert("prev_event_hash".into(), Value::String(prev.into()));
    object.insert("redactions".into(), serde_json::to_value(redactions)?);
    Ok(sha256_hex(
        canonical_json(&Value::Object(object)).as_bytes(),
    ))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainVerification {
    pub valid: bool,
    pub event_count: usize,
    pub final_hash: String,
}

pub fn verify_chain(events: &[StoredEvent]) -> Result<ChainVerification> {
    let mut prev = GENESIS_HASH.to_string();
    let mut seen_ids = BTreeSet::new();
    for (expected_sequence, e) in (1u64..).zip(events.iter()) {
        if e.sequence != expected_sequence {
            return Err(EvidenceError::Invalid(format!(
                "sequence gap/reorder at {} expected {}",
                e.sequence, expected_sequence
            )));
        }
        if e.prev_event_hash != prev {
            return Err(EvidenceError::Invalid(format!(
                "previous hash mismatch at sequence {}",
                e.sequence
            )));
        }
        if !seen_ids.insert(&e.event.event_id) {
            return Err(EvidenceError::Invalid(format!(
                "duplicate event_id {}",
                e.event.event_id
            )));
        }
        let expected = compute_event_hash(&e.event, e.sequence, &e.prev_event_hash, &e.redactions)?;
        if expected != e.event_hash {
            return Err(EvidenceError::Invalid(format!(
                "event hash mismatch at sequence {}",
                e.sequence
            )));
        }
        prev = e.event_hash.clone();
    }
    Ok(ChainVerification {
        valid: true,
        event_count: events.len(),
        final_hash: prev,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub schema_version: String,
    pub bundle_format: String,
    pub session_id: String,
    pub files: BTreeMap<String, FileDigest>,
    pub event_chain_final_hash: String,
    pub receipt_semantics: ReceiptSemantics,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileDigest {
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptSemantics {
    pub proves: Vec<String>,
    pub does_not_prove: Vec<String>,
}

impl Default for ReceiptSemantics {
    fn default() -> Self {
        Self {
            proves: vec![
                "covered bundle bytes match manifest digests".into(),
                "event chain ordering/hash linkage verifies".into(),
            ],
            does_not_prove: vec![
                "software correctness".into(),
                "agent benevolence".into(),
                "truth of external metadata".into(),
                "OS isolation unless separately evidenced".into(),
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct BundleLimits {
    pub max_entries: usize,
    pub max_file_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    pub max_compression_ratio: u64,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_uncompressed_bytes: 256 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BundleInput {
    pub session_id: String,
    pub events: Vec<StoredEvent>,
    /// Relative archive path -> bytes. Reserved manifest/hashes entries are rejected.
    pub assets: BTreeMap<String, Vec<u8>>,
}

pub fn create_proofdrift_bundle(
    path: impl AsRef<Path>,
    input: &BundleInput,
    limits: &BundleLimits,
) -> Result<BundleManifest> {
    if input.session_id.trim().is_empty() {
        return Err(EvidenceError::Invalid("session_id empty".into()));
    }
    let chain = verify_chain(&input.events)?;
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut events_jsonl = Vec::new();
    for event in &input.events {
        serde_json::to_writer(&mut events_jsonl, event)?;
        events_jsonl.push(b'\n');
    }
    files.insert("events.jsonl".into(), events_jsonl);
    for (name, bytes) in &input.assets {
        validate_archive_name(name)?;
        if matches!(name.as_str(), "manifest.json" | "hashes.json") {
            return Err(EvidenceError::Invalid(format!("reserved entry {name}")));
        }
        if files.insert(name.clone(), bytes.clone()).is_some() {
            return Err(EvidenceError::Invalid(format!("duplicate entry {name}")));
        }
    }
    enforce_create_limits(&files, limits)?;
    let digest_map: BTreeMap<String, FileDigest> = files
        .iter()
        .map(|(name, bytes)| {
            (
                name.clone(),
                FileDigest {
                    sha256: sha256_hex(bytes),
                    size: bytes.len() as u64,
                },
            )
        })
        .collect();
    let manifest = BundleManifest {
        schema_version: SCHEMA_VERSION.into(),
        bundle_format: "proofdrift/1".into(),
        session_id: input.session_id.clone(),
        files: digest_map.clone(),
        event_chain_final_hash: chain.final_hash,
        receipt_semantics: ReceiptSemantics::default(),
    };
    let manifest_bytes = canonical_json(&serde_json::to_value(&manifest)?).into_bytes();
    let hashes_bytes = canonical_json(&serde_json::to_value(&digest_map)?).into_bytes();

    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.as_ref())?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);
    for (name, bytes) in &files {
        zip.start_file(name, options)?;
        zip.write_all(bytes)?;
    }
    for (name, bytes) in [
        ("hashes.json", hashes_bytes.as_slice()),
        ("manifest.json", manifest_bytes.as_slice()),
    ] {
        zip.start_file(name, options)?;
        zip.write_all(bytes)?;
    }
    zip.finish()?;
    Ok(manifest)
}

fn enforce_create_limits(files: &BTreeMap<String, Vec<u8>>, limits: &BundleLimits) -> Result<()> {
    if files.len() + 2 > limits.max_entries {
        return Err(EvidenceError::Limit("entry count".into()));
    }
    let mut total = 0u64;
    for (name, bytes) in files {
        let len = bytes.len() as u64;
        if len > limits.max_file_bytes {
            return Err(EvidenceError::Limit(format!("file {name}")));
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| EvidenceError::Limit("total overflow".into()))?;
    }
    if total > limits.max_total_uncompressed_bytes {
        return Err(EvidenceError::Limit("total bytes".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleVerification {
    pub valid: bool,
    pub session_id: String,
    pub verified_files: usize,
    pub event_count: usize,
    pub final_event_hash: String,
}

pub fn verify_proofdrift_bundle(
    path: impl AsRef<Path>,
    limits: &BundleLimits,
) -> Result<BundleVerification> {
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;
    if zip.len() > limits.max_entries {
        return Err(EvidenceError::Limit("entry count".into()));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        validate_archive_name(&name)?;
        if !seen.insert(name.clone()) {
            return Err(EvidenceError::Invalid(format!(
                "duplicate archive entry {name}"
            )));
        }
        let declared = entry.size();
        if declared > limits.max_file_bytes {
            return Err(EvidenceError::Limit(format!("file {name}")));
        }
        let compressed = entry.compressed_size();
        if declared > 1024 * 1024
            && compressed > 0
            && declared / compressed.max(1) > limits.max_compression_ratio
        {
            return Err(EvidenceError::Limit(format!("compression ratio {name}")));
        }
        total = total
            .checked_add(declared)
            .ok_or_else(|| EvidenceError::Limit("total overflow".into()))?;
        if total > limits.max_total_uncompressed_bytes {
            return Err(EvidenceError::Limit("total bytes".into()));
        }
        let mut bytes = Vec::with_capacity(std::cmp::min(declared, limits.max_file_bytes) as usize);
        entry
            .by_ref()
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != declared {
            return Err(EvidenceError::Invalid(format!(
                "entry size mismatch {name}"
            )));
        }
        contents.insert(name, bytes);
    }
    let manifest_bytes = contents
        .get("manifest.json")
        .ok_or_else(|| EvidenceError::Invalid("manifest.json missing".into()))?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)?;
    if manifest.bundle_format != "proofdrift/1" || manifest.schema_version != SCHEMA_VERSION {
        return Err(EvidenceError::Invalid("unsupported bundle version".into()));
    }
    let hashes: BTreeMap<String, FileDigest> = serde_json::from_slice(
        contents
            .get("hashes.json")
            .ok_or_else(|| EvidenceError::Invalid("hashes.json missing".into()))?,
    )?;
    if hashes != manifest.files {
        return Err(EvidenceError::Invalid(
            "hashes.json differs from manifest".into(),
        ));
    }
    for (name, expected) in &manifest.files {
        let bytes = contents
            .get(name)
            .ok_or_else(|| EvidenceError::Invalid(format!("covered file missing {name}")))?;
        if bytes.len() as u64 != expected.size || sha256_hex(bytes) != expected.sha256 {
            return Err(EvidenceError::Invalid(format!("digest mismatch {name}")));
        }
    }
    for name in contents.keys() {
        if name != "manifest.json" && name != "hashes.json" && !manifest.files.contains_key(name) {
            return Err(EvidenceError::Invalid(format!("uncovered file {name}")));
        }
    }
    let events_bytes = contents
        .get("events.jsonl")
        .ok_or_else(|| EvidenceError::Invalid("events.jsonl missing".into()))?;
    let mut events = Vec::new();
    for (idx, line) in events_bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .enumerate()
    {
        let event: StoredEvent = serde_json::from_slice(line)
            .map_err(|e| EvidenceError::Invalid(format!("events.jsonl line {}: {}", idx + 1, e)))?;
        events.push(event);
    }
    let chain = verify_chain(&events)?;
    if chain.final_hash != manifest.event_chain_final_hash {
        return Err(EvidenceError::Invalid(
            "manifest final event hash mismatch".into(),
        ));
    }
    Ok(BundleVerification {
        valid: true,
        session_id: manifest.session_id,
        verified_files: manifest.files.len(),
        event_count: chain.event_count,
        final_event_hash: chain.final_hash,
    })
}

/// Extraction helper for future CLI use. Verification happens first and every
/// output path is revalidated before writing. Existing files are never replaced.
pub fn verify_and_extract_proofdrift_bundle(
    path: impl AsRef<Path>,
    dest: impl AsRef<Path>,
    limits: &BundleLimits,
) -> Result<BundleVerification> {
    let verification = verify_proofdrift_bundle(&path, limits)?;
    fs::create_dir_all(dest.as_ref())?;
    let root = fs::canonicalize(dest.as_ref())?;
    let file = File::open(path)?;
    let mut zip = ZipArchive::new(file)?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        validate_archive_name(&name)?;
        let relative = Path::new(&name);
        let target = root.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
            let canon_parent = fs::canonicalize(parent)?;
            if !canon_parent.starts_with(&root) {
                return Err(EvidenceError::Invalid(format!("extraction escape {name}")));
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut out = options.open(&target)?;
        std::io::copy(
            &mut entry.by_ref().take(limits.max_file_bytes + 1),
            &mut out,
        )?;
    }
    Ok(verification)
}

fn validate_archive_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('\\') || name.starts_with('/') || name.contains('\0') {
        return Err(EvidenceError::Invalid(format!(
            "unsafe archive path {name:?}"
        )));
    }
    let p = Path::new(name);
    for component in p.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(EvidenceError::Invalid(format!(
                "unsafe archive path {name:?}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OtelLogRecord {
    pub event_name: String,
    pub timestamp: String,
    pub attributes: BTreeMap<String, Value>,
}

/// Deterministic OpenTelemetry-compatible projection. It intentionally emits a
/// neutral record model so the integration crate can choose an OTel SDK/exporter.
pub fn to_otel_log(event: &StoredEvent) -> OtelLogRecord {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "proofdrift.session.id".into(),
        Value::String(event.event.session_id.clone()),
    );
    attributes.insert(
        "proofdrift.event.id".into(),
        Value::String(event.event.event_id.clone()),
    );
    attributes.insert(
        "proofdrift.event.sequence".into(),
        Value::from(event.sequence),
    );
    attributes.insert(
        "proofdrift.action".into(),
        Value::String(event.event.proposed_action.clone()),
    );
    attributes.insert(
        "proofdrift.resource".into(),
        Value::String(event.event.resource.clone()),
    );
    attributes.insert(
        "proofdrift.outcome".into(),
        Value::String(event.event.outcome.clone()),
    );
    attributes.insert(
        "proofdrift.enforcement.level".into(),
        Value::String(event.event.enforcement_level.clone()),
    );
    attributes.insert(
        "proofdrift.event.hash".into(),
        Value::String(event.event_hash.clone()),
    );
    OtelLogRecord {
        event_name: format!("proofdrift.agent.{}", event.event.event_type),
        timestamp: event.event.timestamp_wall.clone(),
        attributes,
    }
}

/// Evidence replay never executes recorded tools. It only replays envelopes to
/// a caller-supplied pure decision evaluator.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReplayItem {
    pub sequence: u64,
    pub event_id: String,
    pub action: String,
    pub resource: String,
    pub recorded_decision_id: Option<String>,
    pub simulated_decision: Value,
}

pub fn replay_evidence<F>(events: &[StoredEvent], mut evaluator: F) -> Result<Vec<ReplayItem>>
where
    F: FnMut(&StoredEvent) -> Value,
{
    verify_chain(events)?;
    Ok(events
        .iter()
        .map(|e| ReplayItem {
            sequence: e.sequence,
            event_id: e.event.event_id.clone(),
            action: e.event.proposed_action.clone(),
            resource: e.event.resource.clone(),
            recorded_decision_id: e.event.decision_id.clone(),
            simulated_decision: evaluator(e),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn input(id: &str, secret: bool) -> AgentEventInput {
        AgentEventInput {
            event_id: id.into(),
            session_id: "s1".into(),
            timestamp_wall: "2026-09-10T04:00:00Z".into(),
            timestamp_monotonic_ns: Some(1),
            actor: "agent".into(),
            adapter_id: "mock-runtime".into(),
            adapter_version: Some("1".into()),
            event_type: "tool_call".into(),
            proposed_action: "network.connect".into(),
            resource: "https://example.test".into(),
            normalized_args: if secret {
                serde_json::json!({"authorization":"Bearer SHOULD_NEVER_PERSIST_123456789", "nested":{"message":"token SYNTH_GITHUB_TOKEN_abcdefghijklmnopqrstuvwxyz0123456789"}})
            } else {
                serde_json::json!({"method":"GET"})
            },
            decision_id: Some("d1".into()),
            outcome: "allowed".into(),
            enforcement_level: "L1".into(),
            evidence_refs: vec!["policy:d1".into()],
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn append_redacts_and_chain_verifies() {
        let mut store = EvidenceStore::open_memory(Redactor::new(vec![
            "SHOULD_NEVER_PERSIST_123456789".into(),
            "SYNTH_GITHUB_TOKEN_abcdefghijklmnopqrstuvwxyz0123456789".into(),
        ]))
        .unwrap();
        let a = store.append(input("e1", true)).unwrap();
        let b = store.append(input("e2", false)).unwrap();
        assert_eq!(a.sequence, 1);
        assert_eq!(b.sequence, 2);
        assert_eq!(b.prev_event_hash, a.event_hash);
        let serialized = serde_json::to_string(&store.load_session("s1").unwrap()).unwrap();
        assert!(!serialized.contains("SHOULD_NEVER_PERSIST_123456789"));
        assert!(!serialized.contains("SYNTH_GITHUB_TOKEN_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(serialized.contains("[REDACTED]"));
        assert!(store.verify_session("s1").unwrap().valid);
    }

    #[test]
    fn reorder_delete_and_mutation_fail_chain() {
        let mut store = EvidenceStore::open_memory(Redactor::default()).unwrap();
        for id in ["e1", "e2", "e3"] {
            store.append(input(id, false)).unwrap();
        }
        let events = store.load_session("s1").unwrap();
        let mut reordered = events.clone();
        reordered.swap(0, 1);
        assert!(verify_chain(&reordered).is_err());
        let deleted = vec![events[0].clone(), events[2].clone()];
        assert!(verify_chain(&deleted).is_err());
        let mut mutated = events.clone();
        mutated[1].event.resource = "changed".into();
        assert!(verify_chain(&mutated).is_err());
    }

    #[test]
    fn duplicate_event_rejected_by_store() {
        let mut store = EvidenceStore::open_memory(Redactor::default()).unwrap();
        store.append(input("e1", false)).unwrap();
        assert!(store.append(input("e1", false)).is_err());
    }

    #[test]
    fn bounded_batch_rejects_oversize() {
        let mut store = EvidenceStore::open_memory(Redactor::default()).unwrap();
        assert!(store
            .append_batch(vec![input("e1", false), input("e2", false)], 1)
            .is_err());
    }

    #[test]
    fn batch_is_atomic_and_hash_chained() {
        let mut store = EvidenceStore::open_memory(Redactor::default()).unwrap();
        let events = store
            .append_batch(
                vec![input("e1", false), input("e2", false), input("e3", false)],
                8,
            )
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].prev_event_hash, events[0].event_hash);
        assert_eq!(events[2].prev_event_hash, events[1].event_hash);
        assert!(store.verify_session("s1").unwrap().valid);
    }

    #[test]
    fn batch_rolls_back_all_rows_on_insert_failure() {
        let mut store = EvidenceStore::open_memory(Redactor::default()).unwrap();
        let result = store.append_batch(vec![input("dup", false), input("dup", false)], 8);
        assert!(result.is_err());
        assert!(store.load_session("s1").unwrap().is_empty());
    }

    #[test]
    fn sqlite_reopen_recovers_committed_chain() {
        let d = tempdir().unwrap();
        let db = d.path().join("evidence.db");
        {
            let mut s = EvidenceStore::open(&db, Redactor::default()).unwrap();
            s.append(input("e1", false)).unwrap();
            s.checkpoint().unwrap();
        }
        let mut reopened = EvidenceStore::open(&db, Redactor::default()).unwrap();
        assert_eq!(reopened.load_session("s1").unwrap().len(), 1);
        let second = reopened.append(input("e2", false)).unwrap();
        assert_eq!(second.sequence, 2);
    }

    #[test]
    fn proofdrift_bundle_roundtrip_and_byte_tamper_fails() {
        let d = tempdir().unwrap();
        let path = d.path().join("ok.proofdrift");
        let mut s = EvidenceStore::open_memory(Redactor::default()).unwrap();
        s.append(input("e1", false)).unwrap();
        let mut assets = BTreeMap::new();
        assets.insert("patch/impact.json".into(), br#"{"risk":"db"}"#.to_vec());
        create_proofdrift_bundle(
            &path,
            &BundleInput {
                session_id: "s1".into(),
                events: s.load_session("s1").unwrap(),
                assets,
            },
            &BundleLimits::default(),
        )
        .unwrap();
        assert!(
            verify_proofdrift_bundle(&path, &BundleLimits::default())
                .unwrap()
                .valid
        );
        // Rebuild a syntactically valid zip while mutating a covered byte; this
        // models post-run tampering without relying on corrupting ZIP metadata.
        let bad = d.path().join("bad.proofdrift");
        let file = File::open(&path).unwrap();
        let mut src = ZipArchive::new(file).unwrap();
        let out = File::create(&bad).unwrap();
        let mut zw = ZipWriter::new(out);
        let opt = FileOptions::default().compression_method(CompressionMethod::Stored);
        for i in 0..src.len() {
            let mut e = src.by_index(i).unwrap();
            let name = e.name().to_string();
            let mut bytes = Vec::new();
            e.read_to_end(&mut bytes).unwrap();
            if name == "patch/impact.json" {
                bytes[0] ^= 1;
            }
            zw.start_file(name, opt).unwrap();
            zw.write_all(&bytes).unwrap();
        }
        zw.finish().unwrap();
        assert!(verify_proofdrift_bundle(&bad, &BundleLimits::default()).is_err());
    }

    #[test]
    fn unsafe_and_reserved_paths_rejected() {
        let d = tempdir().unwrap();
        let mut s = EvidenceStore::open_memory(Redactor::default()).unwrap();
        s.append(input("e1", false)).unwrap();
        for bad in ["../escape", "/absolute", "a\\b"] {
            let mut assets = BTreeMap::new();
            assets.insert(bad.into(), vec![1]);
            let p = d
                .path()
                .join(format!("{}.proofdrift", sha256_hex(bad.as_bytes())));
            assert!(create_proofdrift_bundle(
                p,
                &BundleInput {
                    session_id: "s1".into(),
                    events: s.load_session("s1").unwrap(),
                    assets
                },
                &BundleLimits::default()
            )
            .is_err());
        }
    }

    #[test]
    fn create_limits_enforced() {
        let d = tempdir().unwrap();
        let mut s = EvidenceStore::open_memory(Redactor::default()).unwrap();
        s.append(input("e1", false)).unwrap();
        let mut assets = BTreeMap::new();
        assets.insert("big.bin".into(), vec![0; 16]);
        let limits = BundleLimits {
            max_entries: 10,
            max_file_bytes: 8,
            max_total_uncompressed_bytes: 100,
            max_compression_ratio: 10,
        };
        assert!(create_proofdrift_bundle(
            d.path().join("x.proofdrift"),
            &BundleInput {
                session_id: "s1".into(),
                events: s.load_session("s1").unwrap(),
                assets
            },
            &limits
        )
        .is_err());
    }

    #[test]
    fn corrupted_sqlite_fails_closed() {
        let d = tempdir().unwrap();
        let db = d.path().join("corrupt.db");
        fs::write(&db, b"not a sqlite database").unwrap();
        assert!(EvidenceStore::open(&db, Redactor::default()).is_err());
    }

    #[test]
    fn verify_rejects_compression_bomb_ratio() {
        let d = tempdir().unwrap();
        let path = d.path().join("bomb.proofdrift");
        let out = File::create(&path).unwrap();
        let mut zw = ZipWriter::new(out);
        let opt = FileOptions::default().compression_method(CompressionMethod::Deflated);
        zw.start_file("bomb.bin", opt).unwrap();
        zw.write_all(&vec![0u8; 2 * 1024 * 1024]).unwrap();
        zw.finish().unwrap();
        let limits = BundleLimits {
            max_entries: 10,
            max_file_bytes: 4 * 1024 * 1024,
            max_total_uncompressed_bytes: 4 * 1024 * 1024,
            max_compression_ratio: 2,
        };
        assert!(matches!(
            verify_proofdrift_bundle(&path, &limits),
            Err(EvidenceError::Limit(_))
        ));
    }

    #[test]
    fn verified_extraction_never_overwrites_existing_file() {
        let d = tempdir().unwrap();
        let path = d.path().join("safe.proofdrift");
        let mut s = EvidenceStore::open_memory(Redactor::default()).unwrap();
        s.append(input("e1", false)).unwrap();
        create_proofdrift_bundle(
            &path,
            &BundleInput {
                session_id: "s1".into(),
                events: s.load_session("s1").unwrap(),
                assets: BTreeMap::new(),
            },
            &BundleLimits::default(),
        )
        .unwrap();
        let dest = d.path().join("extract");
        fs::create_dir_all(&dest).unwrap();
        let existing = dest.join("events.jsonl");
        fs::write(&existing, b"sentinel").unwrap();
        assert!(
            verify_and_extract_proofdrift_bundle(&path, &dest, &BundleLimits::default()).is_err()
        );
        assert_eq!(fs::read(existing).unwrap(), b"sentinel");
    }

    #[test]
    fn replay_is_pure_and_ordered() {
        let mut s = EvidenceStore::open_memory(Redactor::default()).unwrap();
        s.append(input("e1", false)).unwrap();
        s.append(input("e2", false)).unwrap();
        let mut calls = 0;
        let out = replay_evidence(&s.load_session("s1").unwrap(), |_| {
            calls += 1;
            serde_json::json!({"decision":"DENY"})
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(out[0].sequence, 1);
        assert_eq!(out[1].sequence, 2);
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let a = serde_json::json!({"z":1,"a":{"y":2,"b":3}});
        assert_eq!(canonical_json(&a), r#"{"a":{"b":3,"y":2},"z":1}"#);
    }
}
