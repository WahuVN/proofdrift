pub mod apm;
pub mod cargo_lock;
pub mod git;
pub mod github;
pub mod huggingface;
pub mod mcp;
pub mod npm_lock;
pub mod pnpm_lock;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(crate) const MAX_RECORDED_JSON_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_LOCKFILE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_RECORDED_ITEMS: usize = 10_000;

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Removes URL user-info before provenance metadata is persisted. This is deliberately
/// conservative and keeps non-URL/local identifiers unchanged.
pub(crate) fn sanitize_source_uri(input: &str) -> String {
    let trimmed = input.trim();
    let Some(scheme_pos) = trimmed.find("://") else {
        return trimmed.to_string();
    };
    let authority_start = scheme_pos + 3;
    let remainder = &trimmed[authority_start..];
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if let Some(at) = authority.rfind('@') {
        let host = &authority[at + 1..];
        format!(
            "{}{}{}",
            &trimmed[..authority_start],
            host,
            &remainder[authority_end..]
        )
    } else {
        trimmed.to_string()
    }
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize_json(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Canonicalizes each tool object and sorts the tools by canonical bytes so a registry
/// returning the same set in another order does not create false TOOL_SCHEMA_DRIFT.
pub(crate) fn canonical_tools_json(tools: &[Value]) -> Result<Vec<u8>, serde_json::Error> {
    let mut canonical: Vec<Value> = tools.iter().map(canonicalize_json).collect();
    canonical.sort_by(|a, b| {
        let a_name = a.get("name").and_then(Value::as_str).unwrap_or("");
        let b_name = b.get("name").and_then(Value::as_str).unwrap_or("");
        a_name
            .cmp(b_name)
            .then_with(|| a.to_string().cmp(&b.to_string()))
    });
    serde_json::to_vec(&canonical)
}
