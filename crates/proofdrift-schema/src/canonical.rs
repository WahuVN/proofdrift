use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Canonicalization/hashing failures.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("failed to serialize value before canonicalization: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Serialize JSON deterministically using the ProofDrift Canonical JSON Profile v1.
///
/// Profile rules:
/// - UTF-8 JSON, no insignificant whitespace;
/// - object keys sorted lexicographically by their Rust/UTF-8 string order;
/// - array order retained;
/// - strings encoded by `serde_json` escaping;
/// - JSON numbers emitted in `serde_json::Number` textual form.
///
/// The profile is intentionally narrower than claiming full RFC 8785/JCS compliance.
/// Producers that require cross-implementation signature interoperability should map
/// to the attestation standard selected by the attestation layer.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(v) => out.extend_from_slice(if *v { b"true" } else { b"false" }),
        Value::Number(v) => out.extend_from_slice(v.to_string().as_bytes()),
        Value::String(v) => {
            // Serializing valid Rust UTF-8 as JSON string cannot fail.
            out.extend_from_slice(
                serde_json::to_string(v)
                    .expect("string serialization")
                    .as_bytes(),
            );
        }
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(*key)
                        .expect("object key serialization")
                        .as_bytes(),
                );
                out.push(b':');
                write_value(&map[*key], out);
            }
            out.push(b'}');
        }
    }
}

/// Compute SHA-256 over the canonical JSON representation of any serializable value.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let value = serde_json::to_value(value)?;
    Ok(sha256_hex(&canonical_json_bytes(&value)))
}

/// Compute SHA-256 after omitting named fields from the top-level JSON object.
///
/// This is intended for self-hashed objects such as `AgentEvent`, where the
/// top-level `event_hash` must not be included in its own digest. Exclusion is
/// deliberately **not recursive**: a user-controlled nested field named
/// `event_hash` remains integrity-protected.
pub fn canonical_sha256_excluding<T: Serialize>(
    value: &T,
    excluded_fields: &[&str],
) -> Result<String, CanonicalError> {
    let mut value = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut value {
        let excluded: BTreeSet<&str> = excluded_fields.iter().copied().collect();
        map.retain(|key, _| !excluded.contains(key.as_str()));
    }
    Ok(sha256_hex(&canonical_json_bytes(&value)))
}

/// Build a stable opaque identifier/fingerprint from a namespace and normalized value.
pub fn stable_fingerprint<T: Serialize>(
    namespace: &str,
    value: &T,
) -> Result<String, CanonicalError> {
    let canonical = canonical_json_bytes(&serde_json::to_value(value)?);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    let digest = hasher.finalize();
    Ok(to_hex(&digest))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    to_hex(&digest)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let a = json!({"z": 1, "a": {"y": 2, "b": 3}});
        let b = json!({"a": {"b": 3, "y": 2}, "z": 1});
        assert_eq!(canonical_json_bytes(&a), canonical_json_bytes(&b));
        assert_eq!(canonical_json_bytes(&a), br#"{"a":{"b":3,"y":2},"z":1}"#);
    }

    #[test]
    fn excluded_top_level_self_hash_does_not_change_digest() {
        let a = json!({"event_id":"e1","event_hash":"aaa","prev_event_hash":"p"});
        let b = json!({"event_id":"e1","event_hash":"bbb","prev_event_hash":"p"});
        assert_eq!(
            canonical_sha256_excluding(&a, &["event_hash"]).unwrap(),
            canonical_sha256_excluding(&b, &["event_hash"]).unwrap()
        );
    }

    #[test]
    fn nested_field_with_same_name_remains_hash_bound() {
        let a = json!({"event_id":"e1","event_hash":"self","args":{"event_hash":"payload-a"}});
        let b = json!({"event_id":"e1","event_hash":"self","args":{"event_hash":"payload-b"}});
        assert_ne!(
            canonical_sha256_excluding(&a, &["event_hash"]).unwrap(),
            canonical_sha256_excluding(&b, &["event_hash"]).unwrap()
        );
    }

    #[test]
    fn previous_hash_is_bound_when_not_excluded() {
        let a = json!({"event_id":"e1","event_hash":"aaa","prev_event_hash":"p1"});
        let b = json!({"event_id":"e1","event_hash":"aaa","prev_event_hash":"p2"});
        assert_ne!(
            canonical_sha256_excluding(&a, &["event_hash"]).unwrap(),
            canonical_sha256_excluding(&b, &["event_hash"]).unwrap()
        );
    }
}
