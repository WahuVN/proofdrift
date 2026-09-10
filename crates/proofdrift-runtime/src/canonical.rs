use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Serialize JSON with recursively sorted object keys so fingerprints are deterministic.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&canonicalize(value))
}

pub fn canonical_sha256(value: &Value) -> Result<String, serde_json::Error> {
    let bytes = canonical_json_bytes(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

/// Structural redaction for obvious secret-bearing keys.
///
/// This is intentionally a baseline defense, not the full secret fingerprint engine.
/// Values under unknown keys are not claimed to be secret-safe.
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, value) in map {
                if is_sensitive_key(key) {
                    out.insert(key.clone(), Value::String("[REDACTED]".to_owned()));
                } else {
                    out.insert(key.clone(), redact_json(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    [
        "authorization",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "password",
        "passwd",
        "secret",
        "cookie",
        "setcookie",
        "privatekey",
        "clientsecret",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_digest_ignores_object_key_order() {
        let a = json!({"z": 1, "a": {"d": 4, "b": 2}});
        let b = json!({"a": {"b": 2, "d": 4}, "z": 1});
        assert_eq!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
    }

    #[test]
    fn structural_redaction_is_recursive() {
        let value = json!({
            "headers": {"Authorization": "Bearer synthetic-secret"},
            "nested": [{"api_key": "synthetic-secret"}],
            "safe": "visible"
        });
        let redacted = redact_json(&value);
        let text = serde_json::to_string(&redacted).unwrap();
        assert!(!text.contains("synthetic-secret"));
        assert!(text.contains("visible"));
    }
}
