use serde_json::Value;

/// Errors returned by narrow, explicit contract migrations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MigrationError {
    #[error("contract value must be a JSON object")]
    NotAnObject,
    #[error("missing schema_version")]
    MissingVersion,
    #[error("unsupported schema_version: {0}")]
    UnsupportedVersion(String),
    #[error("legacy artifact is missing required field: {0}")]
    MissingRequired(&'static str),
}

/// Migrate the documented ArtifactIdentity v0.9 compatibility sample to v1.
///
/// This function is intentionally narrow rather than silently guessing arbitrary
/// historical shapes. v0.9 used `type` and `sha256`; v1 uses `artifact_type` and
/// `content_digest`. Additive unknown fields are preserved.
pub fn migrate_artifact_identity_to_v1(mut value: Value) -> Result<Value, MigrationError> {
    let object = value.as_object_mut().ok_or(MigrationError::NotAnObject)?;
    let version = object
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or(MigrationError::MissingVersion)?
        .to_owned();

    if version.starts_with("1.") {
        return Ok(value);
    }
    if version != "0.9.0" {
        return Err(MigrationError::UnsupportedVersion(version));
    }

    if !object.contains_key("artifact_type") {
        let legacy_type = object
            .remove("type")
            .ok_or(MigrationError::MissingRequired("type"))?;
        object.insert("artifact_type".to_owned(), legacy_type);
    }
    if !object.contains_key("content_digest") {
        if let Some(legacy_hash) = object.remove("sha256") {
            let normalized = legacy_hash.as_str().map_or(legacy_hash.clone(), |text| {
                if text.starts_with("sha256:") {
                    legacy_hash.clone()
                } else {
                    Value::String(format!("sha256:{text}"))
                }
            });
            object.insert("content_digest".to_owned(), normalized);
        }
    }
    object.insert(
        "schema_version".to_owned(),
        Value::String("1.0.0".to_owned()),
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArtifactIdentity;
    use serde_json::json;

    #[test]
    fn migrates_documented_v0_9_artifact_without_dropping_unknown_fields() {
        let legacy = json!({
            "schema_version":"0.9.0",
            "artifact_id":"skill:legacy",
            "type":"skill",
            "name":"legacy",
            "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "provenance_status":"declared",
            "future_vendor_field":{"preserve":true}
        });
        let migrated = migrate_artifact_identity_to_v1(legacy).unwrap();
        assert_eq!(migrated["schema_version"], "1.0.0");
        assert_eq!(migrated["artifact_type"], "skill");
        assert_eq!(
            migrated["content_digest"],
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let typed: ArtifactIdentity = serde_json::from_value(migrated).unwrap();
        assert!(typed.extensions.contains_key("future_vendor_field"));
    }

    #[test]
    fn refuses_unknown_major_history_instead_of_guessing() {
        let err = migrate_artifact_identity_to_v1(json!({"schema_version":"0.8.0"})).unwrap_err();
        assert_eq!(err, MigrationError::UnsupportedVersion("0.8.0".to_owned()));
    }
}
