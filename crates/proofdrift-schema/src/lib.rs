#![forbid(unsafe_code)]
//! Versioned shared contracts for the ProofDrift trust/evidence graph.
//!
//! This crate deliberately keeps policy evaluation, storage, and enforcement out of
//! the schema layer. Unknown object fields are preserved in `extensions` so a newer
//! producer can be consumed by an older reader without silently discarding evidence.

mod canonical;
mod migration;
mod model;
mod redaction;
mod validation;

pub use canonical::{
    canonical_json_bytes, canonical_sha256, canonical_sha256_excluding, stable_fingerprint,
    CanonicalError,
};
pub use migration::{migrate_artifact_identity_to_v1, MigrationError};
pub use model::*;
pub use redaction::{
    RedactedValue, RedactionError, RedactionKind, SecretString, MIN_FINGERPRINT_SALT_BYTES,
};
pub use validation::{
    BundleValidationError, EvidenceValidationError, DEFAULT_MAX_BUNDLE_ENTRIES,
    DEFAULT_MAX_BUNDLE_ENTRY_BYTES, DEFAULT_MAX_BUNDLE_TOTAL_BYTES,
};

/// Current contract major/minor version emitted by this crate.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Conservative default JSON input ceiling for convenience parsers.
pub const DEFAULT_MAX_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Deserialize a JSON payload only after applying an explicit byte bound.
pub fn from_json_slice_bounded<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, ParseError> {
    if bytes.len() > max_bytes {
        return Err(ParseError::InputTooLarge {
            actual: bytes.len(),
            limit: max_bytes,
        });
    }
    serde_json::from_slice(bytes).map_err(ParseError::Json)
}

/// Errors returned by bounded parsing helpers.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("JSON input is {actual} bytes, exceeding configured limit {limit}")]
    InputTooLarge { actual: usize, limit: usize },
    #[error("invalid JSON: {0}")]
    Json(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_parser_rejects_oversized_input_before_deserializing() {
        let err = from_json_slice_bounded::<serde_json::Value>(b"{}", 1).unwrap_err();
        assert!(matches!(err, ParseError::InputTooLarge { .. }));
    }

    #[test]
    fn bounded_parser_reports_malformed_json() {
        let err = from_json_slice_bounded::<serde_json::Value>(b"{not-json}", 1024).unwrap_err();
        assert!(matches!(err, ParseError::Json(_)));
    }

    #[test]
    fn schema_version_is_semver_like() {
        let parts: Vec<_> = SCHEMA_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.parse::<u64>().is_ok()));
    }
}
