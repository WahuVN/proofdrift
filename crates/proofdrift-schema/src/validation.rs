use crate::{BundleEntry, BundleManifest, EvidenceKind, EvidenceValue};
use std::collections::BTreeSet;

/// Conservative default archive limits used by contract consumers unless they
/// explicitly configure tighter values.
pub const DEFAULT_MAX_BUNDLE_ENTRIES: usize = 10_000;
pub const DEFAULT_MAX_BUNDLE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_BUNDLE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, thiserror::Error, PartialEq)]
pub enum EvidenceValidationError {
    #[error("confidence is only valid for derived evidence")]
    ConfidenceOnlyForDerived,
    #[error("confidence must be finite and between 0 and 1 inclusive: {0}")]
    InvalidConfidence(f64),
}

impl<T> EvidenceValue<T> {
    /// Validate cross-field evidence semantics that are not represented by Rust's
    /// field types alone.
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if let Some(confidence) = self.confidence {
            if self.evidence_kind != EvidenceKind::Derived {
                return Err(EvidenceValidationError::ConfidenceOnlyForDerived);
            }
            if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
                return Err(EvidenceValidationError::InvalidConfidence(confidence));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleValidationError {
    #[error("bundle contains too many entries: {actual} > {limit}")]
    TooManyEntries { actual: usize, limit: usize },
    #[error("bundle entry is too large: {path} is {actual} bytes > {limit}")]
    EntryTooLarge {
        path: String,
        actual: u64,
        limit: u64,
    },
    #[error("bundle declared size exceeds limit: {actual} bytes > {limit}")]
    TotalTooLarge { actual: u64, limit: u64 },
    #[error("bundle declared size overflowed u64")]
    TotalSizeOverflow,
    #[error("unsafe or non-canonical bundle path: {0}")]
    UnsafePath(String),
    #[error("duplicate bundle path: {0}")]
    DuplicatePath(String),
}

impl BundleEntry {
    /// Return true only for normalized relative POSIX archive member paths.
    ///
    /// Backslashes and colons are rejected intentionally so the same manifest has
    /// one interpretation on Windows and Unix and cannot encode drive-relative or
    /// NTFS alternate-data-stream paths.
    pub fn has_safe_portable_path(&self) -> bool {
        let path = self.path.as_str();
        if path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path.contains(':')
            || path.ends_with('/')
        {
            return false;
        }
        path.split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    }
}

impl BundleManifest {
    pub fn validate_default_limits(&self) -> Result<(), BundleValidationError> {
        self.validate_limits(
            DEFAULT_MAX_BUNDLE_ENTRIES,
            DEFAULT_MAX_BUNDLE_ENTRY_BYTES,
            DEFAULT_MAX_BUNDLE_TOTAL_BYTES,
        )
    }

    pub fn validate_limits(
        &self,
        max_entries: usize,
        max_entry_bytes: u64,
        max_total_bytes: u64,
    ) -> Result<(), BundleValidationError> {
        if self.entries.len() > max_entries {
            return Err(BundleValidationError::TooManyEntries {
                actual: self.entries.len(),
                limit: max_entries,
            });
        }

        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for entry in &self.entries {
            if !entry.has_safe_portable_path() {
                return Err(BundleValidationError::UnsafePath(entry.path.clone()));
            }
            if !seen.insert(entry.path.as_str()) {
                return Err(BundleValidationError::DuplicatePath(entry.path.clone()));
            }
            if entry.size_bytes > max_entry_bytes {
                return Err(BundleValidationError::EntryTooLarge {
                    path: entry.path.clone(),
                    actual: entry.size_bytes,
                    limit: max_entry_bytes,
                });
            }
            total = total
                .checked_add(entry.size_bytes)
                .ok_or(BundleValidationError::TotalSizeOverflow)?;
            if total > max_total_bytes {
                return Err(BundleValidationError::TotalTooLarge {
                    actual: total,
                    limit: max_total_bytes,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BundleManifest, SCHEMA_VERSION};

    fn entry(path: &str, size_bytes: u64) -> BundleEntry {
        BundleEntry {
            path: path.to_owned(),
            sha256: "a".repeat(64),
            size_bytes,
            media_type: None,
        }
    }

    fn manifest(entries: Vec<BundleEntry>) -> BundleManifest {
        BundleManifest {
            schema_version: SCHEMA_VERSION.to_owned(),
            bundle_version: "1".to_owned(),
            session_id: "test".to_owned(),
            created_at: "2026-09-10T00:00:00Z".to_owned(),
            canonicalization: "proofdrift-json-v1".to_owned(),
            entries,
            attestation_refs: vec![],
            extensions: Default::default(),
        }
    }

    #[test]
    fn evidence_confidence_is_derived_only_and_bounded() {
        let mut value = EvidenceValue {
            schema_version: SCHEMA_VERSION.to_owned(),
            value: true,
            evidence_kind: EvidenceKind::Derived,
            confidence: Some(0.9),
            source_refs: vec![],
            timestamp: None,
            extensions: Default::default(),
        };
        assert_eq!(value.validate(), Ok(()));
        value.evidence_kind = EvidenceKind::Observed;
        assert_eq!(
            value.validate(),
            Err(EvidenceValidationError::ConfidenceOnlyForDerived)
        );
        value.evidence_kind = EvidenceKind::Derived;
        value.confidence = Some(1.01);
        assert!(matches!(
            value.validate(),
            Err(EvidenceValidationError::InvalidConfidence(_))
        ));
    }

    #[test]
    fn bundle_rejects_ambiguous_paths_duplicates_and_size_abuse() {
        for unsafe_path in [
            "../secret",
            "a/../secret",
            "a/./b",
            "/absolute",
            "C:drive-relative",
            "dir\\windows",
            "dir//empty",
            "stream:ads",
            "trailing/",
        ] {
            assert!(matches!(
                manifest(vec![entry(unsafe_path, 1)]).validate_default_limits(),
                Err(BundleValidationError::UnsafePath(_))
            ));
        }

        assert!(matches!(
            manifest(vec![entry("events.jsonl", 1), entry("events.jsonl", 2)])
                .validate_default_limits(),
            Err(BundleValidationError::DuplicatePath(_))
        ));
        assert!(matches!(
            manifest(vec![entry("huge.bin", DEFAULT_MAX_BUNDLE_ENTRY_BYTES + 1)])
                .validate_default_limits(),
            Err(BundleValidationError::EntryTooLarge { .. })
        ));
    }

    #[test]
    fn bundle_count_total_and_overflow_limits_are_enforced() {
        let two = manifest(vec![entry("a", 60), entry("b", 60)]);
        assert!(matches!(
            two.validate_limits(1, 100, 1_000),
            Err(BundleValidationError::TooManyEntries { .. })
        ));
        assert!(matches!(
            two.validate_limits(10, 100, 100),
            Err(BundleValidationError::TotalTooLarge { .. })
        ));

        let overflow = manifest(vec![entry("a", u64::MAX), entry("b", 1)]);
        assert_eq!(
            overflow.validate_limits(10, u64::MAX, u64::MAX),
            Err(BundleValidationError::TotalSizeOverflow)
        );
    }

    #[test]
    fn canonical_nested_relative_path_is_accepted() {
        let manifest = manifest(vec![entry("tests/results.json", 42)]);
        assert_eq!(manifest.validate_default_limits(), Ok(()));
    }
}
