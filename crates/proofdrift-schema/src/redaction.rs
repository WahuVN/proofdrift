use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// Classification of intentionally removed sensitive data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RedactionKind {
    Secret,
    Credential,
    EnvironmentValue,
    LocalPath,
    ToolPayload,
    UserContent,
    Other,
}

/// Persistable evidence that a value was redacted, without retaining the plaintext.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactedValue {
    pub kind: RedactionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub const MIN_FINGERPRINT_SALT_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RedactionError {
    #[error("secret fingerprint salt is too short: {actual} bytes < {minimum}")]
    SaltTooShort { actual: usize, minimum: usize },
}

impl RedactedValue {
    /// Create redaction evidence without a reusable fingerprint.
    ///
    /// This is the safe default for persisted/shared evidence because an unsalted
    /// digest of a low-entropy secret can become an offline guessing oracle.
    pub fn without_fingerprint(kind: RedactionKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            fingerprint_sha256: None,
            reason: Some(reason.into()),
        }
    }

    /// Create a domain-separated, caller-salted fingerprint when correlation is
    /// explicitly required. Prefer a random per-session or per-bundle salt.
    pub fn from_secret_with_salt(
        secret: &[u8],
        salt: &[u8],
        kind: RedactionKind,
        reason: impl Into<String>,
    ) -> Result<Self, RedactionError> {
        if salt.len() < MIN_FINGERPRINT_SALT_BYTES {
            return Err(RedactionError::SaltTooShort {
                actual: salt.len(),
                minimum: MIN_FINGERPRINT_SALT_BYTES,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(b"proofdrift-secret-fingerprint-v1\0");
        hasher.update(salt);
        hasher.update(b"\0");
        hasher.update(secret);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(Self {
            kind,
            fingerprint_sha256: Some(hex),
            reason: Some(reason.into()),
        })
    }
}

/// In-memory secret wrapper whose `Debug`, `Display`, and serialization never reveal plaintext.
///
/// The explicit `expose_secret` method exists for enforcement adapters that must use a
/// credential. The evidence/schema layers should persist `RedactedValue` instead.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Build safe persisted redaction evidence without a secret fingerprint.
    pub fn redaction(&self, reason: impl Into<String>) -> RedactedValue {
        RedactedValue::without_fingerprint(RedactionKind::Secret, reason)
    }

    /// Build redaction evidence with explicit, salted correlation fingerprinting.
    pub fn redaction_with_salt(
        &self,
        salt: &[u8],
        reason: impl Into<String>,
    ) -> Result<RedactedValue, RedactionError> {
        RedactedValue::from_secret_with_salt(self.0.as_bytes(), salt, RedactionKind::Secret, reason)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_never_appears_in_debug_display_or_serialization() {
        let secret = SecretString::new("synthetic-secret-123");
        for rendered in [
            format!("{secret:?}"),
            format!("{secret}"),
            serde_json::to_string(&secret).unwrap(),
        ] {
            assert!(!rendered.contains("synthetic-secret-123"));
        }
    }

    #[test]
    fn default_redaction_does_not_create_offline_guessing_oracle() {
        let secret = SecretString::new("short-secret");
        let redacted = secret.redaction("persist safely");
        assert!(redacted.fingerprint_sha256.is_none());
    }

    #[test]
    fn salted_secret_fingerprint_is_domain_separated_and_salt_scoped() {
        let secret = SecretString::new("synthetic-secret-123");
        let a = secret
            .redaction_with_salt(b"session-a-1234567", "correlate")
            .unwrap();
        let a_again = secret
            .redaction_with_salt(b"session-a-1234567", "correlate")
            .unwrap();
        let b = secret
            .redaction_with_salt(b"session-b-1234567", "correlate")
            .unwrap();
        assert_eq!(a.fingerprint_sha256, a_again.fingerprint_sha256);
        assert_ne!(a.fingerprint_sha256, b.fingerprint_sha256);
        assert_eq!(
            secret.redaction_with_salt(b"too-short", "bad"),
            Err(RedactionError::SaltTooShort {
                actual: 9,
                minimum: MIN_FINGERPRINT_SALT_BYTES,
            })
        );
    }
}
