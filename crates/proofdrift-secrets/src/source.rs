use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::fingerprint::{FingerprintError, SecretFingerprintIndex, is_valid_secret_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretSourceKind {
    DotEnv,
    SshPrivateKey,
    AwsCredentials,
    CloudCredentials,
    GenericSensitiveFile,
}

pub fn classify_secret_path(path: impl AsRef<Path>) -> Option<SecretSourceKind> {
    let path = path.as_ref();
    let normalized = normalized_components(path);
    let file = path.file_name()?.to_string_lossy().to_ascii_lowercase();

    if file == ".env" || file.starts_with(".env.") {
        return Some(SecretSourceKind::DotEnv);
    }
    if matches!(
        file.as_str(),
        "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
    ) {
        return Some(SecretSourceKind::SshPrivateKey);
    }
    if normalized.ends_with("/.aws/credentials") || normalized.ends_with("/.aws/config") {
        return Some(SecretSourceKind::AwsCredentials);
    }
    if normalized.contains("/.config/gcloud/")
        || normalized.ends_with("/application_default_credentials.json")
        || normalized.contains("/.azure/")
    {
        return Some(SecretSourceKind::CloudCredentials);
    }
    if matches!(
        file.as_str(),
        "credentials" | "credentials.json" | "secrets.json"
    ) {
        return Some(SecretSourceKind::GenericSensitiveFile);
    }
    None
}

pub fn validate_secret_id(value: &str) -> bool {
    is_valid_secret_id(value)
}

#[derive(Debug)]
pub enum DotEnvError {
    InvalidUtf8,
    InvalidName {
        line: usize,
    },
    Fingerprint {
        key: String,
        source: FingerprintError,
    },
}

impl fmt::Display for DotEnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("dotenv payload is not valid UTF-8"),
            Self::InvalidName { line } => {
                write!(f, "dotenv contains an invalid variable name on line {line}")
            }
            Self::Fingerprint { key, source } => {
                write!(
                    f,
                    "failed to register dotenv secret for key {key}: {source}"
                )
            }
        }
    }
}

impl std::error::Error for DotEnvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fingerprint { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredDotEnvSecret {
    pub secret_id: String,
    pub source_key: String,
    pub source_label: String,
}

/// Parses a conservative dotenv subset without retaining values. The caller
/// supplies bytes explicitly; this crate never crawls a real home directory by
/// default. Empty values are ignored.
pub fn register_dotenv_bytes(
    index: &mut SecretFingerprintIndex,
    source_label: &str,
    bytes: &[u8],
) -> Result<Vec<RegisteredDotEnvSecret>, DotEnvError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DotEnvError::InvalidUtf8)?;
    let mut registered = Vec::new();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((name, raw_value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !is_env_name(name) {
            return Err(DotEnvError::InvalidName { line: line_number });
        }
        let value = parse_value(raw_value.trim());
        if value.is_empty() {
            continue;
        }
        let secret_id = format!("dotenv.{}.{}", sanitize_id_segment(source_label), name);
        index
            .register_secret(&secret_id, &value)
            .map_err(|source| DotEnvError::Fingerprint {
                key: name.to_owned(),
                source,
            })?;
        registered.push(RegisteredDotEnvSecret {
            secret_id,
            source_key: name.to_owned(),
            source_label: source_label.to_owned(),
        });
    }
    Ok(registered)
}

fn parse_value(value: &str) -> Zeroizing<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        return Zeroizing::new(bytes[1..bytes.len() - 1].to_vec());
    }
    Zeroizing::new(bytes.to_vec())
}

fn is_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn sanitize_id_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len().max(1));
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            out.push(byte as char);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out == "." || out == ".." {
        "source".to_owned()
    } else {
        out
    }
}

fn normalized_components(path: &Path) -> String {
    let as_path = PathBuf::from(path);
    as_path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("/")
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use crate::{FingerprintKey, Representation};

    use super::*;

    #[test]
    fn classifies_common_secret_sources_without_reading_them() {
        assert_eq!(
            classify_secret_path("repo/.env.local"),
            Some(SecretSourceKind::DotEnv)
        );
        assert_eq!(
            classify_secret_path("C:/Users/test/.ssh/id_ed25519"),
            Some(SecretSourceKind::SshPrivateKey)
        );
        assert_eq!(
            classify_secret_path("C:/Users/test/.aws/credentials"),
            Some(SecretSourceKind::AwsCredentials)
        );
        assert_eq!(
            classify_secret_path("/home/test/.config/gcloud/application_default_credentials.json"),
            Some(SecretSourceKind::CloudCredentials)
        );
    }

    #[test]
    fn dotenv_registration_returns_metadata_not_values() {
        let mut index = SecretFingerprintIndex::new(FingerprintKey::from_bytes([3; 32]));
        let registered = register_dotenv_bytes(
            &mut index,
            "fixture",
            b"# synthetic only\nAPI_TOKEN='synthetic-dotenv-secret'\nEMPTY=\n",
        )
        .unwrap();
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].source_key, "API_TOKEN");
        let debug = format!("{registered:?}");
        assert!(!debug.contains("synthetic-dotenv-secret"));
        assert!(
            index
                .scan(b"synthetic-dotenv-secret")
                .iter()
                .any(|m| m.representation == Representation::Raw)
        );
    }

    #[test]
    fn secret_id_validation_is_path_safe() {
        assert!(validate_secret_id("github.project.push-token"));
        assert!(!validate_secret_id("../token"));
        assert!(!validate_secret_id("token/value"));
        assert!(!validate_secret_id("token value"));
    }
}
