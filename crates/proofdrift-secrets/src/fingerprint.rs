use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"proofdrift.secret-fingerprint.v1\0";
const MIN_SECRET_BYTES: usize = 6;
const MAX_SECRET_BYTES: usize = 64 * 1024;
const MAX_PATTERNS: usize = 16_384;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Representation {
    Raw,
    Base64,
    Base64Url,
    HexLower,
    UrlPercent,
}

impl Representation {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Raw => b"raw",
            Self::Base64 => b"base64",
            Self::Base64Url => b"base64url",
            Self::HexLower => b"hex-lower",
            Self::UrlPercent => b"url-percent",
        }
    }
}

impl fmt::Debug for Representation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Raw => "Raw",
            Self::Base64 => "Base64",
            Self::Base64Url => "Base64Url",
            Self::HexLower => "HexLower",
            Self::UrlPercent => "UrlPercent",
        })
    }
}

#[derive(Clone)]
pub struct FingerprintKey([u8; 32]);

impl Drop for FingerprintKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl FingerprintKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FingerprintKey([REDACTED])")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FingerprintError {
    InvalidSecretId,
    SecretTooShort,
    SecretTooLarge,
    TooManyPatterns,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretId => f.write_str(
                "secret id is invalid; allowed characters are ASCII letters, digits, '.', '_' and '-'",
            ),
            Self::SecretTooShort => write!(
                f,
                "secret material is too short to fingerprint safely (minimum {MIN_SECRET_BYTES} bytes)"
            ),
            Self::SecretTooLarge => write!(
                f,
                "secret material exceeds the {MAX_SECRET_BYTES} byte safety limit"
            ),
            Self::TooManyPatterns => write!(
                f,
                "fingerprint index exceeds the {MAX_PATTERNS} pattern safety limit"
            ),
        }
    }
}

impl std::error::Error for FingerprintError {}

#[derive(Clone)]
struct PatternFingerprint {
    secret_id: String,
    representation: Representation,
    byte_len: usize,
    digest: [u8; 32],
}

impl fmt::Debug for PatternFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PatternFingerprint")
            .field("secret_id", &self.secret_id)
            .field("representation", &self.representation)
            .field("byte_len", &self.byte_len)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeakMatch {
    pub secret_id: String,
    pub representation: Representation,
    pub offset: usize,
    pub byte_len: usize,
}

pub struct SecretFingerprintIndex {
    key: FingerprintKey,
    patterns: Vec<PatternFingerprint>,
    max_pattern_len: usize,
}

impl fmt::Debug for SecretFingerprintIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFingerprintIndex")
            .field("key", &self.key)
            .field("patterns", &self.patterns)
            .field("max_pattern_len", &self.max_pattern_len)
            .finish()
    }
}

impl SecretFingerprintIndex {
    pub fn new(key: FingerprintKey) -> Self {
        Self {
            key,
            patterns: Vec::new(),
            max_pattern_len: 0,
        }
    }

    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    pub fn max_pattern_len(&self) -> usize {
        self.max_pattern_len
    }

    /// Registers raw and common outbound encodings, then wipes each temporary
    /// transformed representation after its keyed fingerprint is produced.
    pub fn register_secret(
        &mut self,
        secret_id: &str,
        secret: &[u8],
    ) -> Result<usize, FingerprintError> {
        if !is_valid_secret_id(secret_id) {
            return Err(FingerprintError::InvalidSecretId);
        }
        if secret.len() < MIN_SECRET_BYTES {
            return Err(FingerprintError::SecretTooShort);
        }
        if secret.len() > MAX_SECRET_BYTES {
            return Err(FingerprintError::SecretTooLarge);
        }

        let encoded = vec![
            (Representation::Raw, Zeroizing::new(secret.to_vec())),
            (
                Representation::Base64,
                Zeroizing::new(STANDARD.encode(secret).into_bytes()),
            ),
            (
                Representation::Base64Url,
                Zeroizing::new(URL_SAFE_NO_PAD.encode(secret).into_bytes()),
            ),
            (Representation::HexLower, Zeroizing::new(hex_lower(secret))),
            (
                Representation::UrlPercent,
                Zeroizing::new(url_percent_encode(secret)),
            ),
        ];

        let mut seen = BTreeSet::<(usize, [u8; 32])>::new();
        let mut staged = Vec::new();
        for (representation, value) in encoded {
            let digest = digest_candidate(self.key.as_bytes(), secret_id, representation, &value);
            let identity = content_identity(self.key.as_bytes(), secret_id, &value);
            if seen.insert((value.len(), identity)) {
                staged.push(PatternFingerprint {
                    secret_id: secret_id.to_owned(),
                    representation,
                    byte_len: value.len(),
                    digest,
                });
            }
        }

        if self.patterns.len().saturating_add(staged.len()) > MAX_PATTERNS {
            return Err(FingerprintError::TooManyPatterns);
        }

        let added = staged.len();
        for pattern in staged {
            self.max_pattern_len = self.max_pattern_len.max(pattern.byte_len);
            self.patterns.push(pattern);
        }
        Ok(added)
    }

    pub fn scan(&self, payload: &[u8]) -> Vec<LeakMatch> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            if pattern.byte_len == 0 || payload.len() < pattern.byte_len {
                continue;
            }
            for (offset, window) in payload.windows(pattern.byte_len).enumerate() {
                let candidate = digest_candidate(
                    self.key.as_bytes(),
                    &pattern.secret_id,
                    pattern.representation,
                    window,
                );
                if constant_time_eq(&candidate, &pattern.digest) {
                    matches.push(LeakMatch {
                        secret_id: pattern.secret_id.clone(),
                        representation: pattern.representation,
                        offset,
                        byte_len: pattern.byte_len,
                    });
                }
            }
        }
        matches.sort_by(|a, b| {
            (a.offset, &a.secret_id, a.representation, a.byte_len).cmp(&(
                b.offset,
                &b.secret_id,
                b.representation,
                b.byte_len,
            ))
        });
        matches.dedup();
        matches
    }

    pub fn streaming_scanner(&self) -> StreamingScanner<'_> {
        StreamingScanner::new(self)
    }
}

pub struct StreamingScanner<'a> {
    index: &'a SecretFingerprintIndex,
    tail: Zeroizing<Vec<u8>>,
    total_seen: usize,
}

impl fmt::Debug for StreamingScanner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingScanner")
            .field("tail", &"[REDACTED]")
            .field("total_seen", &self.total_seen)
            .finish()
    }
}

impl<'a> StreamingScanner<'a> {
    fn new(index: &'a SecretFingerprintIndex) -> Self {
        Self {
            index,
            tail: Zeroizing::new(Vec::new()),
            total_seen: 0,
        }
    }

    /// Scans a stream while retaining only the minimum bounded suffix needed
    /// to detect a registered representation split across chunk boundaries.
    pub fn scan_chunk(&mut self, chunk: &[u8]) -> Vec<LeakMatch> {
        let prior_tail_len = self.tail.len();
        let base_offset = self.total_seen.saturating_sub(prior_tail_len);
        let mut combined = Zeroizing::new(Vec::with_capacity(prior_tail_len + chunk.len()));
        combined.extend_from_slice(&self.tail);
        combined.extend_from_slice(chunk);

        let boundary = self.total_seen;
        let mut matches = self.index.scan(&combined);
        for item in &mut matches {
            item.offset += base_offset;
        }
        // Suppress matches wholly contained in the retained suffix because they
        // were already reported on an earlier chunk.
        matches.retain(|item| item.offset.saturating_add(item.byte_len) > boundary);

        self.total_seen = self.total_seen.saturating_add(chunk.len());
        let keep = self
            .index
            .max_pattern_len()
            .saturating_sub(1)
            .min(combined.len());
        self.tail.zeroize();
        self.tail.clear();
        if keep > 0 {
            self.tail
                .extend_from_slice(&combined[combined.len() - keep..]);
        }
        matches
    }
}

pub(crate) fn is_valid_secret_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && value != "."
        && value != ".."
}

fn content_identity(key: &[u8; 32], secret_id: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"proofdrift.secret-representation-dedup.v1\0");
    hasher.update(secret_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn digest_candidate(
    key: &[u8; 32],
    secret_id: &str,
    representation: Representation,
    bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(DOMAIN);
    hasher.update(secret_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(representation.tag());
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0f) as usize]);
    }
    out
}

fn url_percent_encode(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte);
        } else {
            out.extend_from_slice(&[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
        }
    }
    out
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&a, &b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_with(secret: &[u8]) -> SecretFingerprintIndex {
        let mut index = SecretFingerprintIndex::new(FingerprintKey::from_bytes([7; 32]));
        index.register_secret("synthetic.token", secret).unwrap();
        index
    }

    #[test]
    fn debug_never_contains_key_or_registered_secret() {
        let secret = b"synthetic_SUPER_secret_123!";
        let index = index_with(secret);
        let debug = format!("{index:?}");
        assert!(!debug.contains("synthetic_SUPER_secret_123!"));
        assert!(!debug.contains(&"07".repeat(32)));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn detects_raw_and_common_encodings() {
        let secret = b"synthetic-token+/=42";
        let index = index_with(secret);

        let raw = index.scan(b"prefix synthetic-token+/=42 suffix");
        assert!(raw.iter().any(|m| m.representation == Representation::Raw));

        let encoded = STANDARD.encode(secret);
        let base64_matches = index.scan(format!("x={encoded}").as_bytes());
        assert!(
            base64_matches
                .iter()
                .any(|m| m.representation == Representation::Base64)
        );

        let hex = String::from_utf8(hex_lower(secret)).unwrap();
        let hex_matches = index.scan(format!("x={hex}").as_bytes());
        assert!(
            hex_matches
                .iter()
                .any(|m| m.representation == Representation::HexLower)
        );

        let url = String::from_utf8(url_percent_encode(secret)).unwrap();
        let url_matches = index.scan(format!("x={url}").as_bytes());
        assert!(
            url_matches
                .iter()
                .any(|m| m.representation == Representation::UrlPercent)
        );
    }

    #[test]
    fn streaming_scanner_detects_chunked_secret_once() {
        let secret = b"synthetic-chunked-secret";
        let index = index_with(secret);
        let mut scanner = index.streaming_scanner();

        assert!(scanner.scan_chunk(b"prefix synthetic-ch").is_empty());
        let matches = scanner.scan_chunk(b"unked-secret suffix");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 7);
        assert_eq!(matches[0].representation, Representation::Raw);
        assert!(scanner.scan_chunk(b" more").is_empty());
    }

    #[test]
    fn rejects_unsafe_ids_and_tiny_values() {
        let mut index = SecretFingerprintIndex::new(FingerprintKey::from_bytes([1; 32]));
        assert_eq!(
            index.register_secret("../escape", b"long-enough"),
            Err(FingerprintError::InvalidSecretId)
        );
        assert_eq!(
            index.register_secret("ok", b"tiny"),
            Err(FingerprintError::SecretTooShort)
        );
    }
}
