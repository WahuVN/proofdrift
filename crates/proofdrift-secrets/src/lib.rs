//! Redaction-first secret fingerprinting and outbound egress inspection.
//!
//! The production index stores keyed fingerprints, lengths, identifiers and
//! transformation metadata only. It never stores registered secret plaintext.
//! Payload bytes are caller-owned and are inspected transiently.

mod destination;
mod fingerprint;
mod source;

pub use destination::{
    DestinationPolicy, EgressGuard, EgressReport, EgressVerdict, HostRule, PolicyAction,
};
pub use fingerprint::{
    FingerprintError, FingerprintKey, LeakMatch, Representation, SecretFingerprintIndex,
    StreamingScanner,
};
pub use source::{
    DotEnvError, RegisteredDotEnvSecret, SecretSourceKind, classify_secret_path,
    register_dotenv_bytes, validate_secret_id,
};
