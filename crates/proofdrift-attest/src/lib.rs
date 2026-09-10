//! Standards-oriented attestation adapters.
//! No bespoke signing scheme is implemented: signing is delegated to an
//! external signer (for example Sigstore/cosign) through a narrow trait.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PROOFDRIFT_PREDICATE_TYPE: &str = "urn:proofdrift:attestation:evidence:v0.1";

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signer unavailable: {0}")]
    SignerUnavailable(String),
    #[error("signer failed: {0}")]
    SignerFailed(String),
    #[error("invalid signature result: {0}")]
    InvalidSignature(String),
    #[error("invalid input: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, AttestError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePredicate {
    pub schema_version: String,
    pub session_id: String,
    pub bundle_format: String,
    pub final_event_hash: String,
    pub policy_bundle_digests: Vec<String>,
    pub enforcement_summary: BTreeMap<String, u64>,
    pub claims: ReceiptClaims,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptClaims {
    pub proves: Vec<String>,
    pub does_not_prove: Vec<String>,
}

impl Default for ReceiptClaims {
    fn default() -> Self {
        Self {
            proves: vec![
                "bundle digest identifies exact evidence bytes".into(),
                "covered event-chain hash is bound into this statement".into(),
            ],
            does_not_prove: vec![
                "software correctness".into(),
                "test completeness".into(),
                "agent benevolence".into(),
                "truthfulness of unsigned external metadata".into(),
            ],
        }
    }
}

pub fn evidence_statement(
    bundle_name: &str,
    bundle_sha256: &str,
    predicate: EvidencePredicate,
) -> Result<InTotoStatement> {
    if bundle_name.trim().is_empty() || !is_sha256(bundle_sha256) {
        return Err(AttestError::Invalid("bundle name/digest".into()));
    }
    let mut digest = BTreeMap::new();
    digest.insert("sha256".into(), bundle_sha256.to_ascii_lowercase());
    Ok(InTotoStatement {
        statement_type: STATEMENT_TYPE.into(),
        subject: vec![Subject {
            name: bundle_name.into(),
            digest,
        }],
        predicate_type: PROOFDRIFT_PREDICATE_TYPE.into(),
        predicate: serde_json::to_value(predicate)?,
    })
}

/// SLSA provenance is emitted only when the caller actually has build
/// provenance semantics. Evidence sessions are not mislabeled as SLSA builds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlsaBuildContext {
    pub builder_id: String,
    pub build_type: String,
    pub invocation_id: String,
    pub source_uri: String,
    pub source_digest_sha256: String,
}

pub fn slsa_v1_statement(
    subject_name: &str,
    subject_sha256: &str,
    ctx: &SlsaBuildContext,
) -> Result<InTotoStatement> {
    if ctx.builder_id.trim().is_empty()
        || ctx.build_type.trim().is_empty()
        || !is_sha256(subject_sha256)
        || !is_sha256(&ctx.source_digest_sha256)
    {
        return Err(AttestError::Invalid("SLSA semantics incomplete".into()));
    }
    let mut digest = BTreeMap::new();
    digest.insert("sha256".into(), subject_sha256.to_ascii_lowercase());
    let predicate = json!({
        "buildDefinition": {
            "buildType": ctx.build_type,
            "externalParameters": {},
            "internalParameters": {},
            "resolvedDependencies": [{"uri":ctx.source_uri,"digest":{"sha256":ctx.source_digest_sha256}}]
        },
        "runDetails": {
            "builder": {"id":ctx.builder_id},
            "metadata": {"invocationId":ctx.invocation_id}
        }
    });
    Ok(InTotoStatement {
        statement_type: STATEMENT_TYPE.into(),
        subject: vec![Subject {
            name: subject_name.into(),
            digest,
        }],
        predicate_type: "https://slsa.dev/provenance/v1".into(),
        predicate,
    })
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub trait DetachedSigner {
    fn sign_blob(
        &self,
        blob: &Path,
        signature_out: &Path,
        certificate_out: Option<&Path>,
    ) -> Result<SignerMetadata>;
    fn verify_blob(
        &self,
        blob: &Path,
        signature: &Path,
        certificate: Option<&Path>,
    ) -> Result<SignerMetadata>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerMetadata {
    pub provider: String,
    pub verified: bool,
    pub identity: Option<String>,
    pub certificate_present: bool,
    pub note: String,
}

/// Optional Sigstore integration via the official `cosign` CLI. The library
/// never shells through a command interpreter and never logs environment or
/// secret values. Callers must explicitly configure keyless/key-based auth.
#[derive(Clone, Debug)]
pub struct CosignSigner {
    pub executable: PathBuf,
    pub extra_verify_args: Vec<String>,
}

impl CosignSigner {
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            extra_verify_args: Vec::new(),
        }
    }

    fn ensure_executable(&self) -> Result<()> {
        if self.executable.as_os_str().is_empty() {
            return Err(AttestError::SignerUnavailable("cosign path empty".into()));
        }
        Ok(())
    }
}

impl DetachedSigner for CosignSigner {
    fn sign_blob(
        &self,
        blob: &Path,
        signature_out: &Path,
        certificate_out: Option<&Path>,
    ) -> Result<SignerMetadata> {
        self.ensure_executable()?;
        let mut cmd = Command::new(&self.executable);
        cmd.arg("sign-blob")
            .arg("--yes")
            .arg("--output-signature")
            .arg(signature_out);
        if let Some(cert) = certificate_out {
            cmd.arg("--output-certificate").arg(cert);
        }
        cmd.arg(blob)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .map_err(|e| AttestError::SignerUnavailable(e.to_string()))?;
        if !out.status.success() {
            return Err(AttestError::SignerFailed(sanitize_stderr(&out.stderr)));
        }
        if !signature_out.is_file() {
            return Err(AttestError::SignerFailed(
                "cosign reported success without signature file".into(),
            ));
        }
        Ok(SignerMetadata {
            provider: "sigstore/cosign".into(),
            verified: false,
            identity: None,
            certificate_present: certificate_out.map(|p| p.is_file()).unwrap_or(false),
            note: "signature created; verification is a separate operation".into(),
        })
    }

    fn verify_blob(
        &self,
        blob: &Path,
        signature: &Path,
        certificate: Option<&Path>,
    ) -> Result<SignerMetadata> {
        self.ensure_executable()?;
        if !signature.is_file() {
            return Err(AttestError::InvalidSignature(
                "signature file missing".into(),
            ));
        }
        let mut cmd = Command::new(&self.executable);
        cmd.arg("verify-blob").arg("--signature").arg(signature);
        if let Some(cert) = certificate {
            cmd.arg("--certificate").arg(cert);
        }
        for arg in &self.extra_verify_args {
            cmd.arg(arg);
        }
        cmd.arg(blob)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .map_err(|e| AttestError::SignerUnavailable(e.to_string()))?;
        if !out.status.success() {
            return Err(AttestError::InvalidSignature(sanitize_stderr(&out.stderr)));
        }
        Ok(SignerMetadata {
            provider: "sigstore/cosign".into(),
            verified: true,
            identity: None,
            certificate_present: certificate.map(|p| p.is_file()).unwrap_or(false),
            note:
                "cryptographic verification succeeded; this does not establish software correctness"
                    .into(),
        })
    }
}

fn sanitize_stderr(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let first = s.lines().next().unwrap_or("signer error");
    first.chars().take(240).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub schema_version: String,
    pub bundle_sha256: String,
    pub attestation_sha256: String,
    pub signer: Option<SignerMetadata>,
    pub claims: ReceiptClaims,
}

pub fn unsigned_receipt(bundle_sha256: &str, attestation_sha256: &str) -> Result<Receipt> {
    if !is_sha256(bundle_sha256) || !is_sha256(attestation_sha256) {
        return Err(AttestError::Invalid("receipt digest".into()));
    }
    Ok(Receipt {
        schema_version: "0.1".into(),
        bundle_sha256: bundle_sha256.to_ascii_lowercase(),
        attestation_sha256: attestation_sha256.to_ascii_lowercase(),
        signer: None,
        claims: ReceiptClaims::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    #[test]
    fn generic_statement_is_in_toto_and_not_slsa() {
        let p = EvidencePredicate {
            schema_version: "0.1".into(),
            session_id: "s1".into(),
            bundle_format: "proofdrift/1".into(),
            final_event_hash: hash('a'),
            policy_bundle_digests: vec![hash('b')],
            enforcement_summary: BTreeMap::from([("L1".into(), 2)]),
            claims: ReceiptClaims::default(),
        };
        let s = evidence_statement("session.proofdrift", &hash('c'), p).unwrap();
        assert_eq!(s.statement_type, STATEMENT_TYPE);
        assert_eq!(s.predicate_type, PROOFDRIFT_PREDICATE_TYPE);
        assert_ne!(s.predicate_type, "https://slsa.dev/provenance/v1");
    }

    #[test]
    fn slsa_requires_real_build_context_shape() {
        let bad = SlsaBuildContext {
            builder_id: "".into(),
            build_type: "x".into(),
            invocation_id: "i".into(),
            source_uri: "git+https://example".into(),
            source_digest_sha256: hash('d'),
        };
        assert!(slsa_v1_statement("bin", &hash('e'), &bad).is_err());
        let good = SlsaBuildContext {
            builder_id: "https://builder.example/v1".into(),
            build_type: "https://example/build/v1".into(),
            invocation_id: "i".into(),
            source_uri: "git+https://example".into(),
            source_digest_sha256: hash('d'),
        };
        assert_eq!(
            slsa_v1_statement("bin", &hash('e'), &good)
                .unwrap()
                .predicate_type,
            "https://slsa.dev/provenance/v1"
        );
    }

    #[test]
    fn receipt_never_claims_correctness() {
        let r = unsigned_receipt(&hash('a'), &hash('b')).unwrap();
        assert!(r.signer.is_none());
        assert!(r
            .claims
            .does_not_prove
            .iter()
            .any(|x| x.contains("correctness")));
    }

    #[test]
    fn missing_cosign_is_actionable_not_fake_verified() {
        let signer = CosignSigner::new("definitely-not-a-real-cosign-binary-proofdrift-test");
        let err = signer
            .verify_blob(Path::new("blob"), Path::new("missing.sig"), None)
            .unwrap_err();
        assert!(matches!(err, AttestError::InvalidSignature(_)));
    }
}
