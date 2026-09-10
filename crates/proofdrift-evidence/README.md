# proofdrift-evidence

Tamper-evident local evidence storage for ProofDrift. The crate provides structural redaction, SQLite-backed append-only event chains, bounded `.proofdrift` bundles, offline verification and safe extraction.

A valid chain proves integrity of the recorded evidence under the verifier's rules; it does not prove software correctness or completeness of observation.
