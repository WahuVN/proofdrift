# proofdrift-attest

Standards-oriented attestation adapters for ProofDrift evidence. Generic evidence statements use the in-toto Statement v1 envelope. SLSA provenance is emitted only when real build-provenance context is supplied. Signing and verification are delegated to configured external tooling such as Sigstore/cosign; no custom signature scheme is introduced.
