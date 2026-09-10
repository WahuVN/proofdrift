# proofdrift-patch

Deterministic patch-impact analysis for ProofDrift. The crate classifies changed files and symbols, identifies sensitive surfaces, estimates blast radius and maps changes to required or recommended test evidence.

Line count is intentionally not used as the primary risk signal. Authentication, persistence, schema, concurrency and privilege surfaces receive explicit treatment.
