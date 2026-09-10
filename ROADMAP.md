# Roadmap

ProofDrift develops around evidence quality and boundary-specific enforcement. Items are ordered by product dependency, not promised dates.

## 0.1 — Complete the first trust-diff loop
- Production stdio MCP transport with deny-before-dispatch, approval gating, bounded I/O and end-to-end tests.
- Streamable HTTP MCP transport with explicit TLS/redirect/egress policy and schema-drift handling.
- Better `trust diff` presentation that correlates component provenance, capability expansion, observed actions, patch surfaces and test gaps in one report.
- Stable machine-readable report format synchronized with `proofdrift-spec`.

## 0.2 — Stronger local enforcement
- L2 isolation backends with explicit per-platform capability matrices rather than a single global sandbox claim.
- Filesystem, process and network enforcement adapters with symlink/junction/TOCTOU regression coverage.
- Approval UX that can be integrated by coding-agent hosts without weakening one-time/scope-bound semantics.

## 0.3 — Interoperability and evidence portability
- OpenTelemetry export for runtime/evidence events.
- Stronger in-toto/SLSA/Sigstore interoperability and verification UX.
- SPDX/CycloneDX export validation against public schemas.
- Cross-tool import of compatible agent manifests/lockfiles without becoming another package manager.

## 1.0 readiness criteria
A 1.0 release requires stable public contracts, migration documentation, at least one demonstrated L2 backend, production MCP transport coverage, reproducible release provenance, and sustained cross-platform regression coverage.

## Non-goals
ProofDrift will not become a generic agent framework, hosted prompt dashboard, package manager, or model leaderboard. It should remain focused on change control, execution evidence and verifiable security boundaries.
