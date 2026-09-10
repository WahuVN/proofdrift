# Cross-Repository Release Gate

This gate is the release-quality contract across `proofdrift`, `proofdrift-spec`, and `proofdrift-bench`. It is deliberately stricter than badges: a release should carry machine-readable conformance, security, coverage, benchmark, checksum, SBOM, and provenance evidence.

## Required drift families

The release gate keeps these names stable and requires benchmark evidence for every family:

| Drift family | Minimum benchmark evidence |
| --- | --- |
| `provenance drift` | `missing_provenance_trusted`, `provenance_conflict` |
| `capability drift` | `capability_inferred_as_observed`, `tool_schema_rugpull`, `broad_shell` |
| `policy drift` | `policy_digest_mismatch`, `approval_scope_mismatch`, `decision_request_digest_mismatch` |
| `runtime drift` | `unknown_enforcement_claim`, `toctou_executable_swap`, `approval_concurrent_replay` |
| `patch-impact drift` | `risky_auth_patch`, `risky_db_patch`, `risky_concurrency_patch` |
| `test-proof drift` | `test_weakening`, `test_claim_without_observation` |

Do not rename these six families in a release-only change. If a contract needs a rename, land a compatibility/migration proposal first.

## Machine gate

From a checkout where the three repositories are siblings:

```sh
python tools/cross_repo_gate.py \
  --spec ../proofdrift-spec \
  --bench ../proofdrift-bench \  --json-output cross-repo-evidence.json
```

Ground-truth rationale, Bench v3 science-suite coverage, immutable spec identities, semantic traceability, and each repository's native fail-closed release gate are mandatory on every run; there is no weaker release mode.

The gate fails on schema-version mismatch, unexpected canonicalization, mutable or incomplete schema identity, semantic trace coverage below 100%, native release-gate failure, Bench version drift, regression below 24 drift pairs or 18 hard controls, missing any of the six drift classes, or science-oracle digest mismatch. It records exact engine/spec/bench commits in the evidence JSON.

Engine/spec wire conformance is checked separately by:

```sh
PROOFDRIFT_SPEC_DIR=../proofdrift-spec \
  cargo test --locked -p proofdrift-schema --test cross_repo_spec
```

On Windows, enter the Visual C++ environment first when using the MSVC Rust target, for example `call D:\BuildTools\VC\Auxiliary\Build\vcvars64.bat`.

## Security and robustness proof

Before tagging, all of the following must be green:

1. Existing `ci-success` plus `quality-gate-success`.
2. `cargo fmt --all -- --check`, strict Clippy, workspace unit/integration tests, and declared MSRV check.
3. Tamper regression: evidence mutation/reorder/delete and bundle byte tampering fail closed.
4. Replay regression: approval replay/race/expiry and request binding fail closed.
5. Forged provenance regression: changing provenance changes the request binding digest.
6. Policy downgrade regression: removing an enforcing policy changes the policy digest; approval bound to the original digest is rejected under the downgraded digest.
7. Dependency vulnerability audit (`cargo audit`).
8. Determinism/crash-resistance robustness tests, including canonicalization fixed-point checks and bounded malformed JSON parsing.
9. Repeat the race and canonical determinism regressions at least three times in CI to expose obvious flakiness.

## Coverage and benchmark evidence

`quality-gate.yml` emits LCOV for the security-critical schema, policy, and evidence crates and enforces at least **70% line coverage** for that focused set. Treat this as a floor, not a target; lowering it requires a documented security/architecture reason.

The benchmark repository must pass `verify_corpus.py` and its Rust property/regression tests. The committed benchmark reference must have a case count and operation count consistent with the current corpus. Performance numbers are evidence, not a security threshold, and must not be silently relaxed to make a release pass.

AI 5 must not rewrite AI 3 expected labels, ground truth, FPR/FNR thresholds, or benchmark scientific conclusions. A disagreement is resolved in the benchmark branch, not by weakening this release gate.

## Release evidence checklist

Before creating `vX.Y.Z`:

- update `CHANGELOG.md` and the workspace package version;
- confirm `proofdrift-schema::SCHEMA_VERSION` equals `proofdrift-spec/contracts/schemas/index.json`;
- archive `cross-repo-evidence.json` from the strict gate;
- archive the security-critical LCOV artifact and confirm the threshold passed;
- archive current benchmark result/metrics and corpus digest;
- confirm all three native repository validators/tests pass from clean checkouts;
- confirm no generated schema/corpus diff is unexplained;
- build from the tag with the lockfile;
- publish platform archives plus `SHA256SUMS.txt`, SPDX SBOM, and GitHub build-provenance attestations;
- verify at least one published artifact attestation after release.

A badge, a successful local build, or a benchmark result by itself is not sufficient release evidence.
