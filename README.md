# ProofDrift

[![CI](https://github.com/WahuVN/proofdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/WahuVN/proofdrift/actions/workflows/ci.yml)
[![Security](https://github.com/WahuVN/proofdrift/actions/workflows/security.yml/badge.svg)](https://github.com/WahuVN/proofdrift/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

ProofDrift is a local-first change-control and evidence layer for coding agents. It connects four questions that are usually handled separately: **what agent components changed, what capabilities changed, what actually executed, and whether the resulting patch has enough test evidence.**

## What works today

- Passive discovery for common coding-agent, skill and MCP configuration surfaces without executing discovered commands.
- Deterministic admission scanning with stable `PROOFDRIFT-SCAN-*` rule identifiers.
- Baseline creation and trust diff over local agent/project artifacts.
- Canonical capability taxonomy with declared, inferred and observed evidence kept distinct.
- Cedar-backed policy evaluation with deny, approval and observe semantics bound to normalized requests and policy digests.
- L1 brokered process execution: `proofdrift run` evaluates policy before dispatch and records tamper-evident local evidence.
- Runtime receipts in SQLite plus `proofdrift report` hash-chain verification and event timelines.
- Tamper-evident `.proofdrift` evidence bundles with bounded archive verification.
- Patch/blast-radius and test-evidence analysis.
- Git, GitHub metadata, Hugging Face metadata, APM, Cargo, npm, pnpm and MCP provenance adapters.
- SPDX 2.3 and CycloneDX 1.6 shaped inventory export helpers.
- Secret/egress guards and cross-platform CI.

## Enforcement model

`proofdrift run` is **L1 brokered** at the direct process-dispatch boundary. L1 is not an OS sandbox. A permitted shell can still perform nested side effects that are outside this boundary unless another enforcing adapter or sandbox is present. L2 isolation and L3 attestation are reported only when a concrete backend or attestation proves them.

The MCP broker core is implemented and tested for deny-before-dispatch, approval gating, schema drift, request/response limits, timeout and redaction. The CLI intentionally does not claim a production MCP transport until a concrete stdio/HTTP adapter is wired and tested end to end.

## Install from source

Rust 1.89 or newer is required.

```sh
git clone https://github.com/WahuVN/proofdrift.git
cd proofdrift
cargo build --locked --release -p proofdrift-cli
```

The binary is `target/release/proofdrift` (`proofdrift.exe` on Windows).

## CLI quick start

```sh
proofdrift discover .
proofdrift scan .
proofdrift baseline create --name trusted-main .
proofdrift diff --baseline trusted-main .
proofdrift policy check request.json
proofdrift run -- cmd /c echo hello
proofdrift report
proofdrift patch --base HEAD^ --head HEAD
proofdrift provenance explain <artifact>
proofdrift verify session.proofdrift
```

On Unix, replace the Windows `cmd /c echo hello` example with a direct command such as `printf hello`.

Exit codes: `0` success, `1` operational/config or child-process failure, `2` findings/evidence gaps, `3` policy deny or approval required, `4` evidence verification failure, `5` intentionally unsupported enforcement surface.

## Repositories

- **proofdrift** — CLI, runtime, policy, evidence, provenance and integrations.
- **proofdrift-spec** — versioned JSON Schemas, examples and contract tooling.
- **proofdrift-bench** — adversarial security corpus, fuzz seeds and benchmark harness.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --locked --workspace --release
```

See [Architecture](docs/ARCHITECTURE.md), [Security Boundaries](docs/SECURITY_BOUNDARIES.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
