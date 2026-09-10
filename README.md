# ProofDrift

[![CI](https://github.com/WahuVN/proofdrift/actions/workflows/ci.yml/badge.svg)](https://github.com/WahuVN/proofdrift/actions/workflows/ci.yml)
[![Security](https://github.com/WahuVN/proofdrift/actions/workflows/security.yml/badge.svg)](https://github.com/WahuVN/proofdrift/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/WahuVN/proofdrift?include_prereleases)](https://github.com/WahuVN/proofdrift/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

ProofDrift is a **local-first change-control and evidence layer for coding agents**. It correlates four things that are usually reviewed separately: supply-chain changes, capability drift, actions that actually executed, and whether the resulting patch has enough test evidence.

## Why it exists

A coding-agent change can look small in Git while materially changing what the agent is allowed to do. ProofDrift keeps the evidence chain explicit:

```text
agent / skill / MCP change
        ↓
provenance + declared capability
        ↓
static inference + policy decision
        ↓
observed / brokered runtime action
        ↓
patch blast radius + tests actually run
        ↓
trust diff + tamper-evident evidence
```

The key rule is **never silently upgrade evidence strength**. Declared, inferred, observed, brokered, isolated and attested are different claims.

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
- Secret/egress guard primitives and cross-platform CI.
- A self-contained composite GitHub Action for report-only or strict CI checks.

## Enforcement model

`proofdrift run` is **L1 brokered** at the direct process-dispatch boundary. L1 is not an OS sandbox. A permitted shell can still perform nested side effects outside this boundary unless another enforcing adapter or sandbox is present. L2 isolation and L3 attestation are reported only when a concrete backend or attestation proves them.

The MCP broker core is implemented and tested for deny-before-dispatch, approval gating, schema drift, request/response limits, timeout and redaction. The CLI intentionally does not claim a production MCP transport until a concrete stdio/HTTP adapter is wired and tested end to end.

## Install

### Release archive

Prebuilt preview archives are published on the [Releases](https://github.com/WahuVN/proofdrift/releases) page for Linux x64, Windows x64 and macOS ARM64. Verify `SHA256SUMS.txt` before use. Releases produced by the current tag workflow also publish an SPDX JSON SBOM and GitHub build-provenance attestations; see [RELEASING.md](RELEASING.md) for verification.

### Build from source

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
proofdrift run -- printf hello
proofdrift report
proofdrift patch --base HEAD^ --head HEAD
proofdrift provenance explain <artifact>
proofdrift verify session.proofdrift
```

On Windows, replace `printf hello` with a direct command such as `cmd /c echo hello`. Prefer direct argv commands when precise runtime classification matters.

Exit codes are intentionally separated for CI: `0` pass, `1` tool/child-process failure, `2` findings or evidence gaps (warn), `3` policy deny or approval required (block), `4` evidence verification failure, `5` intentionally unsupported enforcement surface, and `64` invalid CLI input/configuration. `--json` keeps stdout machine-readable for both success and failure paths.

### CLI configuration

ProofDrift loads configuration with deterministic precedence: **CLI flags > `PROOFDRIFT_*` environment variables > config file > built-in defaults**. By default it reads `.proofdrift/config.toml` when that file exists; override it with `--config <path>` or `PROOFDRIFT_CONFIG`.

```toml
[output]
format = "human" # human | json

[run]
policy = "safe-local-dev"
timeout_ms = 300000
max_output_bytes = 4194304
```

Validate or inspect the effective configuration before a CI run:

```sh
proofdrift config validate
proofdrift --json config show
```

Environment overrides are `PROOFDRIFT_OUTPUT`, `PROOFDRIFT_POLICY`, `PROOFDRIFT_TIMEOUT_MS`, and `PROOFDRIFT_MAX_OUTPUT_BYTES`. Unknown config keys and invalid limits fail early with exit code `64`. A complete example is in `examples/proofdrift.config.toml`.

## GitHub Action

```yaml
steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 2
  - uses: WahuVN/proofdrift/integrations/github-action@v0.0.2
    with:
      base: HEAD^
      head: HEAD
      strict: 'false'
```

The action exposes scan/patch exit codes and JSON report paths. `strict: false` is report-only; set `strict: true` when the repository is ready to gate on ProofDrift findings.

## Repositories

- **[proofdrift](https://github.com/WahuVN/proofdrift)** — CLI, runtime, policy, evidence, provenance and integrations.
- **[proofdrift-spec](https://github.com/WahuVN/proofdrift-spec)** — versioned JSON Schemas, examples and contract tooling.
- **[proofdrift-bench](https://github.com/WahuVN/proofdrift-bench)** — adversarial security corpus, fuzz seeds and benchmark harness.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
```

Project policy and maintenance docs: [Architecture](docs/ARCHITECTURE.md), [Security Boundaries](docs/SECURITY_BOUNDARIES.md), [Roadmap](ROADMAP.md), [Support](SUPPORT.md), [Governance](GOVERNANCE.md), [Changelog](CHANGELOG.md), [Security Policy](SECURITY.md), and [Contributing](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
