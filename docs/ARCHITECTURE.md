# Architecture

ProofDrift is organized around a single evidence path:

`discovery -> capability model -> policy -> brokered action -> evidence -> patch/test proof -> provenance/report`

## Major components

- `proofdrift-discover` finds agent, skill, hook and MCP configuration without executing it.
- `proofdrift-scan` performs deterministic admission checks and emits stable finding identifiers.
- `proofdrift-capabilities` normalizes capability vocabulary and keeps declared, inferred and observed evidence distinct.
- `proofdrift-policy` evaluates Cedar-backed policy and binds decisions to normalized requests and policy digests.
- `proofdrift-runtime` guards direct process dispatch and records explicit enforcement levels.
- `proofdrift-mcp-proxy` provides broker-core checks for MCP tool calls, approvals, schema drift and bounded transport behavior.
- `proofdrift-evidence` stores redacted, hash-chained runtime evidence and verifies `.proofdrift` bundles.
- `proofdrift-patch` computes changed surfaces, blast radius and required/recommended test evidence.
- `proofdrift-provenance` and `proofdrift-registry` build deterministic local provenance graphs and immutable snapshots.
- `proofdrift-attest` projects evidence into standards-oriented attestations without inventing unsupported guarantees.
- `proofdrift-secrets` provides secret fingerprinting and egress-oriented guard primitives.

## Design rules

1. **Fail closed on ambiguous security input.** Unknown capabilities, malformed policy context and unsafe archive paths are rejected rather than guessed.
2. **Never upgrade evidence strength silently.** Declared, inferred, observed, brokered, isolated and attested are separate states.
3. **Determinism is part of the contract.** Canonical hashing, stable ordering and stable finding identifiers make baseline and CI diffs reviewable.
4. **Boundary-specific claims only.** A process wrapper is not described as an OS sandbox; a generic evidence receipt is not described as proof of correctness.
5. **Local-first by default.** Core discovery, policy, evidence and provenance operations do not require a hosted control plane.

The public wire contracts live in the `proofdrift-spec` repository. Adversarial test cases and benchmark methodology live in `proofdrift-bench`.
