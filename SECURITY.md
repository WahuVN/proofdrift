# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository whenever possible. Do not publish exploit details, real credentials, private repository content, or personal data in an issue.

If private reporting is unavailable, open a minimal issue asking a maintainer for a private contact channel without including exploit details.

## Current security properties

- Discovery and static scanning do not intentionally execute discovered MCP commands, hooks or setup instructions.
- Baseline names and evidence archive paths are bounded and validated against traversal and ambiguous-path cases.
- Cedar decisions are bound to normalized requests and policy-bundle digests; unknown capabilities fail closed.
- `proofdrift run` evaluates policy before direct process dispatch. A denied command is not sent to the process runner.
- Approval tokens are one-time, expiring and scope-bound in the policy/runtime primitives.
- Runtime evidence is structurally redacted before persistence and stored in a hash chain.
- `.proofdrift` bundle verification checks covered-file digests, event-chain integrity, duplicate/uncovered entries, path safety and resource limits.
- MCP broker-core tests cover deny-before-dispatch, approval-before-dispatch, tool schema drift, unknown tools, redaction, bounds, timeout and concurrency limits.
- Provenance snapshots include integrity digests and strict graph validation. Unverified external metadata is not silently promoted to verified provenance.

## Boundaries and non-guarantees

L1 means ProofDrift controls a broker/process-dispatch boundary. It does **not** mean OS/container isolation. Once a permitted process is dispatched, nested behavior inside that process is outside the direct-process boundary unless another enforcing adapter or sandbox is present.

ProofDrift does not guarantee that every prompt injection can be detected, that an agent or model is benevolent, that test success proves software correctness, or that L2/L3 guarantees exist without explicit backend/attestation evidence.

The MCP broker core is implemented, but the public CLI does not claim production proxy enforcement until a concrete stdio/HTTP transport is wired and separately tested.

Synthetic secrets only belong in tests. Never submit real secrets to fixtures, logs, screenshots or issue attachments.
