# Security Boundaries

ProofDrift reports security properties per boundary instead of exposing one global "safe" flag.

## L0 — inventoried

The component or action is known to ProofDrift, but ProofDrift did not control execution.

## L1 — brokered

ProofDrift controls a dispatch boundary and can allow, deny or require approval before forwarding the action. `proofdrift run` currently provides L1 for the direct process it launches. The MCP broker core also implements L1 semantics, while the public CLI does not yet advertise a production MCP transport.

## L2 — isolated

Execution occurs inside a separately demonstrated isolation boundary with constrained filesystem/network/process behavior. ProofDrift does not infer L2 from L1.

## L3 — attested

Evidence about an execution or artifact is bound to a verifiable attestation from a configured trust root. A hash-chained local receipt alone is not L3.

## Nested-process caveat

If a policy permits `bash -c ...`, `pwsh -Command ...`, `cmd /c ...`, or another interpreter, the direct interpreter process is brokered but arbitrary nested effects inside the command are not automatically intercepted. Policy should prefer direct argv forms for actions that require precise classification.

## Evidence caveat

A valid evidence chain proves integrity of the recorded chain under the verifier's rules. It does not prove the application is correct, the tests are complete, or the model was truthful.
