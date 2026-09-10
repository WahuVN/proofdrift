# Policy pack fixtures

The executable built-ins live in `proofdrift_policy::built_in_policy_pack`. These files document intended fixture semantics for contract tests.

- `safe-local-dev`: local read/write/create/process/git commit/MCP plus network approval; denies secret egress and force-push to `origin/main`.
- `read-only-audit`: read-oriented capabilities only.
- `no-secret-egress`: broad permit with Cedar forbid for `secret.egress`, demonstrating forbid-overrides-permit.
- `protected-git-main`: broad permit except force-push to `origin/main`.
- `constrained-mcp`: MCP list/call, with `dangerous.*` calls requiring approval.
- `ci-unattended`: limited read/exec CI profile; no interactive approval path.

Approval rules are ProofDrift metadata applied only after Cedar returns Allow. They are not represented as fake Cedar syntax.
