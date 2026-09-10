# Contributing

Contributions are welcome. ProofDrift favors deterministic behavior, narrow changes, explicit security boundaries and evidence-backed claims. Do not label inferred behavior as observed, observed behavior as brokered, or brokered behavior as isolated.

## Development requirements

- Rust **1.89 or newer**; CI verifies the declared MSRV separately from stable Rust.
- A platform toolchain capable of building Rust dependencies used by the workspace.
- Git for patch/provenance integration tests.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --release
```

For behavior changes, add a focused regression test that fails before the fix when practical. For security-sensitive changes, describe the enforcement boundary and add an adversarial case in `proofdrift-bench` when applicable.

## Pull request expectations

- Explain the user-visible or security-relevant behavior being changed.
- Keep generated files and `Cargo.lock` synchronized with manifest changes.
- Update `CHANGELOG.md` for release-visible behavior.
- Update `proofdrift-spec` when a public wire contract changes; document compatibility or migration impact.
- Do not weaken required CI, redaction, fail-closed behavior or evidence semantics merely to make a test pass.
- Do not add real secrets, private repository data, build output, local databases or machine-specific paths.

## Repository scope

The main repository owns executable behavior. Public data contracts belong in `proofdrift-spec`; adversarial corpus and benchmark changes belong in `proofdrift-bench`. Cross-repository changes should preserve compatibility where possible and make version transitions explicit.

## Security reports

Do not open a public issue for a vulnerability that could expose users. Follow [SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting.
