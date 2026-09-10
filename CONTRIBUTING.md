# Contributing

Contributions are welcome. Keep changes deterministic, evidence-backed and narrow. Security claims require regression tests. Do not label inferred behavior as observed, or observed behavior as enforced.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --locked --workspace --release
```

For behavior changes, include a focused test that fails before the fix when practical. For security-sensitive changes, describe the enforcement boundary and add an adversarial regression case when applicable.

Do not add real secrets, private repository data, generated build output, local databases or machine-specific paths.

## Scope

The main repository owns executable behavior. Contract changes belong in `proofdrift-spec`; adversarial corpus and benchmark changes belong in `proofdrift-bench`. When a change spans repositories, keep the wire-format change backward compatible or document the required version transition explicitly.
