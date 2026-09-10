# Summary

AI 4 completed the CLI / integration / DX hardening work on branch `ai4-integration-dx` in the isolated worktree `D:\Code\ProofDrift-public-20260910\proofdrift-ai4-integration-dx`, based on commit `c62bee7`.

The main changes are:

- Added deterministic CLI configuration with precedence `CLI > PROOFDRIFT_* environment > config file > built-in defaults`.
- Added `--config`, `--output human|json`, `proofdrift config validate`, and `proofdrift config show` while keeping `--json` backward-compatible.
- Split CI-relevant exit classes: `0 pass`, `1 tool/child error`, `2 warn/findings`, `3 block/deny`, `4 verification failure`, `5 unsupported`, `64 invalid CLI/config`.
- Made explicit JSON mode machine-readable on error paths, including CLI parse/config failures, with stable error codes and actionable hints.
- Made policy deny / approval-required paths emit structured JSON in JSON mode rather than mixing human stderr with machine output.
- Added fail-closed TOML config parsing, bounds validation, CRLF coverage, environment precedence coverage, and unknown-key rejection.
- Hardened the composite GitHub Action so invalid `strict` values fail early instead of silently behaving as report-only.
- Added user-facing config documentation and a complete example config.
- Kept the original dirty `feature/complete-product-loop` worktree untouched by doing all AI 4 work in a dedicated worktree/branch.

# Files changed

- `Cargo.lock` — records the existing workspace `toml` crate as a direct CLI dependency.
- `README.md` — documents CLI config, precedence, JSON failure behavior, and reliable exit classes.
- `apps/proofdrift-cli/Cargo.toml` — adds `toml.workspace = true`.
- `apps/proofdrift-cli/src/config.rs` — new typed config loader/resolver/validation layer.
- `apps/proofdrift-cli/src/main.rs` — CLI options, config commands, exit taxonomy, structured error handling, resolved run configuration, structured deny/approval output.
- `apps/proofdrift-cli/tests/cli_dx.rs` — new end-to-end binary tests.
- `examples/proofdrift.config.toml` — new copyable config example.
- `integrations/github-action/action.yml` — validates `strict` input exactly.
- `integrations/github-action/README.md` — documents invalid `strict` failure behavior.
- `BAO_CAO_AI4.md` — this report.

# Tests added

`apps/proofdrift-cli/tests/cli_dx.rs` adds four E2E tests that execute the built CLI binary:

1. `json_cli_parse_error_is_machine_readable_and_uses_config_exit_class`
   - malformed CLI usage with `--json` returns valid JSON on stdout;
   - exit code is `64`;
   - error kind/code are stable;
   - stderr remains empty.
2. `missing_explicit_config_fails_early_with_actionable_json`
   - missing `--config` path fails before command work starts;
   - error is machine-readable and names the bad path.
3. `config_file_accepts_crlf_and_environment_overrides_file_values`
   - CRLF TOML is accepted;
   - environment overrides file values;
   - config-selected JSON output is honored.
4. `unknown_config_keys_fail_closed`
   - unknown TOML keys are rejected rather than silently ignored.

Two focused unit tests were also added in `config.rs` for output modes, unknown fields, and invalid limits.

# Commands run + exact result

Environment note: plain Cargo initially could not find the MSVC linker. The machine already had Visual C++ Build Tools at `D:\BuildTools`; validation was therefore run after `call D:\BuildTools\VC\Auxiliary\Build\vcvars64.bat`.

- `cargo check --locked -p proofdrift-cli --all-targets`
  - result: **PASS, exit 0** after loading the VS build environment.
- `cargo test --locked -p proofdrift-cli`
  - result: **PASS, exit 0**;
  - CLI unit tests: **10 passed, 0 failed**;
  - CLI E2E tests: **4 passed, 0 failed**.
- `cargo clippy --locked -p proofdrift-cli --all-targets -- -D warnings`
  - result: **PASS, exit 0**.
- `cargo test --locked --workspace`
  - result: **PASS, exit 0**;
  - **208 non-doc tests passed, 0 failed** across the workspace; doc-test groups also completed successfully.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
  - result: **PASS, exit 0**.
- `rustfmt --edition 2021 --config skip_children=true --check apps/proofdrift-cli/src/main.rs apps/proofdrift-cli/src/config.rs apps/proofdrift-cli/tests/cli_dx.rs`
  - result: **PASS, exit 0**.
- `git diff --check`
  - result: **PASS, exit 0**; only Git newline-conversion notices for pre-existing CRLF working-copy files were printed.
- `target\debug\proofdrift.exe --json config show`
  - result: **PASS, exit 0**;
  - emitted valid JSON showing defaults: `safe-local-dev`, `300000 ms`, `4194304 bytes`.
- `target\debug\proofdrift.exe --json scan --definitely-invalid`
  - result: **expected config failure, exit 64**;
  - emitted one valid JSON error object to stdout with `kind=config_error`, `code=PD_CLI_CONFIG`; stderr empty.
- `target\debug\proofdrift.exe --help`
  - result: **PASS, exit 0**;
  - help shows `config`, `--output`, `--config`, precedence, and exit-class documentation.

A full `cargo fmt --all -- --check` was also attempted and returned exit 1 because the baseline repository contains many untouched Rust files with CRLF while `rustfmt.toml` requires `newline_style = "Unix"`. AI 4 intentionally did not rewrite those files because they are outside this agent's assigned scope and would create broad cross-agent conflicts. All Rust files modified/created by AI 4 pass the scoped rustfmt check above.

# Public API/schema changes

No ProofDrift evidence/spec schema was changed.

CLI surface additions:

- new global `--config <PATH>`;
- new global `--output human|json`;
- existing `--json` retained as a compatible shorthand;
- new `proofdrift config validate`;
- new `proofdrift config show`;
- new optional `.proofdrift/config.toml` configuration surface;
- new supported environment variables:
  - `PROOFDRIFT_CONFIG`
  - `PROOFDRIFT_OUTPUT`
  - `PROOFDRIFT_POLICY`
  - `PROOFDRIFT_TIMEOUT_MS`
  - `PROOFDRIFT_MAX_OUTPUT_BYTES`.

Behavioral contract change:

- invalid CLI/config input now exits `64` instead of being conflated with generic exit `1`;
- explicit JSON mode now guarantees structured error output for CLI/config/application failures handled by the CLI;
- invalid GitHub Action `strict` values now fail with `64` instead of silently acting as report-only.

# Compatibility risks

- Scripts that assumed every non-policy CLI/config failure returned exit `1` must recognize exit `64` as configuration/input failure. This is intentional so CI can distinguish tool failure from bad configuration.
- Scripts that assumed the exit-code universe was only `0..5` need to allow `64`.
- `#[serde(deny_unknown_fields)]` intentionally makes config typo/forward-key handling fail closed. This is safer for CI, but consumers must remove unsupported keys rather than expecting them to be ignored.
- `--json` remains supported, so existing successful JSON consumers keep their current entry point. Error JSON is additive behavior.
- No cross-repo evidence/schema names or the six shared drift classes were renamed or modified.

# Known remaining issues

- Repository-wide `cargo fmt --all -- --check` has a pre-existing CRLF/Unix newline mismatch across many untouched Rust files. Resolving that should be coordinated as a repository-wide formatting change, not mixed into AI 4's CLI branch.
- The GitHub composite action was validated by source review and the repository already has an `action-smoke` job, but this local Windows session cannot reproduce a hosted GitHub Actions runner invocation. The Rust workspace and CLI E2E behavior itself are fully validated locally.
- The assignment's existing MCP CLI still correctly reports that a production stdio/HTTP transport is unsupported until a concrete transport is wired. AI 4 did not falsely upgrade that enforcement claim.

# Merge notes

- Branch: `ai4-integration-dx`.
- Base: `c62bee7` (`v0.0.2` / current main at worktree creation time).
- Worktree: `D:\Code\ProofDrift-public-20260910\proofdrift-ai4-integration-dx`.
- The original worktree on `feature/complete-product-loop` had unrelated uncommitted CLI/runtime/MCP changes and was left untouched.
- Expected conflict hotspot: `apps/proofdrift-cli/src/main.rs` if another branch also changes the CLI. Preserve AI 4's config resolution, structured error path, and exit taxonomy when resolving.
- `runtime_cli.rs` is intentionally unchanged from the base in the final AI 4 worktree.
- Review public contract/schema work from AI 2 and cross-repo gate work from AI 5 before changing any of these CLI wire/error conventions during final integration.

# Score before/after theo thang 10 va bang chung

**AI 4 scope before: 8.2/10.** The CLI already had useful commands, human/JSON success output, runtime evidence, and a GitHub Action, but configuration was effectively hard-coded, config precedence was absent, invalid configuration/tool errors shared exit `1`, and `--json` failures could fall back to plain stderr.

**AI 4 scope after: 9.7/10.** Evidence:

- deterministic, documented config precedence;
- fail-fast config validation with bounded values and unknown-key rejection;
- separate CI exit classes including `64` for configuration/input failures;
- machine-readable JSON failure behavior;
- structured deny/approval output;
- 6 new focused tests including 4 real-binary E2E cases;
- explicit CRLF config coverage;
- full workspace test pass with 208 non-doc tests and 0 failures;
- full workspace clippy with `-D warnings` passes;
- scoped rustfmt and `git diff --check` pass;
- GitHub Action no longer silently accepts invalid strict-mode configuration.

The remaining 0.3 is withheld because the pre-existing repository-wide newline mismatch prevents a clean full `cargo fmt --all -- --check` in this Windows checkout, and the hosted GitHub Actions smoke job itself was not run from this local session.
