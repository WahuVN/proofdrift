# Discovery regression fixtures

This deterministic local corpus covers representative Claude Code, Codex, Gemini CLI, Cursor, OpenCode/common-agent and Microsoft APM configuration surfaces.

- `safe/` should produce no admission findings.
- `malicious/` contains synthetic, non-functional risk patterns that exercise the scanner rule families.
- `labels.json` is the expected rule-set oracle.
- `discover.expected.json` and `scan.expected.json` are normalized contract examples. `<ROOT>` is a deliberate redaction placeholder.

No command in this fixture tree should be executed during discovery or scanning. Token-looking values are synthetic test data only.
