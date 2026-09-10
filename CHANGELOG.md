# Changelog

All notable public changes to ProofDrift are documented here. The project follows Semantic Versioning while the public API is still pre-1.0.

## [0.0.2] - 2026-09-10

### Added
- Self-contained composite GitHub Action with report-path outputs and CI smoke coverage.
- Automated tag release pipeline with platform archives, SHA-256 checksums, SPDX JSON SBOM generation and GitHub build-provenance attestations.
- Public roadmap, support policy, governance notes and release procedure.

### Changed
- GitHub Actions are pinned to full commit SHAs.
- MSRV installation now uses an explicit `toolchain: 1.89.0` input so dependency automation cannot mistake the Rust version for an action version.
- Release packaging is deterministic in naming and idempotent on workflow re-runs.

## [0.0.1] - 2026-09-10

### Added
- Initial public preview with discovery, admission scanning, capability modeling, Cedar policy evaluation, L1 process brokering, tamper-evident evidence, patch/test proof, provenance adapters and a 160-case public security corpus.
- Linux x64, Windows x64 and macOS ARM64 preview binaries with SHA-256 checksums.

[0.0.2]: https://github.com/WahuVN/proofdrift/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/WahuVN/proofdrift/releases/tag/v0.0.1
