# Releasing ProofDrift

Tagged releases are produced by `.github/workflows/release.yml`. Do not hand-build public binaries from an untracked workspace.

## Release checklist

1. Land changes through a PR with `ci-success` green.
2. Update `CHANGELOG.md` and the workspace version in `Cargo.toml`.
3. Confirm `cargo fmt --all -- --check`, strict Clippy, workspace tests and the declared MSRV pass.
4. Confirm the scheduled/manual security workflow is green.
5. Create an annotated `vX.Y.Z` tag from the intended `main` commit and push the tag.
6. Wait for all platform package jobs and the publish job to pass.
7. Verify the GitHub Release contains platform archives, `SHA256SUMS.txt` and the SPDX JSON SBOM.
8. Verify an archive attestation, for example:

```sh
gh attestation verify proofdrift-vX.Y.Z-linux-x64.tar.gz --repo WahuVN/proofdrift
```

## Release integrity

The tag workflow builds from the checked-out tag with `Cargo.lock`, creates platform archives, computes SHA-256 checksums, emits an SPDX JSON SBOM and publishes GitHub build-provenance attestations. These attestations establish provenance for the published artifacts; they are not platform code-signing certificates and do not by themselves prove software correctness.

Re-running the publish job is idempotent: an existing tag release is updated with `--clobber` rather than creating a second release.
