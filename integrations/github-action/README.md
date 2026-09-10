# ProofDrift GitHub Action

The composite action runs ProofDrift scan and patch-impact checks against the caller's checked-out repository. It is **report-only by default** and installs the Rust toolchain it needs before building the pinned ProofDrift source from the selected ref.

It does not close pull requests, push commits, upload source, or mutate repository contents. JSON reports remain in the job's temporary directory unless the caller explicitly uploads or parses them.

## Usage

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v7
    with:
      fetch-depth: 2

  - id: proofdrift
    uses: WahuVN/proofdrift/integrations/github-action@v0.0.2
    with:
      base: ${{ github.event.pull_request.base.sha }}
      head: ${{ github.sha }}
      strict: 'false'

  - name: Upload ProofDrift reports
    uses: actions/upload-artifact@v7
    with:
      name: proofdrift-reports
      path: |
        ${{ steps.proofdrift.outputs.scan-report-path }}
        ${{ steps.proofdrift.outputs.patch-report-path }}
```

For higher supply-chain assurance, pin ProofDrift and third-party actions to reviewed full commit SHAs rather than mutable tags.

## Modes

- `strict: 'false'`: report-only. ProofDrift exit codes are exposed as outputs but do not fail the action step.
- `strict: 'true'`: propagate non-zero scan/patch risk exit codes and use the action as a CI gate.
- Any other `strict` value fails immediately with exit code `64` instead of silently falling back to report-only mode.

Outputs are `scan-exit-code`, `patch-exit-code`, `scan-report-path`, and `patch-report-path`.

The action is an integration surface, not an OS sandbox. Its reports inherit the same L0/L1/L2/L3 claim boundaries documented in the main project.
