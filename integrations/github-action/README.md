# ProofDrift GitHub Action

The action is **report-only by default**. It builds the local CLI, runs a workspace scan and patch-impact analysis, and writes a concise job summary. It never closes a PR, pushes commits, uploads source, or changes repository contents.

Set `strict: 'true'` only when the repository intentionally wants ProofDrift risk exit codes to fail the job. The caller controls whether JSON outputs are uploaded as artifacts.

```yaml
- uses: WahuVN/proofdrift/integrations/github-action@<pinned-ref>
  with:
    base: ${{ github.event.pull_request.base.sha }}
    head: ${{ github.sha }}
    strict: 'false'
```

Pin the action to a reviewed commit or release tag once public releases exist. Until then this integration is source-only and not a published action claim.
