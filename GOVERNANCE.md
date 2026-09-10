# Governance

ProofDrift is currently maintained by `@WahuVN` with an evidence-first review policy.

## Decision model

- Public behavior changes are reviewed through pull requests and must pass required CI.
- Security claims require a concrete enforcement boundary and regression evidence.
- Wire-format changes are coordinated with `proofdrift-spec`; adversarial cases belong in `proofdrift-bench`.
- Breaking pre-1.0 changes are allowed when necessary, but require changelog and migration notes.
- Security embargoes may temporarily keep vulnerability details private until a fix or advisory is ready.

## Maintainer responsibilities

Maintainers keep required checks meaningful, avoid silently weakening security boundaries, disclose important release limitations, and separate project decisions from benchmark results or marketing claims.

## Contributor path

Contributors can start with issues, documentation, fixtures or focused fixes. Repeated high-quality contributions may lead to delegated review/triage permissions as the community grows. Governance will be revised before granting merge or release authority to additional maintainers.

## Conflicts of interest

Contributors and maintainers should disclose material conflicts when reviewing security products, benchmark results or integrations in which they have a financial or organizational interest.
