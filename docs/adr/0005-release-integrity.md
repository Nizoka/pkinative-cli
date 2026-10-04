---
status: accepted
date: 2026-10-04
since: 1.0.0
---

# Release integrity: the bytes that passed the gate are the bytes published

## Context and Problem Statement

pkinative's 1.0.0 publish needed three runs: the workflow first ran on a tag push and found no Release to attach files to, and its build job lacked tools its own gate required. A CLI that ships to every developer machine needs the same guarantees from its first release.

## Decision Outcome

`publish.yml` starts on `release: published` and runs four jobs ([SECURITY.md §Release integrity](../../SECURITY.md#release-integrity)):
**guard** (the tag equals the version), **build** (the full publish gate with `--require-all`, OpenSSL installed; `npm pack` once; digests out),
**publish** (the `npm-publish` environment, a maintainer's approval, digests re-checked, an integrity-pinned npm client, provenance through Trusted Publishing)
and **attest** (the registry's bytes compared, `npm audit signatures`, SBOMs, a Sigstore attestation, all attached to the Release).
The job that holds `id-token` never runs the development toolchain. This is SLSA Build Level 2, as in pkinative's ADR 0019.

### Consequences

- Good: a consumer can verify provenance and the SBOM of the exact tarball they installed.
- Bad: a release needs the npm `pkinative-cli` package configured for Trusted Publishing and a protected environment, set once by the maintainer.
