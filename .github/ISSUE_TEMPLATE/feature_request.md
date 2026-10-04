---
name: Feature Request
about: Suggest a new feature or improvement for pkinative-cli
title: ''
labels: enhancement
assignees: ''
---

<!-- pkinative-cli exposes what the pkinative library already does; it adds no
     PKI logic of its own. Requests for what pkinative refuses by doctrine are
     closed: network fetching (CRLs, OCSP, AIA, timestamps), key generation,
     writing PKCS#8 or PKCS#12, and legacy PKCS#12 ciphers. A request for a new
     engine capability belongs to https://github.com/Nizoka/pkinative/issues -->

## Problem

<!-- What problem does this feature solve? What CLI workflow is currently painful? -->

## Proposed Solution

<!-- Describe the command, subcommand or flag you'd like, with an example
     invocation, and the standard (RFC, ITU-T) that defines the behaviour. -->

```
pkinative <command> [subcommand] --new-flag value
```

## The pkinative export it reaches

<!-- Name the export(s) of the pkinative library this feature calls
     (docs/data/core-exports.json lists every one and the command that reaches
     it today). A feature with no export behind it is an engine request. -->

## Alternatives Considered

<!-- Any alternative approaches, workarounds, or existing tools you've considered? -->

## Additional Context

<!-- Examples, related issues, the pkinative release that added the export, etc. -->
