---
name: Interoperability report
about: A certificate, CSR, signature or request pkinative-cli WROTE that another tool will not read, or reads differently
title: '[interop] '
labels: interop
assignees: ''
---

<!-- This template is for the WRITE direction: bytes pkinative-cli produced
     (`cert create`, `csr create`, `cms sign`, `ocsp request`, `tsp request`,
     `pem encode`, `asn1 encode`, …) that something else cannot consume. If the
     problem is an input pkinative-cli cannot READ, use the Bug Report instead.
     When another tool refuses what pkinative-cli wrote, the bytes are ours and
     the defect is presumed ours until shown otherwise. The bytes come from the
     pkinative library: if the library writes the same bytes, the report will
     be moved to https://github.com/Nizoka/pkinative/issues -->

## The tool that disagrees

| | |
|---|---|
| Tool and version | <!-- `openssl version`, `keytool -help`, `python -c "import cryptography; print(cryptography.__version__)"` … --> |
| Operating system | |
| How it was invoked | <!-- the exact command, so anyone can repeat it --> |

## What pkinative-cli wrote

The command that produced it, short enough to run as-is (no password on the
command line, no private key pasted):

```
pkinative cert create …
```

`pkinative --version --json`:

```json
```

## What happened

- [ ] The tool **refused** the artefact outright
- [ ] The tool accepted it and read a field **differently** from pkinative-cli
- [ ] The tool accepted it and another tool refused it

The tool's own output, verbatim:

```
```

## What the standard says

The clause that decides it (`RFC 5280 §4.2.1.6`, `ITU-T X.690 §11.6`, …), and
the sentence itself. A disagreement between two implementations is not
settled by either of them:

## Does pkinative-cli read it back?

Inspecting what pkinative-cli wrote is the first thing to try, because a
writer whose own reader complains has written something someone else's reader
will refuse too:

```
pkinative cert inspect out.pem --json
```

- [ ] pkinative-cli reads it back with **no diagnostic**
- [ ] pkinative-cli reads it back and reports: <!-- the codes -->
- [ ] pkinative-cli refuses its own output <!-- always a bug, say so plainly -->

## The artefact

Attach the DER (or paste the PEM). **Do not attach anything containing a
private key**, even a test one: re-create the case with a key generated for
the report.
