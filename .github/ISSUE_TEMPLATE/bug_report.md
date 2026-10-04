---
name: Bug Report
about: Report a bug in pkinative-cli
title: ''
labels: bug
assignees: ''
---

<!-- Security problems (a secret printed or logged, a check a config file can
     relax, a crash or resource exhaustion on hostile input) are NOT reported
     here: follow SECURITY.md and use private vulnerability reporting.

     If the pkinative library, called directly, behaves the same way, the bug
     belongs to the engine: https://github.com/Nizoka/pkinative/issues -->

## Description

<!-- A clear description of the bug. -->

## Command Line

<!-- The exact command you ran. NEVER include a password, a private key or a
     PKCS#12 file: passwords go through --password-file, --password-stdin or
     PKINATIVE_PASSWORD, so they are not part of the command line anyway. -->

```
pkinative <command> [subcommand] [...flags]
```

## Expected Behavior

<!-- What should happen? -->

## Actual Behavior

<!-- What happens instead? Include the exit code, and the --json envelope the
     CLI prints on stderr (re-run with --json if needed). -->

```json
```

## Environment

<!-- Paste both outputs verbatim. -->

`pkinative --version --json`:

```json
```

`pkinative doctor --json`:

```json
```

- **OS:** <!-- Windows 11, macOS 15, Ubuntu 24.04, … -->
- **Node.js version:** <!-- `node --version` -->

## Inputs

<!-- Attach public certificates only (PEM or base64 DER) — never a private key,
     a PKCS#12 file or a password. Re-create the case with a key generated for
     the report if a key is involved. -->

## Additional Context

<!-- `openssl x509 -noout -text` output, the producer of the certificate, etc. -->
