---
status: accepted
date: 2026-10-05
since: 1.0.0
---

# The configuration file is presentation only

## Context and Problem Statement

`.pkinativerc.json` is found by walking up from the working directory, so a user who runs the CLI inside a cloned repository reads a file somebody else wrote.
The first design refused a deny-list of keys (`--allow-*`, `--max-*`, `--ber`, `--pem-mode`, `--overwrite`, passwords) and accepted every other flag.
The pre-release audit of 1.0.0 showed that this was not enough. A planted file could:
- supply the trust anchors and the untrusted pool;
- move the validation instant;
- switch signature checking off;
- widen a CRL or OCSP tolerance;
- trust any OCSP responder;
- replace the input the user named.

As a result, a forged or a revoked certificate passed `chain verify` (findings A-01 and V-01). A deny-list fails open: every flag added later is accepted until somebody remembers to list it.

## Decision Outcome

- **An allow-list, `CONFIG_KEYS`.** A configuration file may set `json`, `pretty`, `quiet`, `no-color`, `format`, `encoding`, `fields`, `summary` and `strict`. These are how a result is shown, plus `strict`, which only tightens a check.
  - Any other key, at the top level or in a section, is `E_USAGE` with exit 2. This includes every flag added after this decision.
  - `tests/utils/config.test.ts` derives the refused list from the registry, so a new flag is covered without being named.
- **Defaults apply only where they mean something.** A key is applied only when the invoked subcommand declares the flag; elsewhere it is ignored. Sections may name a command (`"cert"`) or a subcommand (`"cert inspect"`), and the most specific section wins.
- **Visibility.** When a file supplied a default:
  - the `--json` envelope carries `config: <path>`, on success and on failure;
  - the text mode prints `note: defaults from <path>` on stderr, unless `--quiet`.
- **Bounded read.** Only a regular file is read, and its size is checked against 1 MiB before it is read.

### Consequences

- Good: no file in a working directory can change what a command reads, what it trusts, when it judges, what it tolerates or where it writes. The boundary is closed by default, and new flags inherit it.
- Bad: inputs and policy cannot be shared through the configuration file. Teams put them in the script that calls the CLI, where they are visible in review.
