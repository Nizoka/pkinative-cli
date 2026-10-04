# Ledger and verdict formats

Everything lives under `.audit/<version>/` (git-ignored). Plain Markdown, one table per file, so review and grep both work.

## Finding format (auditors)

One row per claim or surface, including the ones that hold:

| id | severity | claim / surface | evidence command | observed | expected | status |
|---|---|---|---|---|---|---|
| A-03 | major | "a password is never accepted on argv" | `node dist/cli.cjs p12 open x.p12 --password s --json` | exit 2, `--password is refused` | exit 2 before any read | holds |
| B-07 | blocker | `cert create --help` describes `--days` | `node dist/cli.cjs cert create --help` | absent | present | finding |

- `id` — `A-`, `B-`, `D-` (autonomy pass) or `V-` (raised by a verifier), zero-padded to two digits.
- `severity` — `blocker` (a shipped claim is false, a secret leaks, a check can be relaxed, a public surface is wrong, a gate would fail, the publish job would fail), `major` (a user or an agent is misled, no test catches it), `minor` (wording, ordering, a stale example that still behaves), `note` (observation, no action).
- `evidence command` — the exact command; the verifier re-runs it verbatim. A row without one is `unverified`.
- `status` — `holds`, `finding`, `unverified`.

## Verifier format

The auditor table plus two columns:

| … | stamp | justification |
|---|---|---|
| … | CONFIRMED | re-ran the command; the flag is parsed at src/commands/registry.ts:84 and absent from the help block |
| … | DOWNGRADED → minor | real, but `tests/docs/usage.test.ts` fails on it — cannot ship silently |
| … | REJECTED | the flag is described under the shared signing options; the help block lists it |
| … | DUPLICATE of B-02 | same missing sentence, different subcommand |

## Ledger (`ledger.md`)

Only `CONFIRMED` and `DOWNGRADED` findings, sorted by severity then id, with two more columns:

| id | severity | claim / surface | evidence command | fix | waiver |
|---|---|---|---|---|---|

- `fix` — the commit hash that resolved it, or `open`.
- `waiver` — empty, or the maintainer's one-line reason for shipping with it (only `major` and below may be waived).

Above the table: the tally per severity and per stamp, the previous tag, the HEAD hash audited, the pkinative version the release is built on, and the date.

## Verdict (`verdict.md`)

```
Verdict: GO | NO-GO
Release: v<version>   HEAD: <hash>   Previous: <tag>   Engine: pkinative <version>   Date: <YYYY-MM-DD>
Blockers open: <n>   Majors open: <n>   Waived: <n>
Findings: <confirmed> confirmed, <downgraded> downgraded, <rejected> rejected, <duplicate> duplicate
Next: <the one command the maintainer runs next — the fix loop, or the gate>
```

Then the open blockers, one per line, each with its evidence command.
