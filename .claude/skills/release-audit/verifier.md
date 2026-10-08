# Verifier — adversarial re-derivation

You receive one or two auditor reports for a pkinative-cli release. Assume each finding is wrong until you have reproduced it yourself: auditors run at roughly 10 % false findings, and a false finding that reaches the ledger costs a fix loop or, worse, a waiver that hides a real one later.

## Method, per finding

1. Re-run the evidence command exactly as written. If it is missing, the finding is `REJECTED` (reason: no evidence) — do not invent one.
2. Read the cited lines yourself (`Read` with the offset, or `git show HEAD:<path>`), and the surrounding context the auditor may have skipped.
3. Decide the stamp:
   - `CONFIRMED` — the command and the lines say what the auditor says; severity stands.
   - `DOWNGRADED` — real, but the severity is too high (state the new one and why: not user-visible, already covered by a test, cosmetic).
   - `REJECTED` — does not reproduce, or the auditor misread the code, the help text or the test.
   - `DUPLICATE` — the same defect as another finding (name it); the earliest id keeps the row.
4. One line of justification per stamp, with the decisive observation. No paragraphs.

## Also check

- A finding that says "missing" for a file, a flag or a sentence: grep for it under a different name before confirming.
- A finding about a count or a matrix entry: recompute it (`npm run surface:build` then `git diff -- docs/data/core-exports.json tests/regression/engine-surface.json`).
- A finding about engine behaviour: call the pkinative export directly (`node -e` over `node_modules/pkinative`) before blaming the CLI; if the engine does the same, the finding is real but belongs to pkinative — say so in the justification.
- A finding about a secret in an output: re-run with a fresh password of your own, so a fixture string that happens to match is not mistaken for a leak.
- A `holds` row whose evidence command you cannot make pass is a new finding; add it with the prefix `V-`.

## Output

Write `.audit/<version>/verifier-<n>.md`: the auditor's table with a `stamp` and `justification` column added, then a tally per stamp and per severity. Finish with the list of `CONFIRMED` blockers, if any — that list is what Phase E reads first.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a shell command — the guard hook refuses the whole command.
