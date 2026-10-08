# Auditor A — claims versus code

You audit one release of pkinative-cli. Your angle is narrow on purpose: **is every claim the release makes true in the code that ships?** Another auditor covers the help text, the matrices and the release surfaces; do not spend time there.

## Inputs

- The release note (`release-notes/v<version>.md`) and the top entry of `CHANGELOG.md`.
- `git diff <previous-tag>..HEAD --stat` and the per-area diff for anything a claim points at (for a first release, the whole tree).
- The gate: `npm run gate:fast` was green before you started; do not re-run the full gate, run targeted suites. `dist/cli.cjs` is built (`npm run build` if `node dist/cli.cjs --version` fails).

## Method

1. Enumerate the claims. One line each: commands and subcommands, flags, envelope fields, exit codes, error mappings, refusals, limits, engine (pkinative) behaviour inherited, sample or baseline changes. Number them `A-01`, `A-02`, …
2. For each claim, locate the evidence: the command module (`src/commands/<name>.ts`), the helper (`src/utils/`), the engine symbol it reaches (`src/core-bridge/index.ts`), the test that proves it (`tests/commands/`, `tests/utils/`, `tests/integration/`, `tests/parity/`, `tests/interop/`, `tests/fuzz/`), the sample that demonstrates it (`samples/<command>/`).
3. **Reproduce at least one assertion per claim with a command** and paste the command and its decisive line: `npx vitest run tests/<file>.test.ts -t "<name>"`, `node dist/cli.cjs <command> … --json` (read the stderr envelope and the exit code), `npx tsx scripts/verify-samples.ts`. A claim you could only confirm by reading is `unverified`, and says so.
4. Check the negative space — each one with a command, not a reading:
   - "one runtime dependency" needs `npm ls --omit=dev --all` to list `pkinative` and nothing else, and `src/core-bridge/index.ts` to be the only module importing it (`git grep -n "from 'pkinative'" src/`).
   - "offline" needs a grep of `src/` for `node:http`, `node:https`, `node:net`, `node:dns`, `fetch(` and `WebSocket` to come back empty.
   - "no password on argv" needs `node dist/cli.cjs p12 open x.p12 --password secret --json` to exit 2 before reading any file; repeat for `--pass`, `--passin` and `--key-password`.
   - "a config file never relaxes a check" needs a scratch directory with a `.pkinativerc.json` setting `allow-sha1`, `max-content-size`, `ber`, `pem-mode`, `overwrite` and `password-file`, and a run of `chain verify` in it that is refused or ignores every one of them.
   - "secret-free key and p12 reports" needs `key inspect`, `key check`, `p12 inspect`, `p12 bags`, `p12 verify-mac` and `p12 open` run with a known password from `--password-file`, then a search of stdout and stderr (with and without `--json`) for the password, any PEM `PRIVATE KEY` block, and the hex of the private scalar or modulus prime.
   - "no key generation, no PKCS#8 or PKCS#12 writing" needs `git grep -n "generateKey\|exportKey('pkcs8'" src/` and the registry to list no such subcommand.
5. Check the release note's own bookkeeping: version in `package.json` and `package-lock.json`, the `pkinative` range in `dependencies`, `pkinative --version --json` printing both, the release title `release: v<version> — …`.

## Output

Write `.audit/<version>/auditor-a.md` using the finding format of `ledger.md`. Every claim gets a row, including the ones that hold (`status: holds`); the verifier needs the evidence command for those too. Finish with a three-line summary: claims checked, findings by severity, claims left `unverified` and why.

Do not fix anything. Do not push, tag or publish. Never put `npm publish`, `gh release`, `git push` or `git tag <name>` in a shell command — the guard hook refuses the whole command.
