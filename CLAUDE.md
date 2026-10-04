@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies. This file adds only what is specific to Claude Code sessions in this repository.

## Token discipline

- Run tests through `npm run gate:fast` or `npx vitest run <file>` (dot reporter); never paste a test run or a gate log into context — open `test-output/.gate/<step>.log` only for the failing step.
- Never Read `coverage/`, `dist/`, `test-output/`, `node_modules/`, `package-lock.json`, `docs/data/pkinative/api.frozen.json` — generated or vendored: query them with `node -e`.
- Read README.md, SECURITY.md and docs/KNOWLEDGE_BASE.md by section (`grep -n "^## "`, then a line range); CHANGELOG.md: only the top entry.
- Open the ONE `.github/instructions/*.md` for the area you touch (AGENTS.md §Where is what); the matching `.claude/rules/*.md` loads itself when you read a file in scope.

## Windows

- vitest needs the repository path with an upper-case drive letter (`D:\Github\pkinative-cli`); from a lower-case `d:` it reports "no tests".
- PowerShell swallows a bare `--` after `npm run`: call `npx tsx scripts/gate.ts --fast` rather than `npm run gate -- --fast`.
- OpenSSL from Git for Windows writes CRLF; the fixtures are stored LF (`scripts/fixtures/make-test-pki.sh` normalises them).

## Hooks and permissions in force

- `.claude/hooks/guard.mjs` (PreToolUse on **Bash and PowerShell**) denies `npm publish`/`unpublish`/`deprecate`/`dist-tag`/`version <bump>`, `gh pr|issue create|edit|close|comment`,
  `gh release`, writing `gh api`, any `git push` and `git tag <name>` — the maintainer's acts (.github/AGENT_RULES.md): prepare, then stop.
- No `Co-Authored-By` trailers (`attribution.commit` is `""`).

## Rules

- `.claude/rules/*.md` are generated from `.github/instructions/*.instructions.md` by `npm run agents:rules`. Never edit a rule: edit the instruction file, then regenerate.
- Plans name the files, the commands and the expected gate outcome, and summarise gate output.
