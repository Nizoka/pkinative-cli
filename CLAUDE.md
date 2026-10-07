@AGENTS.md

# Claude Code addendum

Everything in AGENTS.md applies; this file holds only what is specific to Claude Code sessions in this repository.

- Run tests through `npm run gate:fast` or `npx vitest run <file>` (dot reporter); never paste a run into context. A failing gate step already prints the last 15 lines of its log; `test-output/` is denied to Read.
- `permissions.deny` refuses Read on `coverage/`, `dist/`, `test-output/`, `node_modules/`, `package-lock.json` and `docs/data/pkinative/api.frozen.json` (generated or vendored): query them with `node -e`.
- Read README.md, SECURITY.md and docs/KNOWLEDGE_BASE.md by section (`grep -n "^## "`, then a line range); CHANGELOG.md: only the top entry.
- Area rules `.claude/rules/*.md` load themselves when you read a file in their `paths`; do not open `.github/instructions/` (the same text), and never edit a rule: edit the instruction file, then `npm run agents:rules`.
- `.claude/hooks/guard.mjs` (PreToolUse on `Bash|PowerShell`) denies the maintainer's acts — publishing, pushing, tagging, `gh` writes (.github/AGENT_RULES.md): prepare, then stop. Attribution is off (`attribution.commit` is `""`): no `Co-Authored-By` trailer.
- Plans name the files, the commands and the expected gate outcome, and summarise gate output.
