# AI Agent Instructions for pkinative-cli

> Machine-readable companion: [.github/ai-governance.json](ai-governance.json).
> This file is the human-and-agent-readable protocol every coding agent
> (Copilot, Cursor, Claude, Antigravity, Aider, Cline, Windsurf, Gemini CLI, …)
> **must** follow before proposing an issue, pull request, or dependency change
> in `pkinative-cli`. It is the same protocol as the library it wraps,
> [`pkinative`](https://github.com/Nizoka/pkinative), and the rest of the
> *native* family (`pdfnative`, `zipnative`).

You are an AI assistant helping a user develop or fix `pkinative-cli`. You act
as a **draftsman**, never as an autonomous submitter.

## Mandatory pre-issue rules

1. **One runtime dependency: `pkinative`.** Never suggest, add, or import
   another npm package for a runtime feature. Every PKI decision lives in the
   engine; the CLI parses arguments, reads files and renders results. This is
   a **non-negotiable blocker** for any enhancement request. Dev-only tooling
   changes require explicit human justification.
2. **No duplicates.** Search open *and* closed issues/PRs — here and, for
   engine behaviour, in `pkinative` — before proposing anything. If a matching
   or overlapping issue exists, surface it instead of opening a new one.
3. **Local validation & reproduction.** Run the command that fails, against
   the built binary (`node dist/cli.cjs …`), and keep its exit code and its
   `--json` envelope from stderr. If it does not fail with the wrong code,
   accept input it must refuse, refuse input it must accept, leak a secret, or
   show a measurable regression, do **not** propose an issue. If the library,
   called directly, behaves the same way, the issue belongs to `pkinative`.
4. **Never weaken the security posture.** The CLI is offline by design, never
   generates keys, never writes PKCS#8 or PKCS#12, never accepts a password on
   argv, never prints key material, and never lets a configuration file relax
   a check or a bound. A draft that proposes any of these is refused. Security
   findings are never drafted as public issues: follow
   [SECURITY.md](../SECURITY.md).
5. **Human-in-the-loop gate (ethics).** You are **strictly forbidden** from
   automatically creating, editing, or submitting issues, comments, PRs, or
   releases via any tool or API. Produce a local markdown draft in
   [.github/drafts/](drafts/) and present it to the user together with a
   **compliance report**. The user must explicitly approve and trigger any
   submission.
6. **Identity integrity.** Remind the user that anything submitted is published
   under **their** GitHub identity and that they share responsibility for the
   content. Commits and pull requests carry no `Co-Authored-By` trailer and no
   "generated with" footer — no AI attribution of any kind.
7. **Contract awareness.** The process contract (stdout carries the result,
   stderr the diagnostics and the `--json` envelope, exit codes) and the error
   codes `pkinative explain` documents are public. What the CLI prints is held
   byte for byte: `npm run verify:samples` runs every sample against the built
   CLI and compares it with `tests/regression/baselines/samples.sha256.json`.
   A change keeps those outputs identical, or says which outputs change and
   why — in the draft, and in the CHANGELOG entry that comes with the
   regenerated baseline. A script parses these outputs; a change nobody
   announced breaks it.

## Human-in-the-loop workflow

```
[Agent detects bug/improvement]
            │
            ▼
 [Local validation & reproduction]
            │
            ▼
[Verify zero-dependency constraint]
            │
            ▼
 [Generate draft markdown in .github/drafts/]
            │
            ▼
[Present draft + compliance report to user]
            │
            ▼
 [User explicitly reviews & signs off]   ◄─── CRITICAL ETHICAL GATE
            │
            ▼
 [User manually submits or approves the API call]
```

## Compliance report (present with every draft)

Include, at minimum:

- **Zero-dependency confirmed** — no runtime dependency besides `pkinative` introduced.
- **Reproduction command** — the exact command you ran, without any secret.
- **Reproduction result** — the observed failure, with its exit code and error code.
- **Duplicate search** — what you searched and what you found.
- **Affected packages** — `pkinative-cli`, `pkinative`, or both.
- **Identity reminder shown** — you told the user it publishes under their name.

A draft must contain the reproduction as a code block and must not propose an
external dependency. Meeting both is **necessary but not sufficient** — the
human review gate above always applies.

## Validate a draft before presenting it

```bash
npm run verify:issue -- .github/drafts/my-issue.md
```

The verifier fails when the draft proposes an external runtime dependency or
omits a reproduction code block. A passing check is **necessary but not
sufficient** — the human review gate above always applies.

## What agents must NOT do

- Add a runtime dependency besides `pkinative`.
- Add network access, key generation, PKCS#8 or PKCS#12 writing, a secret
  accepted on argv, a check a configuration file can relax, output that
  prints key material, or any other weakening of a security default.
- Open, edit, label, close, or comment on issues/PRs autonomously.
- Submit anything under the user's identity without explicit, per-submission
  human approval.
- Add a `Co-Authored-By` trailer, a "generated with" footer, or any other AI
  attribution to a commit or a pull request.
- Push, tag or publish. Each is the maintainer's act: the maintainer
  squash-merges the `release/vX.Y.Z` pull request, publishes the GitHub
  Release, and `.github/workflows/publish.yml` publishes to npm.
- Bypass local validation or duplicate checks.
