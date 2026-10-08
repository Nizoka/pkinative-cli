# Release Notes Template

One file per published version: `release-notes/vMAJOR.MINOR.PATCH.md`. `scripts/release-prepare.ts` scaffolds it from the block below; fill the sections that apply and delete the others (never leave an empty section).

```markdown
# pkinative-cli vX.Y.Z

<!-- GitHub Release title: vX.Y.Z — short description -->

_Released YYYY-MM-DD · engine: pkinative ^A.B.C_

<!-- One paragraph: what the release is about, and the compatibility statement
     ("no command, flag, exit code or JSON member removed or renamed", or the
     exact list of what moved). -->

## Highlights

- ...

## Security

<!-- CWE, affected versions, mitigation. First when present. -->

- **fix(security):** ...

## Breaking Changes

<!-- What changed, why, the migration. A major release only. -->

- **BREAKING:** ...

## Added

- **feat(scope):** ...

## Changed

<!-- Includes every intended change of a sample's output, with the sample id. -->

- **refactor(scope):** ...

## Fixed

- **fix(scope):** ... ([#NN]).

## Engine

<!-- The pkinative range, and the exports, codes or diagnostics this release reaches for the first time. "unchanged" when the engine did not move. -->

## Install

\`\`\`bash
npm install --global pkinative-cli@X.Y.Z
npm audit signatures
pkinative doctor
\`\`\`

## Links

- [CHANGELOG](../CHANGELOG.md)
- [Full diff](https://github.com/Nizoka/pkinative-cli/compare/vA.B.C...vX.Y.Z)
```

## Conventions

- **GitHub Release title** `vX.Y.Z — short description`; the H1 here stays `# pkinative-cli vX.Y.Z`.
- **SemVer is about the process contract.** Commands, flags, exit codes, `E_*` classes and JSON members are the API: removing or renaming one is a major; adding one is a minor; a fix that leaves them alone is a patch. A pkinative minor adopted is a CLI minor.
- **Mirror `CHANGELOG.md`**: same bullets; the note adds the narrative.
- **Security first, with the CWE.** No emojis. Code blocks for commands only.
- **Install from npm**, never a git URL (a git checkout carries no `dist/`).
- A re-pinned sample is a changed output: name it under Changed with the reason.
