# Third-Party Notices

pkinative-cli is licensed under the [MIT License](LICENSE). The published package contains only code written for this project: `dist/cli.cjs` bundles the CLI's own sources and keeps its one runtime dependency external.

## Runtime dependency (installed by npm, not bundled)

| Package | Version range | Source | Licence |
|---|---|---|---|
| pkinative | `^1.0.0` | https://github.com/Nizoka/pkinative | MIT |

pkinative itself has no runtime dependency. `npm ls --omit=dev --all` lists it alone.

## Development tools (never in the package)

The build, type-check, lint and test toolchain (TypeScript, tsup and esbuild, ESLint and typescript-eslint, Vitest and its V8 coverage provider, tsx, publint, `@types/node`) is declared in `package.json` `devDependencies`, pinned by `package-lock.json`, and is not part of what a user installs. The tree is under permissive licences (MIT, ISC, BSD-2/3-Clause, Apache-2.0, BlueOak-1.0.0, Python-2.0), except `lightningcss` and its platform binaries, which Vitest's bundler pulls in under MPL-2.0 and which are used unmodified at test time only. `dependency-review.yml` holds every new dependency to that allow-list and names the `lightningcss` exception package by package.

## Test material (in the repository, never in the package)

`tests/fixtures/pki/` is a test-only PKI produced by OpenSSL 3.5.5 (Apache-2.0) running `scripts/fixtures/make-test-pki.sh`; the files are this project's output, released under its MIT licence, and described in [tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md). Every private key there is public test material.

`docs/data/pkinative/` holds registries copied unmodified from pkinative's v1.0.0 tag (MIT, same author), so the CLI's tests can hold themselves to the engine version they target.
