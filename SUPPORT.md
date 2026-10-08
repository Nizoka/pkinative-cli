# Support

Thanks for using **pkinative-cli**! Here is where to get help depending on what you need.

## :wrench: Help yourself first

Two commands answer most questions without leaving the terminal, offline:

- **`pkinative doctor`** — the CLI version, the pkinative engine it runs on, the Node.js runtime and whether it meets the security floor, and what the runtime's Web Crypto can verify, sign and decrypt. Add `--json` for a machine-readable report.
- **`pkinative explain <code>`** — what an error code means and the remedy for it. Every failure prints its code; with `--json`, the envelope on stderr carries it.

`pkinative --help` and `pkinative <command> --help` describe every command and flag.

## :books: Documentation

- **Quick start & command reference:** [README.md](./README.md)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)
- **The engine:** [pkinative](https://github.com/Nizoka/pkinative) — the library every verdict comes from, with its guides, error codes and security model.

## :question: Questions, bugs & feature requests

- **GitHub Issues** — [github.com/Nizoka/pkinative-cli/issues](https://github.com/Nizoka/pkinative-cli/issues) — the one public channel for the CLI.
  Use it for how-to questions too: most of them are a documentation gap, and an issue is where that gets fixed.
  Before opening an issue, please:
  1. Search existing issues — it may already be reported or resolved.
  2. Reproduce on the latest release on npm.
  3. Include the **exact command line** (without any password or key material), the **error code** and, ideally, the `--json` envelope printed on stderr, plus the output of `pkinative doctor --json`.
  4. Attach the certificate or DER blob when relevant — **never a private key, a PKCS#12 file or a password**. Public certificates only; redact anything confidential.

Templates are provided for bug reports, feature requests, interoperability reports and maintenance tasks.

## :gear: CLI or engine?

pkinative-cli parses arguments, reads files and renders results; every PKI decision — decoding, path building, signature and revocation verdicts, the error codes themselves — is made by the `pkinative` library. If the library, called directly, behaves the same way as the CLI, the issue belongs to the engine: report it at [github.com/Nizoka/pkinative/issues](https://github.com/Nizoka/pkinative/issues). If unsure, open it here; it will be moved.

## :lock: Security vulnerabilities

**Do not open public issues for security problems.**

Report them privately through GitHub private vulnerability reporting:
[github.com/Nizoka/pkinative-cli/security/advisories/new](https://github.com/Nizoka/pkinative-cli/security/advisories/new).
See [SECURITY.md](./SECURITY.md) for the disclosure procedure and the handling timeline.

## :handshake: Contributing

Interested in contributing? Start with [CONTRIBUTING.md](./CONTRIBUTING.md) and our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## :warning: What is *not* supported

- **Private email support** — we do not offer one-on-one support; please use the public issue tracker above so the whole community benefits.
- **Commercial SLAs** — pkinative-cli is MIT-licensed open source with no warranty. Consider sponsoring or contributing patches if you rely on it heavily.
- **Network features** — the CLI is offline by design: it never fetches a CRL, an OCSP response, a timestamp or an intermediate certificate. Fetch them with another tool and pass the files.
- **Node.js versions outside `engines`** — the supported range is the one declared in `package.json` (`engines.node`), which `pkinative doctor` checks; anything below it is not supported.

## :sparkles: Sponsor

If pkinative-cli saves you time or money, consider starring the repo or
[sponsoring via GitHub Sponsors](https://github.com/sponsors/Nizoka). Every bit helps
keep development sustainable.
