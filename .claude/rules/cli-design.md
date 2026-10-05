---
paths:
  - "src/cli.ts"
  - "src/bin.ts"
  - "src/context.ts"
  - "src/utils/args.ts"
  - "src/utils/agent.ts"
  - "src/utils/config.ts"
  - "src/utils/output.ts"
  - "src/utils/projection.ts"
  - "src/utils/colors.ts"
---
<!-- GENERATED from .github/instructions/cli-design.instructions.md by scripts/build-claude-rules.ts — do not edit -->

# CLI design

## Dispatch

- `run(argv, io)` in `src/cli.ts` returns the exit code; it never calls `process.exit`. `src/bin.ts` is the only file that touches the process (EPIPE, signals, `process.exitCode`).
- The command and subcommand are located with the parser's own rules (`firstPositionalIndex`), so a flag value is never mistaken for a command. Global flags are accepted before or after the command.
- Every flag a command accepts is declared in `src/commands/registry.ts`; anything else is `E_USAGE` ("Unknown flag"). A flag is boolean or valued everywhere, never both.

## Output

- stdout: the artefact (`emitArtifact`: PEM, DER or hex; raw DER to a terminal is refused) or the report (`emitReport`: text, or JSON in the ADR 0018 wire form via `toWire`).
- `--json` (or `PKINATIVE_JSON=1`): the report is compact JSON; exactly one envelope goes to stderr: `{ ok: true, command, ...ctx.status, diagnostics }` or the failure envelope. Envelope fields are additive only.
- `--summary` swaps in the command's minimal shape; `--fields a,b.c` projects; `--pretty` indents. Text diagnostics print as `<severity> <code> at <path>: <message> (<standard>)` unless `--quiet`.

## Exit codes and errors

- 0 success; 1 any failure but usage; 2 `E_USAGE` only; 130/143 on SIGINT/SIGTERM. A negative verdict prints its report first, then fails with `E_VERIFY_FAILED` or `E_CHECK_FAILED` and the reasons in the envelope.
- `remedy` names the CLI flag that lifts a refusal (`PKI_REMEDY`), never a library option.

## Configuration

- `.pkinativerc.json` (nearest upward, `--config`, `--no-config`) fills only flags not given, and only flags the invoked subcommand declares. It is presentation only (`CONFIG_KEYS`, ADR 0007): any other key, present or future, is `E_USAGE`, so a planted file never changes an input, trust, time, a bound or an output. The applied file is named in the envelope (`config`).
