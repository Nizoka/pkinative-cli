// Hand-written help text, one block per command. tests/docs/usage.test.ts
// holds each block to the registry: every flag listed here is declared there
// and vice versa, boolean flags never show a <value>, lines stay ≤ 80 columns.

import { COMMANDS } from './registry.js';

export const GLOBAL_USAGE = `\
Global options (any command):
  --json            Agent mode: JSON report on stdout, one JSON envelope on
                    stderr ({ ok, command, ... } or { ok: false, error })
  --pretty          Indent JSON output
  --fields <a,b.c>  Keep only these dot-paths of a JSON report
  --summary         Print the command's minimal JSON shape
  --quiet,   -q     No notes or diagnostics on stderr (errors still print)
  --no-color        No ANSI colour (also NO_COLOR; FORCE_COLOR forces it)
  --dry-run         Validate everything, write nothing
  --strict          Escalate the first engine warning to E_CHECK_FAILED
  --ber             Accept BER as well as DER (common in CMS)
  --pem-mode <strict|lax>  PEM reading: RFC 7468 strict (default) or lax
  --allow-sha1      Accept SHA-1 signatures (legacy material you trust)
  --overwrite       Replace an existing --output file (atomic rename)
  --config <file>   Use this .pkinativerc.json (default: nearest upward)
  --no-config       Ignore any .pkinativerc.json
  --max-content-size <size>  Bound on content read whole (default 1 GiB)
  --max-<limit> <n>          The 22 pkinative limits, e.g. --max-input-bytes,
                    --max-depth, --max-chain-length (see: pkinative limits)

Exit codes:
  0  success                 1  failure (any E_* class but E_USAGE)
  2  usage error (E_USAGE)   130 / 143  interrupted by SIGINT / SIGTERM
                                        (a file being written is removed)

Environment:
  PKINATIVE_JSON=1      same as --json       PKINATIVE_QUIET=1  --quiet
  PKINATIVE_PASSWORD    password source (never accepted on the command line)
  PKINATIVE_DEBUG=1     stack traces on stderr
  NO_COLOR / FORCE_COLOR / TERM=dumb         colour of the text output
`;

/** The command list of the top-level help, grouped, derived from the registry. */
export function commandList(): string {
    const groups = new Map<string, string[]>();
    for (const c of COMMANDS) {
        const lines = groups.get(c.group) ?? [];
        lines.push(`  ${c.name.padEnd(12)}${c.summary}`);
        groups.set(c.group, lines);
    }
    const body = [...groups].map(([group, lines]) => ` ${group}\n${lines.join('\n')}`).join('\n\n');
    return `Commands (${COMMANDS.length}):\n\n${body}\n`;
}

export const USAGE = `\
pkinative-cli — Official CLI for pkinative (X.509, CMS, PKCS, ASN.1)

Usage:
  pkinative <command> [<subcommand>] [options]

${commandList()}
Options:
  --help,    -h   Show this help, or a command's help
  --version, -V   Show the version (with --json: CLI and engine versions)

${GLOBAL_USAGE}
Offline, always: no command opens a socket or fetches anything.
For autonomous/agent usage see AGENTS.md.
Run \`pkinative <command> --help\` for a command's options.
`;

const LIMITS_USAGE = `\
pkinative limits — The 22 pkinative security bounds

Usage:
  pkinative limits [--max-<limit> <n>]... [--format text|json]

Prints every bound of pkinative's DEFAULT_PKI_LIMITS with the flag that raises
it, its default, the effective value under the --max-* flags given, its CWE
and what it guards, plus the CLI's own --max-content-size.

Options:
  --format, -f <text|json>  Report format (json under --json)

Raise a bound only for input you trust; a config file can never raise one.
`;

export const COMMAND_USAGE: Readonly<Record<string, string>> = {
    limits: LIMITS_USAGE,
};
