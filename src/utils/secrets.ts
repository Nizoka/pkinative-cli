// Password intake. A password is never accepted as an argv value: argv is
// visible to every user of the machine (ps, /proc/<pid>/cmdline, shell
// history). Three sources only, at most one per invocation:
//   --password-file <file>   first line of the file (one trailing newline dropped)
//   --password-stdin         first line of stdin
//   PKINATIVE_PASSWORD       the environment variable
// The value is never written to stdout, stderr or an envelope.

import { getStringFlag, hasFlag, type ParsedArgs } from './args.js';
import { usageError } from './error.js';
import { readInput, type Io } from './io.js';

export const PASSWORD_ENV = 'PKINATIVE_PASSWORD';
const MAX_PASSWORD_BYTES = 64 * 1024;

/** The flags that look like a literal password and are therefore refused. */
const LITERAL_PASSWORD_FLAGS: readonly string[] = ['password', 'pass', 'passin', 'key-password'];

/**
 * Refuse `--password <value>` and its look-alikes before anything else runs,
 * and `--password-stdin=<value>`, which is a password typed on argv too; the
 * value is never echoed (audit A-19).
 */
export function assertNoLiteralPassword(args: ParsedArgs): void {
    for (const name of LITERAL_PASSWORD_FLAGS) {
        if (args.flags[name] !== undefined) {
            throw usageError(
                `--${name} is refused: a password on the command line is visible to every process on the machine.`,
                `--password-file <file> | --password-stdin | ${PASSWORD_ENV}`,
            );
        }
    }
    const stdinFlag = args.flags['password-stdin'];
    if (stdinFlag !== undefined && typeof stdinFlag !== 'boolean') {
        throw usageError('--password-stdin takes no value: the password is read from stdin, never from the command line.', `--password-stdin | --password-file <file> | ${PASSWORD_ENV}`);
    }
}

/** Whether any input of the invocation, other than the password itself, is read from stdin. */
function readsStdin(args: ParsedArgs): boolean {
    if (args.positionals.includes('-')) return true;
    return Object.entries(args.flags).some(([name, value]) =>
        name !== 'password-file' && (value === '-' || (Array.isArray(value) && value.includes('-'))));
}

function firstLine(bytes: Uint8Array): string {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return text.replace(/\r?\n[\s\S]*$/, '');
}

/**
 * Resolve the password, or `undefined` when no source is given. Two sources
 * at once is a usage error; so is --password-stdin when stdin already carries
 * the input object.
 */
export async function readPassword(io: Io, args: ParsedArgs, stdinTaken: boolean): Promise<string | undefined> {
    const file = getStringFlag(args.flags, 'password-file');
    const fromStdin = hasFlag(args.flags, 'password-stdin');
    const env = io.env[PASSWORD_ENV];
    const sources = [file !== undefined, fromStdin, env !== undefined && env !== ''].filter(Boolean).length;
    if (sources > 1) {
        throw usageError(`Give the password once: --password-file, --password-stdin or ${PASSWORD_ENV}, not several.`);
    }
    if ((fromStdin || file === '-') && (stdinTaken || readsStdin(args))) {
        throw usageError('The password cannot come from stdin when an input is read from stdin too; use --password-file <file> or PKINATIVE_PASSWORD.');
    }
    const limits = { what: 'password', maxBytes: MAX_PASSWORD_BYTES };
    if (file !== undefined) return firstLine(await readInput(io, file === '-' ? undefined : file, limits));
    if (fromStdin) return firstLine(await readInput(io, '-', limits));
    return env !== undefined && env !== '' ? env : undefined;
}
