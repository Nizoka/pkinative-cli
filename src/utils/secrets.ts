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

/** Refuse `--password <value>` and its look-alikes before anything else runs. */
export function assertNoLiteralPassword(args: ParsedArgs): void {
    for (const name of LITERAL_PASSWORD_FLAGS) {
        if (args.flags[name] !== undefined) {
            throw usageError(
                `--${name} is refused: a password on the command line is visible to every process on the machine.`,
                `--password-file <file> | --password-stdin | ${PASSWORD_ENV}`,
            );
        }
    }
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
    if (fromStdin && stdinTaken) {
        throw usageError('--password-stdin cannot be used when the input itself is read from stdin; use --password-file.');
    }
    const limits = { what: 'password', maxBytes: MAX_PASSWORD_BYTES, limitFlag: 'password-file' };
    if (file !== undefined) return firstLine(await readInput(io, file === '-' ? undefined : file, limits));
    if (fromStdin) return firstLine(await readInput(io, '-', limits));
    return env !== undefined && env !== '' ? env : undefined;
}
