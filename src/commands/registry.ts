// The single source of the CLI surface: every command, subcommand and flag.
// The parser (which flags are boolean), the unknown-flag refusal, the shell
// completions, the `schema manifest` subject and the docs-parity tests all
// derive from these tables. Pure data: no command code is loaded from here.

import { LIMIT_FLAG_NAMES } from '../utils/limits.js';

export interface FlagSpec {
    /** Long name, bare (no dashes). */
    readonly name: string;
    /** One-letter alias, bare. */
    readonly alias?: string;
    /** Value placeholder; absent for a boolean flag. */
    readonly value?: string;
    /** May be given several times. */
    readonly repeatable?: boolean;
}

export interface CommandSpec {
    readonly name: string;
    readonly group: CommandGroup;
    readonly summary: string;
    /** Subcommand names; empty when the command has none. */
    readonly subcommands: readonly string[];
    readonly flags: readonly FlagSpec[];
}

export type CommandGroup = 'Encodings' | 'Certificates' | 'Paths & revocation' | 'Signatures & time-stamps' | 'Keys' | 'Meta';

export const GLOBAL_FLAGS: readonly FlagSpec[] = [
    { name: 'help', alias: 'h' },
    { name: 'version', alias: 'V' },
    { name: 'json' },
    { name: 'pretty' },
    { name: 'quiet', alias: 'q' },
    { name: 'no-color' },
    { name: 'dry-run' },
    { name: 'strict' },
    { name: 'ber' },
    { name: 'pem-mode', value: 'strict|lax' },
    { name: 'allow-sha1' },
    { name: 'overwrite' },
    { name: 'config', value: 'file' },
    { name: 'no-config' },
    { name: 'fields', value: 'a,b.c' },
    { name: 'summary' },
    { name: 'max-content-size', value: 'size' },
    ...LIMIT_FLAG_NAMES.map((name) => ({ name, value: 'n' })),
];

const input: FlagSpec = { name: 'input', alias: 'i', value: 'file' };
const output: FlagSpec = { name: 'output', alias: 'o', value: 'file' };
const encoding: FlagSpec = { name: 'encoding', value: 'pem|der|hex' };
const format: FlagSpec = { name: 'format', alias: 'f', value: 'text|json' };

export const COMMANDS: readonly CommandSpec[] = [
    { name: 'limits', group: 'Meta', summary: 'The 22 pkinative security bounds: flags, defaults, effective', subcommands: [], flags: [format] },
];

/** Every command name, in table order. */
export function commandNames(): readonly string[] {
    return COMMANDS.map((c) => c.name);
}

export function findCommand(name: string): CommandSpec | undefined {
    return COMMANDS.find((c) => c.name === name);
}

/** Every boolean flag name and alias the parser must never read a value for. */
export function booleanFlags(): ReadonlySet<string> {
    const out = new Set<string>();
    for (const f of [...GLOBAL_FLAGS, ...COMMANDS.flatMap((c) => c.flags)]) {
        if (f.value !== undefined) continue;
        out.add(f.name);
        if (f.alias !== undefined) out.add(f.alias);
    }
    return out;
}

/** Every flag name and alias accepted by `command` (its own and the global ones). */
export function knownFlags(command: CommandSpec): ReadonlySet<string> {
    const out = new Set<string>();
    for (const f of [...GLOBAL_FLAGS, ...command.flags]) {
        out.add(f.name);
        if (f.alias !== undefined) out.add(f.alias);
    }
    return out;
}

/** Shared flag specs, so the same flag reads the same everywhere. */
export const COMMON_FLAGS = { input, output, encoding, format } as const;
