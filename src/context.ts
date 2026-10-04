// The per-invocation context every command receives: the I/O streams, the
// command's own flags and positionals, the global options already parsed,
// and the diagnostics the engine emitted along the way.

import type { PkiDiagnostic, PkiLimits, PkiParseOptions } from './core-bridge/index.js';
import { getChoiceFlag, getStringFlag, hasFlag, type ParsedArgs } from './utils/args.js';
import { colorEnabled, palette, type Palette } from './utils/colors.js';
import type { Io } from './utils/io.js';
import { parseBound, parseLimitFlags } from './utils/limits.js';
import { parseFieldList } from './utils/projection.js';

/** Bound on non-PKI payloads read whole: content to sign or verify, data to time-stamp. */
export const DEFAULT_MAX_CONTENT_SIZE = 1024 ** 3;

export interface GlobalOptions {
    readonly json: boolean;
    readonly pretty: boolean;
    readonly quiet: boolean;
    readonly dryRun: boolean;
    readonly strict: boolean;
    readonly ber: boolean;
    readonly pemMode: 'strict' | 'lax';
    readonly allowSha1: boolean;
    readonly overwrite: boolean;
    readonly fields: readonly string[] | undefined;
    readonly summary: boolean;
    readonly limits: Partial<PkiLimits> | undefined;
    readonly maxContentSize: number;
}

export interface Ctx {
    readonly io: Io;
    /** `cert inspect`, `doctor`: the command and its subcommand, for envelopes. */
    readonly command: string;
    /** The command's flags (global ones included) and its positionals after the subcommand. */
    readonly args: ParsedArgs;
    readonly opts: GlobalOptions;
    readonly color: Palette;
    readonly diagnostics: PkiDiagnostic[];
    /** Extra members a command adds to the `--json` success envelope. */
    readonly status: Record<string, unknown>;
}

export function parseGlobalOptions(args: ParsedArgs, env: Io['env']): GlobalOptions {
    const fields = getStringFlag(args.flags, 'fields');
    const maxContent = getStringFlag(args.flags, 'max-content-size');
    return {
        json: hasFlag(args.flags, 'json') || env['PKINATIVE_JSON'] === '1',
        pretty: hasFlag(args.flags, 'pretty'),
        quiet: hasFlag(args.flags, 'quiet', 'q') || env['PKINATIVE_QUIET'] === '1',
        dryRun: hasFlag(args.flags, 'dry-run'),
        strict: hasFlag(args.flags, 'strict'),
        ber: hasFlag(args.flags, 'ber'),
        pemMode: getChoiceFlag(args.flags, 'pem-mode', ['strict', 'lax'] as const, 'strict'),
        allowSha1: hasFlag(args.flags, 'allow-sha1'),
        overwrite: hasFlag(args.flags, 'overwrite'),
        fields: fields === undefined ? undefined : parseFieldList(fields),
        summary: hasFlag(args.flags, 'summary'),
        limits: parseLimitFlags(args),
        maxContentSize: maxContent === undefined ? DEFAULT_MAX_CONTENT_SIZE : parseBound(maxContent, 'max-content-size', 'bytes'),
    };
}

export function createContext(io: Io, command: string, args: ParsedArgs, opts: GlobalOptions): Ctx {
    return {
        io,
        command,
        args,
        opts,
        color: palette(colorEnabled(io, io.stdout, hasFlag(args.flags, 'no-color'))),
        diagnostics: [],
        status: {},
    };
}

/** The engine options every parse call shares: encoding rules, limits, strictness, diagnostic sink. */
export function parseOptions(ctx: Ctx): PkiParseOptions {
    return {
        encodingRules: ctx.opts.ber ? 'ber' : 'der',
        limits: ctx.opts.limits,
        strict: ctx.opts.strict,
        onDiagnostic: (d: PkiDiagnostic) => {
            ctx.diagnostics.push(d);
        },
    };
}

/** The effective PKI read cap for inputs (the engine's maxInputBytes). */
export function maxInputBytes(ctx: Ctx, fallback: number): number {
    return ctx.opts.limits?.maxInputBytes ?? fallback;
}
