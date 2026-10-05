import { usageError } from './error.js';

export type FlagValue = string | boolean | readonly string[];

export interface ParsedArgs {
    readonly flags: Readonly<Record<string, FlagValue>>;
    readonly positionals: readonly string[];
}

/** Names that would reach Object.prototype through a plain record. */
const FORBIDDEN_FLAG_NAMES: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Zero-dependency argument parser.
 *
 *   --flag value   value-taking flags only      --flag=value  explicit form
 *   -f value       one-letter alias             --flag        boolean
 *   --flag -       a lone dash is a VALUE (stdin/stdout)
 *   --             stop parsing; the rest are positionals
 *
 * A flag named in `booleans` never consumes the next token, so
 * `--json cert inspect a.pem` keeps its positionals. Repeating a value flag
 * collects its values in order. Combined short flags (`-qj`) are refused.
 */
export function parseArgs(argv: readonly string[], booleans: ReadonlySet<string>): ParsedArgs {
    const flags: Record<string, FlagValue> = Object.create(null) as Record<string, FlagValue>;
    const positionals: string[] = [];

    const setFlag = (key: string, value: string | boolean): void => {
        if (key === '' || FORBIDDEN_FLAG_NAMES.has(key)) {
            throw usageError(`Invalid flag name "--${key}".`);
        }
        const existing = flags[key];
        if (existing === undefined || typeof existing === 'boolean') {
            flags[key] = value;
        } else if (typeof value === 'string') {
            flags[key] = typeof existing === 'string' ? [existing, value] : [...existing, value];
        }
    };

    const isValueToken = (tok: string): boolean => tok === '-' || /^-\d/.test(tok) || !tok.startsWith('-');

    for (let i = 0; i < argv.length; i++) {
        const token = argv[i] as string;
        if (token === '--') {
            positionals.push(...argv.slice(i + 1));
            break;
        }
        let key: string;
        if (token.startsWith('--')) {
            const eq = token.indexOf('=');
            if (eq !== -1) {
                setFlag(token.slice(2, eq), token.slice(eq + 1));
                continue;
            }
            key = token.slice(2);
        } else if (token.startsWith('-') && token.length > 1 && !/^-\d/.test(token)) {
            if (token.length > 2) {
                throw usageError(`Combined short flags are not supported ("${token}"): write ${Array.from(token.slice(1), (c) => `-${c}`).join(' ')}.`);
            }
            key = token.slice(1);
        } else {
            positionals.push(token);
            continue;
        }
        const next = argv[i + 1];
        if (!booleans.has(key) && next !== undefined && isValueToken(next)) {
            setFlag(key, next);
            i++;
        } else {
            setFlag(key, true);
        }
    }
    return { flags, positionals };
}

/**
 * Index in argv of the first positional, walking with the parser's own rules
 * (so a flag's value is never mistaken for the command), or -1.
 */
export function firstPositionalIndex(argv: readonly string[], booleans: ReadonlySet<string>): number {
    for (let i = 0; i < argv.length; i++) {
        const token = argv[i] as string;
        if (token === '--') return i + 1 < argv.length ? i + 1 : -1;
        const isFlag = token.startsWith('-') && token.length > 1 && !/^-\d/.test(token);
        if (!isFlag) return i;
        if (token.includes('=')) continue;
        const key = token.replace(/^--?/, '');
        const next = argv[i + 1];
        if (!booleans.has(key) && next !== undefined && (next === '-' || /^-\d/.test(next) || !next.startsWith('-'))) i++;
    }
    return -1;
}

function isNegation(raw: string): boolean {
    const v = raw.trim().toLowerCase();
    return v === 'false' || v === '0' || v === 'no' || v === 'off';
}

/**
 * The first value of the first named flag present. A value flag written bare
 * (`--output` with nothing after it) is a usage error.
 */
export function getStringFlag(flags: ParsedArgs['flags'], ...names: string[]): string | undefined {
    for (const name of names) {
        const value = flags[name];
        if (value === undefined) continue;
        if (typeof value === 'boolean') throw usageError(`Flag --${name} requires a value.`);
        return typeof value === 'string' ? value : value[0];
    }
    return undefined;
}

/** Every value of every named flag, in order. */
export function getStringFlagAll(flags: ParsedArgs['flags'], ...names: string[]): readonly string[] {
    const out: string[] = [];
    for (const name of names) {
        const value = flags[name];
        if (value === undefined) continue;
        if (typeof value === 'boolean') throw usageError(`Flag --${name} requires a value.`);
        out.push(...(typeof value === 'string' ? [value] : value));
    }
    return out;
}

/**
 * Tri-state boolean: `undefined` when absent, `true` for a bare flag or
 * true|1|yes|on, `false` for false|0|no|off. Anything else is a usage error.
 */
export function getBoolFlag(flags: ParsedArgs['flags'], ...names: string[]): boolean | undefined {
    for (const name of names) {
        const value = flags[name];
        if (value === undefined) continue;
        if (typeof value === 'boolean') return value;
        const raw = typeof value === 'string' ? value : value.join(',');
        const v = raw.trim().toLowerCase();
        if (v === 'true' || v === '1' || v === 'yes' || v === 'on') return true;
        if (isNegation(v)) return false;
        throw usageError(`Flag --${name} expects a boolean (true/false), got "${raw}".`);
    }
    return undefined;
}

/** True when any named flag is present and not explicitly negated. */
export function hasFlag(flags: ParsedArgs['flags'], ...names: string[]): boolean {
    return getBoolFlag(flags, ...names) === true;
}

/** Parse a closed set of string values (`--encoding pem|der`). */
export function getChoiceFlag<T extends string>(
    flags: ParsedArgs['flags'],
    name: string,
    choices: readonly T[],
    fallback: T,
): T;
export function getChoiceFlag<T extends string>(
    flags: ParsedArgs['flags'],
    name: string,
    choices: readonly T[],
): T | undefined;
export function getChoiceFlag<T extends string>(
    flags: ParsedArgs['flags'],
    name: string,
    choices: readonly T[],
    fallback?: T,
): T | undefined {
    const raw = getStringFlag(flags, name);
    if (raw === undefined) return fallback;
    if ((choices as readonly string[]).includes(raw)) return raw as T;
    throw usageError(`--${name} expects one of ${choices.join('|')}, got "${raw}".`);
}

/** Parse a non-negative safe integer flag. */
export function getIntFlag(flags: ParsedArgs['flags'], name: string, min = 0, max = Number.MAX_SAFE_INTEGER): number | undefined {
    const raw = getStringFlag(flags, name);
    if (raw === undefined) return undefined;
    if (!/^\d+$/.test(raw)) throw usageError(`--${name} expects an integer, got "${raw}".`);
    const value = Number(raw);
    if (value < min || value > max) throw usageError(`--${name} must be between ${min} and ${max}, got ${raw}.`);
    return value;
}

/**
 * Refuse a value flag given twice when the registry does not declare it
 * repeatable, and a flag given under both its name and its alias: the second
 * value would otherwise be dropped silently, and a verdict would depend on
 * the order of the flags (audit A-11).
 */
export function assertSingleValues(
    flags: ParsedArgs['flags'],
    repeatable: ReadonlySet<string>,
    aliased: ReadonlyArray<{ readonly name: string; readonly alias?: string }>,
    command: string,
): void {
    for (const [name, value] of Object.entries(flags)) {
        if (Array.isArray(value) && !repeatable.has(name)) {
            throw usageError(`--${name} is given ${value.length} times for "${command}"; it takes one value.`);
        }
    }
    for (const f of aliased) {
        if (flags[f.name] !== undefined && flags[f.alias as string] !== undefined) {
            throw usageError(`--${f.name} and -${f.alias as string} are the same flag; give it once.`);
        }
    }
}

/**
 * Refuse positionals beyond what the invocation takes, and an operand given
 * together with the flag it stands for. The values are never echoed: a stray
 * positional may be a secret typed in the wrong place.
 */
export function assertOperands(args: ParsedArgs, rule: { readonly max: number; readonly for?: readonly string[] }, command: string): void {
    const n = args.positionals.length;
    if (n > rule.max) {
        const most = rule.max === 0 ? 'no arguments' : `at most ${rule.max} argument${rule.max === 1 ? '' : 's'}`;
        throw usageError(`"${command}" takes ${most}, got ${n}. Run pkinative ${command} --help.`);
    }
    const flag = (rule.for ?? []).find((name) => args.flags[name] !== undefined);
    if (n > 0 && flag !== undefined) {
        throw usageError(`"${command}" was given --${flag} and an argument for the same input; give it once.`);
    }
}

/** Refuse flags that no command or global table declares. */
export function assertKnownFlags(flags: ParsedArgs['flags'], known: ReadonlySet<string>, command: string): void {
    for (const name of Object.keys(flags)) {
        if (!known.has(name)) {
            throw usageError(`Unknown flag --${name} for "${command}". Run pkinative ${command} --help.`);
        }
    }
}
