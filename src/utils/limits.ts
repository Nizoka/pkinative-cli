// `--max-*` flags → `Partial<PkiLimits>`.
//
// One flag per key of pkinative's DEFAULT_PKI_LIMITS (22), named after the key
// in kebab case (`maxInputBytes` → `--max-input-bytes`). Flat flags complete
// in every shell and are flat keys in `.pkinativerc.json`; JSON on argv is
// hostile to PowerShell quoting. Values are validated here as positive
// integers, so PKI_LIMIT_INVALID is unreachable from the CLI. There is no
// "none": pkinative refuses an unbounded limit, and so does the CLI.

import { DEFAULT_PKI_LIMITS, type PkiLimits } from '../core-bridge/index.js';
import { getStringFlag, type ParsedArgs } from './args.js';
import { usageError } from './error.js';

export type LimitKind = 'bytes' | 'count';

export interface LimitFlag {
    readonly flag: string;
    readonly key: keyof PkiLimits;
    readonly kind: LimitKind;
}

function kebab(key: string): string {
    return key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

/** The 22 limit flags, in DEFAULT_PKI_LIMITS declaration order. */
export const LIMIT_FLAGS: readonly LimitFlag[] = (Object.keys(DEFAULT_PKI_LIMITS) as (keyof PkiLimits)[]).map((key) => ({
    flag: kebab(key),
    key,
    kind: key.endsWith('Bytes') ? 'bytes' : 'count',
}));

/** Every `--max-*` flag name, bare (no dashes). */
export const LIMIT_FLAG_NAMES: readonly string[] = LIMIT_FLAGS.map((l) => l.flag);

const SIZE_UNITS: Readonly<Record<string, number>> = {
    '': 1,
    b: 1,
    k: 1024,
    kb: 1024,
    kib: 1024,
    m: 1024 ** 2,
    mb: 1024 ** 2,
    mib: 1024 ** 2,
    g: 1024 ** 3,
    gb: 1024 ** 3,
    gib: 1024 ** 3,
};

/**
 * Parse a positive integer bound. Byte bounds accept a binary suffix
 * (`64k`, `16MiB`, `1g`); count bounds accept digits only. Anything else,
 * zero, or a value beyond Number.MAX_SAFE_INTEGER is a usage error.
 */
export function parseBound(raw: string, flag: string, kind: LimitKind): number {
    const match = /^(\d+)\s*([a-z]*)$/i.exec(raw.trim());
    const unit = match?.[2]?.toLowerCase() ?? '';
    const factor = kind === 'bytes' ? SIZE_UNITS[unit] : unit === '' ? 1 : undefined;
    if (match === null || factor === undefined) {
        const form = kind === 'bytes' ? 'a byte count such as 65536, 64k, 16MiB or 1g' : 'a positive integer';
        throw usageError(`--${flag} expects ${form}, got "${raw}".`);
    }
    const value = Number(match[1]) * factor;
    if (value === 0 || !Number.isSafeInteger(value)) {
        throw usageError(`--${flag} must be a positive integer no greater than ${Number.MAX_SAFE_INTEGER}, got "${raw}".`);
    }
    return value;
}

/** Parse every `--max-*` flag present; `undefined` when none is set. */
export function parseLimitFlags(args: ParsedArgs): Partial<PkiLimits> | undefined {
    const out: Partial<Record<keyof PkiLimits, number>> = {};
    let any = false;
    for (const spec of LIMIT_FLAGS) {
        const raw = getStringFlag(args.flags, spec.flag);
        if (raw === undefined) continue;
        out[spec.key] = parseBound(raw, spec.flag, spec.kind);
        any = true;
    }
    return any ? out : undefined;
}

/** Defaults merged with the overrides. */
export function effectiveLimits(overrides: Partial<PkiLimits> | undefined): PkiLimits {
    return { ...DEFAULT_PKI_LIMITS, ...overrides };
}

/** The flag that raises a named pkinative limit, when the limit is one of the 22. */
export function flagForLimit(limit: string): string | undefined {
    return LIMIT_FLAGS.find((l) => l.key === limit)?.flag;
}
