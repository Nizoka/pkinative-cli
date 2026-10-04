import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DEFAULT_PKI_LIMITS } from 'pkinative';
import { parseArgs } from '../../src/utils/args.js';
import { LIMIT_FLAGS, LIMIT_FLAG_NAMES, effectiveLimits, flagForLimit, parseBound, parseLimitFlags } from '../../src/utils/limits.js';

const registry = JSON.parse(readFileSync('docs/data/pkinative/limits.json', 'utf8')) as { limits: { limit: string }[] };

describe('LIMIT_FLAGS', () => {
    it('has one flag per DEFAULT_PKI_LIMITS key and per registry row', () => {
        expect(LIMIT_FLAGS.map((l) => l.key)).toEqual(Object.keys(DEFAULT_PKI_LIMITS));
        expect(LIMIT_FLAGS.map((l) => l.key).sort()).toEqual(registry.limits.map((l) => l.limit).sort());
        expect(LIMIT_FLAGS).toHaveLength(22);
        expect(LIMIT_FLAG_NAMES).toContain('max-input-bytes');
        expect(LIMIT_FLAG_NAMES).toContain('max-pkcs12-kdf-iterations');
        expect(LIMIT_FLAGS.find((l) => l.key === 'maxInputBytes')?.kind).toBe('bytes');
        expect(LIMIT_FLAGS.find((l) => l.key === 'maxDepth')?.kind).toBe('count');
    });

    it('maps a limit name back to its flag', () => {
        expect(flagForLimit('maxChainLength')).toBe('max-chain-length');
        expect(flagForLimit('nope')).toBeUndefined();
    });
});

describe('parseBound', () => {
    it('accepts byte suffixes for byte bounds only', () => {
        expect(parseBound('64k', 'f', 'bytes')).toBe(65536);
        expect(parseBound(' 16MiB ', 'f', 'bytes')).toBe(16 * 1024 ** 2);
        expect(parseBound('1g', 'f', 'bytes')).toBe(1024 ** 3);
        expect(parseBound('12', 'f', 'count')).toBe(12);
        expect(() => parseBound('12k', 'f', 'count')).toThrow(/positive integer/);
        expect(() => parseBound('1t', 'f', 'bytes')).toThrow(/byte count/);
        expect(() => parseBound('none', 'f', 'bytes')).toThrow(/byte count/);
    });

    it('refuses zero and values beyond safe integers', () => {
        expect(() => parseBound('0', 'f', 'count')).toThrow(/must be a positive integer/);
        expect(() => parseBound('99999999999999999', 'f', 'count')).toThrow(/no greater than/);
    });
});

describe('parseLimitFlags', () => {
    it('returns undefined without any --max flag', () => {
        expect(parseLimitFlags(parseArgs([], new Set()))).toBeUndefined();
    });

    it('collects the given bounds', () => {
        const limits = parseLimitFlags(parseArgs(['--max-depth', '8', '--max-input-bytes', '1m'], new Set()));
        expect(limits).toEqual({ maxDepth: 8, maxInputBytes: 1024 ** 2 });
        expect(effectiveLimits(limits).maxDepth).toBe(8);
        expect(effectiveLimits(undefined)).toEqual(DEFAULT_PKI_LIMITS);
    });
});
