import { describe, expect, it } from 'vitest';
import {
    assertKnownFlags,
    firstPositionalIndex,
    getBoolFlag,
    getChoiceFlag,
    getIntFlag,
    getStringFlag,
    getStringFlagAll,
    hasFlag,
    parseArgs,
} from '../../src/utils/args.js';
import { CliError } from '../../src/utils/error.js';

const bools = new Set(['json', 'q', 'strict']);

describe('parseArgs', () => {
    it('reads every supported form', () => {
        const a = parseArgs(['--in', 'a.pem', '--out=b', '-o', 'c', '--json', 'pos', '-q', '--n', '-1', '--d', '-'], bools);
        expect(a.flags).toEqual({ in: 'a.pem', out: 'b', o: 'c', json: true, q: true, n: '-1', d: '-' });
        expect(a.positionals).toEqual(['pos']);
    });

    it('keeps the token after a boolean flag as a positional', () => {
        expect(parseArgs(['--json', 'cert'], bools).positionals).toEqual(['cert']);
    });

    it('treats a value flag followed by a flag as bare', () => {
        expect(parseArgs(['--out', '--json'], bools).flags).toEqual({ out: true, json: true });
        expect(parseArgs(['--out'], bools).flags).toEqual({ out: true });
    });

    it('collects repeated values and ignores a later bare repeat', () => {
        const a = parseArgs(['--trust', 'a', '--trust', 'b', '--trust=c', '--trust'], bools);
        expect(a.flags['trust']).toEqual(['a', 'b', 'c']);
        expect(parseArgs(['--x', '--x', 'v'], new Set()).flags['x']).toBe('v');
    });

    it('stops at --', () => {
        expect(parseArgs(['--json', '--', '--not-a-flag', 'x'], bools).positionals).toEqual(['--not-a-flag', 'x']);
    });

    it('refuses combined short flags, prototype names and empty names', () => {
        expect(() => parseArgs(['-qj'], bools)).toThrow(/Combined short flags.*-q -j/);
        for (const bad of ['--__proto__', '--constructor=x', '--prototype', '--=v']) {
            expect(() => parseArgs([bad], bools)).toThrow(CliError);
        }
    });

    it('stores flags on a null-prototype record', () => {
        expect(Object.getPrototypeOf(parseArgs([], bools).flags)).toBeNull();
    });
});

describe('firstPositionalIndex', () => {
    it('skips flag values and finds the command', () => {
        expect(firstPositionalIndex(['--output', 'cert', 'cert', 'inspect'], bools)).toBe(2);
        expect(firstPositionalIndex(['--json', 'cert'], bools)).toBe(1);
        expect(firstPositionalIndex(['--x=1', 'cert'], bools)).toBe(1);
        expect(firstPositionalIndex(['-o', '-', 'pem'], bools)).toBe(2);
        expect(firstPositionalIndex(['--n', '-5', 'oid'], bools)).toBe(2);
        expect(firstPositionalIndex(['--a', '--b'], bools)).toBe(-1);
        expect(firstPositionalIndex(['--', 'cert'], bools)).toBe(1);
        expect(firstPositionalIndex(['--'], bools)).toBe(-1);
        expect(firstPositionalIndex([], bools)).toBe(-1);
    });
});

describe('flag accessors', () => {
    const { flags } = parseArgs(['--a', 'x', '--a', 'y', '--b', '--c=no', '--d=maybe', '--e=on', '--n', '42', '--m', 'x1'], bools);

    it('getStringFlag returns the first value and refuses a bare value flag', () => {
        expect(getStringFlag(flags, 'missing', 'a')).toBe('x');
        expect(getStringFlag(flags, 'e')).toBe('on');
        expect(getStringFlag(flags, 'missing')).toBeUndefined();
        expect(() => getStringFlag(flags, 'b')).toThrow(/requires a value/);
    });

    it('getStringFlagAll collects across names', () => {
        expect(getStringFlagAll(flags, 'a', 'e', 'missing')).toEqual(['x', 'y', 'on']);
        expect(() => getStringFlagAll(flags, 'b')).toThrow(/requires a value/);
    });

    it('getBoolFlag is tri-state and strict', () => {
        expect(getBoolFlag(flags, 'b')).toBe(true);
        expect(getBoolFlag(flags, 'c')).toBe(false);
        expect(getBoolFlag(flags, 'e')).toBe(true);
        expect(getBoolFlag(flags, 'missing')).toBeUndefined();
        expect(() => getBoolFlag(flags, 'd')).toThrow(/expects a boolean/);
        expect(() => getBoolFlag(flags, 'a')).toThrow(/x,y/);
        expect(hasFlag(flags, 'c')).toBe(false);
        expect(hasFlag(flags, 'missing', 'b')).toBe(true);
    });

    it('getChoiceFlag validates against the set', () => {
        expect(getChoiceFlag(flags, 'e', ['on', 'off'] as const)).toBe('on');
        expect(getChoiceFlag(flags, 'missing', ['on'] as const)).toBeUndefined();
        expect(getChoiceFlag(flags, 'missing', ['on', 'off'] as const, 'off')).toBe('off');
        expect(() => getChoiceFlag(flags, 'd', ['on'] as const)).toThrow(/one of on/);
    });

    it('getIntFlag validates digits and range', () => {
        expect(getIntFlag(flags, 'n')).toBe(42);
        expect(getIntFlag(flags, 'missing')).toBeUndefined();
        expect(() => getIntFlag(flags, 'm')).toThrow(/expects an integer/);
        expect(() => getIntFlag(flags, 'n', 0, 10)).toThrow(/between 0 and 10/);
        expect(() => getIntFlag(flags, 'n', 50)).toThrow(/between 50/);
    });

    it('assertKnownFlags refuses an undeclared flag', () => {
        expect(() => assertKnownFlags(flags, new Set(['a']), 'pem')).toThrow(/Unknown flag --b for "pem"/);
        expect(() => assertKnownFlags({ a: 'x' }, new Set(['a']), 'pem')).not.toThrow();
    });
});
