import { describe, expect, it } from 'vitest';
import {
    assertKnownFlags,
    assertOperands,
    assertSingleValues,
    canonicaliseAliases,
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

    it('collects repeated values, and refuses a bare repeat', () => {
        const a = parseArgs(['--trust', 'a', '--trust', 'b', '--trust=c'], bools);
        expect(a.flags['trust']).toEqual(['a', 'b', 'c']);
        // A value flag written bare after a value lacks its value (audit N-5).
        expect(() => parseArgs(['--trust', 'a', '--trust'], bools)).toThrow('Flag --trust requires a value.');
    });

    it('stops at --', () => {
        expect(parseArgs(['--json', '--', '--not-a-flag', 'x'], bools).positionals).toEqual(['--not-a-flag', 'x']);
    });

    it('refuses combined short flags, prototype names and empty names', () => {
        // The token is never spelled out: it may be a password (audit N-1, N-5).
        expect(() => parseArgs(['-qj'], bools)).toThrow('Combined short flags are not supported: write each flag separately (-q -f json, not -qf json).');
        expect(() => parseArgs(['-i=Zq9secret'], bools)).toThrow('A short flag takes no "=": write -i <value>, or the long form --<flag>=<value>.');
        // The remedy spells each letter, never the leading dash as a flag of its own.
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

    it('takes a lone "-" as the first positional, and looks one token ahead for a flag value', () => {
        expect(firstPositionalIndex(['-'], bools)).toBe(0);
        expect(firstPositionalIndex(['--format', 'json', '--x'], bools)).toBe(-1);
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
        expect(() => getIntFlag(flags, 'm')).toThrow(/expects a non-negative integer/);
        expect(() => getIntFlag(flags, 'n', 0, 10)).toThrow(/between 0 and 10/);
        expect(() => getIntFlag(flags, 'n', 50)).toThrow(/between 50/);
        expect(getIntFlag(flags, 'n', 42, 42)).toBe(42);
    });

    it('assertKnownFlags refuses an undeclared flag', () => {
        expect(() => assertKnownFlags(flags, new Set(['a']), 'pem')).toThrow(/Unknown flag -b for "pem"/);
        expect(() => assertKnownFlags({ x: true }, new Set(['a']), 'pem')).toThrow(/Unknown flag -x for "pem"/);
        expect(() => assertKnownFlags({ a: 'x' }, new Set(['a']), 'pem')).not.toThrow();
    });
});

describe('declarations the parser enforces (audit A-11)', () => {
    it('refuses a non-repeatable value flag given twice', () => {
        const parsed = parseArgs(['--host', 'a', '--host', 'b', '--trust', 'x', '--trust', 'y'], new Set());
        expect(() => assertSingleValues(parsed.flags, new Set(['trust']), 'chain verify')).toThrow(/--host is given 2 times for "chain verify"/);
        expect(() => assertSingleValues(parseArgs(['--trust', 'x', '--trust', 'y'], new Set()).flags, new Set(['trust']), 'x')).not.toThrow();
    });

    it('renames an alias to its flag, keeping the order, and refuses a flag under both its names (audit A2-01)', () => {
        const aliased = [{ name: 'input', alias: 'i' }, { name: 'quiet', alias: 'q' }];
        const renamed = canonicaliseAliases(parseArgs(['-q', '-i', 'a', '--json'], new Set(['q', 'json'])).flags, aliased);
        expect(Object.entries(renamed)).toEqual([['quiet', true], ['input', 'a'], ['json', true]]);
        expect(Object.getPrototypeOf(renamed)).toBeNull();
        expect(() => canonicaliseAliases(parseArgs(['-i', 'a', '--input', 'b'], new Set()).flags, aliased)).toThrow('--input and -i are the same flag; give it once.');
        expect(() => canonicaliseAliases(parseArgs(['--input', 'b', '-i', 'a'], new Set()).flags, aliased)).toThrow(/same flag/);
    });

    it('refuses a switch, or a bare value flag, given twice, without echoing a value (audit A2-11)', () => {
        const booleans = new Set(['json', 'q']);
        expect(() => parseArgs(['--json', '--json'], booleans)).toThrow('--json is given more than once; give it once.');
        expect(() => parseArgs(['--json', '--json=false'], booleans)).toThrow(/--json is given more than once/);
        expect(() => parseArgs(['-q', '-q'], booleans)).toThrow('-q is given more than once; give it once.');
        expect(() => parseArgs(['--output', '--output', 'secret'], booleans)).toThrow('--output is given more than once; give it once.');
        expect(() => parseArgs(['--output', 'a', '--output'], booleans)).toThrow('Flag --output requires a value.');
    });

    it('refuses surplus operands without echoing them, and an operand beside the flag it stands for', () => {
        const run = (argv: string[], rule: { max: number; for?: string[] }): string => {
            try { assertOperands(parseArgs(argv, new Set()), rule, 'p12 open'); return ''; } catch (e) { return (e as Error).message; }
        };
        expect(run(['a.p12', 'hunter2'], { max: 1, for: ['input'] })).toBe('"p12 open" takes at most 1 argument, got 2. Run pkinative p12 open --help.');
        expect(run(['x'], { max: 0 })).toMatch(/takes no arguments, got 1/);
        expect(run(['a', 'b', 'c'], { max: 2 })).toMatch(/at most 2 arguments, got 3/);
        expect(run(['a.p12', '--input', 'b.p12'], { max: 1, for: ['input'] })).toMatch(/given --input and an argument/);
        expect(run(['a.p12'], { max: 1, for: ['input'] })).toBe('');
        expect(run(['--input', 'b.p12'], { max: 1, for: ['input'] })).toBe('');
        expect(run(['a', 'b'], { max: Number.POSITIVE_INFINITY })).toBe('');
    });
});
