import { describe, expect, it } from 'vitest';
import { COMMANDS, GLOBAL_FLAGS, type FlagSpec } from '../../src/commands/registry.js';
import { COMMAND_USAGE, GLOBAL_USAGE, USAGE } from '../../src/commands/usage.js';

const allFlags = (c: (typeof COMMANDS)[number]): FlagSpec[] => [...c.flags, ...c.subcommands.flatMap((s) => s.flags)];
/** Flags of other tools quoted in the examples (curl). */
const FOREIGN = new Set(['data-binary']);
const mentioned = (text: string): Set<string> => new Set([...text.matchAll(/--([a-z0-9][a-z0-9-]*)/g)].map((m) => m[1] as string));

describe('help text', () => {
    it('has one block per command, and none extra', () => {
        expect(Object.keys(COMMAND_USAGE).sort()).toEqual(COMMANDS.map((c) => c.name).sort());
    });

    it('lists every flag a command declares', () => {
        for (const c of COMMANDS) {
            const text = COMMAND_USAGE[c.name] as string;
            for (const f of allFlags(c)) expect(text.includes(`--${f.name}`), `${c.name}: --${f.name}`).toBe(true);
        }
    });

    it('mentions only flags that exist for the command or globally', () => {
        const global = new Set(GLOBAL_FLAGS.map((f) => f.name));
        for (const c of COMMANDS) {
            const own = new Set(allFlags(c).map((f) => f.name));
            for (const name of mentioned(COMMAND_USAGE[c.name] as string)) {
                expect(own.has(name) || global.has(name) || name.startsWith('max-') || FOREIGN.has(name), `${c.name} mentions --${name}`).toBe(true);
            }
        }
    });

    it('shows a value placeholder for value flags only', () => {
        for (const c of COMMANDS) {
            const text = COMMAND_USAGE[c.name] as string;
            for (const f of allFlags(c)) {
                const withValue = new RegExp(`--${f.name}(?:, -\\w)? <`).test(text);
                if (f.value === undefined) expect(withValue, `${c.name}: boolean --${f.name} shown with a value`).toBe(false);
            }
        }
    });

    it('lists every global flag in the global help', () => {
        for (const f of GLOBAL_FLAGS) {
            if (f.name.startsWith('max-') && f.name !== 'max-content-size') continue;
            expect(USAGE.includes(`--${f.name}`), `--${f.name}`).toBe(true);
        }
        expect(GLOBAL_USAGE).toContain('--max-<limit>');
    });

    it('keeps every line within 80 columns', () => {
        for (const [name, text] of [['global', USAGE], ...Object.entries(COMMAND_USAGE)] as [string, string][]) {
            for (const line of text.split('\n')) expect(line.length, `${name}: ${line}`).toBeLessThanOrEqual(80);
        }
    });

    it('declares no flag as both boolean and valued', () => {
        const kinds = new Map<string, boolean>();
        for (const f of [...GLOBAL_FLAGS, ...COMMANDS.flatMap(allFlags)]) {
            const valued = f.value !== undefined;
            expect(kinds.get(f.name) ?? valued, `--${f.name}`).toBe(valued);
            kinds.set(f.name, valued);
        }
    });
});
