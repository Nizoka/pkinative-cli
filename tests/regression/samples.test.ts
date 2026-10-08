import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMANDS } from '../../src/commands/registry.js';
import { SAMPLE_BINARY_INPUTS, SAMPLE_INPUTS, SAMPLES } from '../../scripts/lib/sample-plan.js';
import { BASELINE, INPUTS, ps1Script, samplePath, shScript } from '../../scripts/lib/samples.js';

describe('samples', () => {
    it('commits each sample as a .sh and .ps1 pair generated from the plan', () => {
        for (const s of SAMPLES) {
            expect(readFileSync(samplePath(s, 'sh'), 'utf8'), samplePath(s, 'sh')).toBe(shScript(s));
            expect(readFileSync(samplePath(s, 'ps1'), 'utf8'), samplePath(s, 'ps1')).toBe(ps1Script(s));
        }
        const committed = readdirSync('samples', { recursive: true }).map(String).filter((f) => /\.(sh|ps1)$/.test(f)).map((f) => `samples/${f.replace(/\\/g, '/')}`).sort();
        expect(committed).toEqual(SAMPLES.flatMap((s) => [samplePath(s, 'ps1'), samplePath(s, 'sh')]).sort());
    });

    it('commits the inputs the samples read', () => {
        for (const [name, text] of Object.entries(SAMPLE_INPUTS)) expect(readFileSync(join(INPUTS, name), 'utf8'), name).toBe(text + '\n');
        for (const [name, hex] of Object.entries(SAMPLE_BINARY_INPUTS)) expect(Buffer.from(readFileSync(join(INPUTS, name))).toString('hex'), name).toBe(hex);
    });

    it('exercises every subcommand except the host-dependent doctor', () => {
        const covered = new Set(SAMPLES.map((s) => (s.argv[1] !== undefined && COMMANDS.find((c) => c.name === s.argv[0])?.subcommands.some((x) => x.name === s.argv[1]) ? `${s.argv[0]} ${s.argv[1]}` : s.argv[0])));
        const all = COMMANDS.flatMap((c) => (c.subcommands.length === 0 ? [c.name] : c.subcommands.map((x) => `${c.name} ${x.name}`))).filter((n) => n !== 'doctor');
        expect(all.filter((n) => !covered.has(n))).toEqual([]);
    });

    it('pins exactly the planned samples, with unique ids and declared outputs', () => {
        expect(existsSync(BASELINE)).toBe(true);
        const pinned = (JSON.parse(readFileSync(BASELINE, 'utf8')) as { samples: Record<string, string> }).samples;
        expect(Object.keys(pinned).sort()).toEqual(SAMPLES.map((s) => s.id).sort());
        expect(new Set(SAMPLES.map((s) => s.id)).size).toBe(SAMPLES.length);
        for (const s of SAMPLES) {
            if (s.mode === 'file' || s.mode === 'tbs') expect(s.output, s.id).toBeDefined();
            expect(s.command, s.id).toBe(s.argv[0]);
        }
    });
});
