import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMANDS } from '../../src/commands/registry.js';
import { RUNTIME_VIA, surfaceDocument } from '../../scripts/lib/surface.js';

const frozen = JSON.parse(readFileSync('docs/data/pkinative/api.frozen.json', 'utf8')) as { exports: { name: string; kind: string }[] };
const runtime = frozen.exports.filter((e) => e.kind !== 'type').map((e) => e.name);

function sources(dir: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const f of readdirSync(dir)) {
        const p = join(dir, f);
        if (statSync(p).isDirectory()) Object.assign(out, sources(p));
        else if (p.endsWith('.ts')) out[p.replace(/\\/g, '/')] = readFileSync(p, 'utf8');
    }
    return out;
}
const SRC = sources('src');
const BRIDGE = 'src/core-bridge/index.ts';

const INVOCATIONS = new Set(['*', ...COMMANDS.flatMap((c) => (c.subcommands.length === 0 ? [c.name] : c.subcommands.map((s) => `${c.name} ${s.name}`)))]);

describe('surface matrix', () => {
    it('reaches every one of the 294 exports', () => {
        const doc = surfaceDocument() as { counts: Record<string, number>; exports: { name: string; via: string[] }[] };
        expect(doc.counts).toEqual({ exports: 294, capability: 117, typeOnly: 177 });
        const unreached = doc.exports.filter((e) => e.via.length === 0).map((e) => e.name);
        expect(unreached).toEqual([]);
    });

    it('maps exactly the runtime exports, to commands that exist', () => {
        expect(Object.keys(RUNTIME_VIA).sort()).toEqual([...runtime].sort());
        for (const [name, via] of Object.entries(RUNTIME_VIA)) {
            for (const v of via) expect(INVOCATIONS.has(v), `${name} → ${v}`).toBe(true);
        }
    });

    it('re-exports every runtime export from the bridge and uses each outside it', () => {
        const bridge = SRC[BRIDGE] as string;
        for (const name of runtime) {
            expect(new RegExp(`^\\s+${name},$`, 'm').test(bridge), `bridge re-exports ${name}`).toBe(true);
            const users = Object.entries(SRC).filter(([f, t]) => f !== BRIDGE && new RegExp(`\\b${name}\\b`).test(t));
            expect(users.length, `${name} is used by a command`).toBeGreaterThan(0);
        }
    });

    it('imports pkinative through core-bridge only', () => {
        for (const [file, text] of Object.entries(SRC)) {
            if (file === BRIDGE) continue;
            expect(/from ['"]pkinative['"]/.test(text), file).toBe(false);
        }
    });

    it('commits the generated matrix', () => {
        expect(readFileSync('docs/data/core-exports.json', 'utf8')).toBe(JSON.stringify(surfaceDocument(), null, 2) + '\n');
    });

    it('vendors the v1.0.0 registries at schemaVersion 1', () => {
        for (const f of ['errors', 'reasons', 'diagnostics', 'limits', 'defaults', 'surfaces']) {
            const doc = JSON.parse(readFileSync(`docs/data/pkinative/${f}.json`, 'utf8')) as { schemaVersion: number };
            expect(doc.schemaVersion, f).toBe(1);
        }
        expect(JSON.parse(readFileSync('docs/data/pkinative/api.frozen.json', 'utf8')).frozenAt).toBe('1.0.0');
    });

    it('matches the runtime surface of the installed engine', async () => {
        const engine = await import('pkinative');
        const installed = Object.keys(engine).filter((k) => k !== 'default').sort();
        expect(installed).toEqual([...runtime].sort());
    });
});
