import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { allFlagSpecs } from '../../src/commands/registry.js';
import { parseArgs } from '../../src/utils/args.js';
import { CONFIG_FILENAME, CONFIG_KEYS, applyConfigDefaults, isConfigKey, loadConfig } from '../../src/utils/config.js';
import { emptyDir } from '../helpers/io.js';

const COMMANDS = ['cert', 'chain'];

function withConfig(content: string): string {
    const dir = emptyDir();
    writeFileSync(join(dir, CONFIG_FILENAME), content);
    return dir;
}

describe('loadConfig', () => {
    it('returns nothing without a config file', () => {
        expect(loadConfig('cert', undefined, COMMANDS, undefined, emptyDir())).toEqual({ defaults: {} });
    });

    it('layers global, command and subcommand sections, found upward', () => {
        const dir = withConfig(JSON.stringify({ pretty: true, encoding: 'der', 'no-color': true, fields: 'a,b', cert: { encoding: 'pem', format: 'json' }, 'cert inspect': { format: 'text' }, chain: { pretty: false } }));
        const nested = join(dir, 'a', 'b');
        mkdirSync(nested, { recursive: true });
        const loaded = loadConfig('cert', 'inspect', COMMANDS, undefined, nested);
        expect(loaded.path).toBe(join(dir, CONFIG_FILENAME));
        expect(loaded.defaults).toEqual({ pretty: true, encoding: 'pem', 'no-color': true, fields: 'a,b', format: 'text' });
        expect(loadConfig('cert', 'create', COMMANDS, undefined, nested).defaults['format']).toBe('json');
        expect(loadConfig('chain', undefined, COMMANDS, undefined, dir).defaults['pretty']).toBe(false);
    });

    it('drops values that cannot be flags', () => {
        const dir = withConfig(JSON.stringify({ json: null, pretty: { x: 1 }, fields: ['a', 1], encoding: Number.MAX_VALUE * 0, cert: { quiet: null } }));
        expect(loadConfig('cert', undefined, COMMANDS, undefined, dir).defaults).toEqual({ encoding: '0' });
    });

    it('honours an explicit path and refuses a missing one', () => {
        const dir = withConfig('{"quiet":true}');
        expect(loadConfig('cert', undefined, COMMANDS, CONFIG_FILENAME, dir).defaults).toEqual({ quiet: true });
        expect(() => loadConfig('cert', undefined, COMMANDS, 'missing.json', dir)).toThrow(/not found/);
    });

    it('refuses invalid JSON, a non-object, oversize files', () => {
        const load = (body: string): unknown => loadConfig('cert', undefined, COMMANDS, undefined, withConfig(body));
        expect(() => load('{nope')).toThrow(/not valid JSON/);
        expect(() => load('[1]')).toThrow(/JSON object/);
        expect(() => load('null')).toThrow(/JSON object/);
        expect(() => load(`{"fields":"${'x'.repeat(1024 * 1024)}"}`)).toThrow(/1 MiB/);
    });

    it('accepts presentation keys only: every other flag of the registry, present or future, is refused', () => {
        // Derived from the registry, so a flag added tomorrow is refused by
        // default: a planted file never changes inputs, trust, time, bounds
        // or outputs (ADR 0007; audit A-01, V-01).
        const refused = [...new Set(allFlagSpecs().map((f) => f.name))].filter((n) => !CONFIG_KEYS.includes(n));
        expect(refused).toEqual(expect.arrayContaining(['input', 'trust', 'untrusted', 'at', 'no-signatures', 'responder-trusted', 'stale-tolerance', 'output', 'certs-out', 'allow-sha1', 'overwrite', 'password-file']));
        for (const key of refused) {
            expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig(JSON.stringify({ [key]: true }))), key).toThrow(/command line only/);
            expect(() => loadConfig('chain', undefined, COMMANDS, undefined, withConfig(JSON.stringify({ 'cert inspect': { [key]: 'x' } }))), key).toThrow(/command line only/);
        }
        expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig('{"__proto__":{"x":1}}'))).toThrow(/forbidden key/);
        expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig('{"cert inspect extra":{}}'))).toThrow(/command line only/);
        expect(CONFIG_KEYS.every(isConfigKey)).toBe(true);
    });
});

describe('applyConfigDefaults', () => {
    it('fills only the flags the user did not pass and the subcommand declares', () => {
        const args = parseArgs(['--encoding', 'der', 'pos'], new Set());
        const merged = applyConfigDefaults(args, { encoding: 'pem', pretty: true, format: 'json' }, new Set(['encoding', 'pretty']));
        expect({ ...merged.args.flags }).toEqual({ encoding: 'der', pretty: true });
        expect(merged.args.positionals).toEqual(['pos']);
        expect(merged.applied).toEqual(['pretty']);
    });
});
