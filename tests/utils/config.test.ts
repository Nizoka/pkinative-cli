import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { allFlagSpecs, configSections } from '../../src/commands/registry.js';
import { parseArgs } from '../../src/utils/args.js';
import { CONFIG_FILENAME, CONFIG_KEYS, CONFIG_VALUE_KEYS, applyConfigDefaults, isConfigKey, loadConfig } from '../../src/utils/config.js';
import { emptyDir } from '../helpers/io.js';

const COMMANDS: ReadonlySet<string> = new Set(['cert', 'cert inspect', 'cert create', 'chain']);

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

    it('ranks the layers by scope, never by their order in the file', () => {
        const load = (body: object, sub?: string): unknown => loadConfig('cert', sub, COMMANDS, undefined, withConfig(JSON.stringify(body))).defaults['format'];
        // A global key written after the command section still loses to it.
        expect(load({ cert: { format: 'command' }, format: 'global' })).toBe('command');
        // A command section written after the subcommand section still loses to it.
        expect(load({ 'cert inspect': { format: 'sub' }, cert: { format: 'command' } }, 'inspect')).toBe('sub');
    });

    it('refuses a number JSON reads as infinite', () => {
        expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig('{"format":1e999}'))).toThrow(/"format" takes a string/);
        expect(loadConfig('cert', undefined, COMMANDS, undefined, withConfig('{"encoding":0}')).defaults).toEqual({ encoding: '0' });
    });

    it('accepts a file of exactly 1 MiB', () => {
        const head = '{"fields":"a"';
        const body = `${head}${' '.repeat(1024 * 1024 - head.length - 1)}}`;
        expect(body).toHaveLength(1024 * 1024);
        expect(loadConfig('cert', undefined, COMMANDS, undefined, withConfig(body)).defaults).toEqual({ fields: 'a' });
    });

    it('refuses a value of the wrong type, in any section, without echoing it (audit A2-07)', () => {
        const load = (body: object): unknown => loadConfig('chain', undefined, COMMANDS, undefined, withConfig(JSON.stringify(body)));
        for (const body of [{ json: null }, { json: 'yes' }, { pretty: { x: 1 } }, { strict: 1 }, { cert: { quiet: null } }, { 'cert inspect': { summary: 'true' } }]) {
            expect(() => load(body), JSON.stringify(body)).toThrow(/takes true or false/);
        }
        for (const body of [{ fields: ['a', 1] }, { format: true }, { cert: { encoding: null } }]) {
            expect(() => load(body), JSON.stringify(body)).toThrow(/takes a string/);
        }
        expect(() => load({ fields: 'Zq9secret' })).not.toThrow();
        expect(() => load({ format: { secret: 'Zq9secret' } })).toThrow(/^(?!.*Zq9secret)/);
    });

    it('refuses a section that names no subcommand, or that is not an object (audit A2-07)', () => {
        const load = (body: object): unknown => loadConfig('cert', 'inspect', COMMANDS, undefined, withConfig(JSON.stringify(body)));
        expect(() => load({ 'cert inspekt': { format: 'json' } })).toThrow('"cert inspekt" is not a command or subcommand section.');
        expect(() => load({ 'cert inspect extra': {} })).toThrow(/is not a command or subcommand section/);
        expect(() => load({ cert: true })).toThrow(/the section "cert" must be an object/);
        expect(() => load({ 'cert inspect': ['format'] })).toThrow(/must be an object/);
    });

    it('holds its switches and value keys to the registry', () => {
        for (const key of CONFIG_KEYS) {
            const specs = allFlagSpecs().filter((f) => f.name === key);
            expect(specs.length, key).toBeGreaterThan(0);
            for (const f of specs) expect(f.value !== undefined, key).toBe(CONFIG_VALUE_KEYS.includes(key));
        }
        expect(configSections()).toContain('cert inspect');
        expect(configSections()).toContain('fingerprint');
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
            expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig(JSON.stringify({ [key]: true }))), key).toThrow(COMMANDS.has(key) ? /must be an object/ : /command line only/);
            expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig(JSON.stringify({ [key]: 'x' }))), key).toThrow(COMMANDS.has(key) ? /must be an object/ : /command line only/);
            expect(() => loadConfig('chain', undefined, COMMANDS, undefined, withConfig(JSON.stringify({ 'cert inspect': { [key]: 'x' } }))), key).toThrow(/command line only/);
        }
        expect(() => loadConfig('cert', undefined, COMMANDS, undefined, withConfig('{"__proto__":{"x":1}}'))).toThrow(/forbidden key/);
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
