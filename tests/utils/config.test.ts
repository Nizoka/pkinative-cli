import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseArgs } from '../../src/utils/args.js';
import { CONFIG_FILENAME, applyConfigDefaults, isForbiddenConfigKey, loadConfig } from '../../src/utils/config.js';
import { emptyDir } from '../helpers/io.js';

const COMMANDS = ['cert', 'chain'];

function withConfig(content: string): string {
    const dir = emptyDir();
    writeFileSync(join(dir, CONFIG_FILENAME), content);
    return dir;
}

describe('loadConfig', () => {
    it('returns nothing without a config file', () => {
        expect(loadConfig('cert', COMMANDS, undefined, emptyDir())).toEqual({});
    });

    it('merges the global section under the command section, found upward', () => {
        const dir = withConfig(JSON.stringify({ pretty: true, encoding: 'der', 'no-color': true, n: 3, list: ['a', 1], cert: { encoding: 'pem' }, chain: { pretty: false } }));
        const nested = join(dir, 'a', 'b');
        mkdirSync(nested, { recursive: true });
        expect(loadConfig('cert', COMMANDS, undefined, nested)).toEqual({ pretty: true, encoding: 'pem', 'no-color': true, n: '3', list: ['a', '1'] });
        expect(loadConfig('chain', COMMANDS, undefined, dir)['pretty']).toBe(false);
    });

    it('drops values that cannot be flags', () => {
        const dir = withConfig(JSON.stringify({ a: null, b: { x: 1 }, c: [{}], d: Number.MAX_VALUE * 0, cert: { e: null } }));
        expect(loadConfig('cert', COMMANDS, undefined, dir)).toEqual({ d: '0' });
    });

    it('honours an explicit path and refuses a missing one', () => {
        const dir = withConfig('{"quiet":true}');
        expect(loadConfig('cert', COMMANDS, CONFIG_FILENAME, dir)).toEqual({ quiet: true });
        expect(() => loadConfig('cert', COMMANDS, 'missing.json', dir)).toThrow(/not found/);
    });

    it('refuses invalid JSON, a non-object, oversize files', () => {
        expect(() => loadConfig('cert', COMMANDS, undefined, withConfig('{nope'))).toThrow(/not valid JSON/);
        expect(() => loadConfig('cert', COMMANDS, undefined, withConfig('[1]'))).toThrow(/JSON object/);
        expect(() => loadConfig('cert', COMMANDS, undefined, withConfig('null'))).toThrow(/JSON object/);
        expect(() => loadConfig('cert', COMMANDS, undefined, withConfig(`{"a":"${'x'.repeat(1024 * 1024)}"}`))).toThrow(/1 MiB/);
    });

    it('refuses security-relaxing and prototype keys, globally and in sections', () => {
        for (const key of ['allow-sha1', 'max-depth', 'overwrite', 'ber', 'pem-mode', 'password-file', 'config', '__proto__']) {
            const body = key === '__proto__' ? '{"__proto__":{"x":1}}' : JSON.stringify({ [key]: true });
            expect(() => loadConfig('cert', COMMANDS, undefined, withConfig(body)), key).toThrow(/forbidden key|command line only/);
        }
        expect(() => loadConfig('chain', COMMANDS, undefined, withConfig(JSON.stringify({ cert: { 'allow-sha1': true } })))).toThrow(/command line only/);
        expect(isForbiddenConfigKey('pretty')).toBe(false);
    });
});

describe('applyConfigDefaults', () => {
    it('fills only the flags the user did not pass', () => {
        const args = parseArgs(['--encoding', 'der', 'pos'], new Set());
        const merged = applyConfigDefaults(args, { encoding: 'pem', pretty: true });
        expect({ ...merged.flags }).toEqual({ encoding: 'der', pretty: true });
        expect(merged.positionals).toEqual(['pos']);
    });
});
