import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseArgs } from '../../src/utils/args.js';
import { colorEnabled, palette } from '../../src/utils/colors.js';
import { PASSWORD_ENV, assertNoLiteralPassword, readPassword } from '../../src/utils/secrets.js';
import { formatInstant, parseInstant } from '../../src/utils/time.js';
import { CLI_NAME, CLI_VERSION, engineVersion, resetEngineVersionCache } from '../../src/utils/version.js';
import { emptyDir, memoryIo } from '../helpers/io.js';

const args = (argv: string[]) => parseArgs(argv, new Set(['password-stdin']));

describe('secrets', () => {
    it('refuses a literal password flag', () => {
        for (const f of ['--password', '--pass', '--passin', '--key-password']) {
            expect(() => assertNoLiteralPassword(args([f, 'x']))).toThrow(/visible to every process/);
        }
        expect(() => assertNoLiteralPassword(args(['--password-file', 'f']))).not.toThrow();
    });

    it('reads the first line of a password file', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'p'), 'secret\r\nignored');
        await expect(readPassword(memoryIo().io, args(['--password-file', join(dir, 'p')]), false)).resolves.toBe('secret');
    });

    it('reads the password from stdin, or a "-" password file', async () => {
        await expect(readPassword(memoryIo({ stdin: 'pw\n' }).io, args(['--password-stdin']), false)).resolves.toBe('pw');
        await expect(readPassword(memoryIo({ stdin: 'pw2' }).io, args(['--password-file', '-']), false)).resolves.toBe('pw2');
    });

    it('reads the environment variable, ignoring an empty one', async () => {
        await expect(readPassword(memoryIo({ env: { [PASSWORD_ENV]: 'envpw' } }).io, args([]), false)).resolves.toBe('envpw');
        await expect(readPassword(memoryIo({ env: { [PASSWORD_ENV]: '' } }).io, args([]), false)).resolves.toBeUndefined();
        await expect(readPassword(memoryIo().io, args([]), false)).resolves.toBeUndefined();
    });

    it('refuses two sources, and --password-stdin when stdin carries the input', async () => {
        await expect(readPassword(memoryIo({ env: { [PASSWORD_ENV]: 'x' } }).io, args(['--password-stdin']), false)).rejects.toMatchObject({ code: 'E_USAGE' });
        await expect(readPassword(memoryIo().io, args(['--password-stdin']), true)).rejects.toThrow(/cannot be used when the input/);
    });
});

describe('time', () => {
    it('parses epoch, now and ISO forms, UTC by default', () => {
        expect(parseInstant('1700000000000', 'at')).toBe(1700000000000);
        expect(parseInstant('now', 'at', () => 42)).toBe(42);
        expect(parseInstant('2027-01-01', 'at')).toBe(Date.UTC(2027, 0, 1));
        expect(parseInstant('2027-01-01T10:00:00', 'at')).toBe(Date.UTC(2027, 0, 1, 10));
        expect(parseInstant('2027-01-01T10:00:00+02:00', 'at')).toBe(Date.UTC(2027, 0, 1, 8));
        expect(parseInstant('2027-01-01T10:00:00Z', 'at')).toBe(Date.UTC(2027, 0, 1, 10));
        expect(typeof parseInstant('now', 'at')).toBe('number');
    });

    it('refuses anything else', () => {
        for (const bad of ['tomorrow', '2027-13-45T99:00', '99999999999999999999', '']) {
            expect(() => parseInstant(bad, 'at')).toThrow(/--at expects/);
        }
        expect(formatInstant(0)).toBe('1970-01-01T00:00:00.000Z');
    });
});

describe('colors', () => {
    const tty = { write: () => true, isTTY: true };
    const pipe = { write: () => true, isTTY: false };
    it('follows TTY, NO_COLOR, FORCE_COLOR, TERM and the flag', () => {
        expect(colorEnabled(memoryIo().io, tty, false)).toBe(true);
        expect(colorEnabled(memoryIo().io, pipe, false)).toBe(false);
        expect(colorEnabled(memoryIo().io, tty, true)).toBe(false);
        expect(colorEnabled(memoryIo({ env: { NO_COLOR: '' } }).io, tty, false)).toBe(false);
        expect(colorEnabled(memoryIo({ env: { FORCE_COLOR: '1' } }).io, pipe, false)).toBe(true);
        expect(colorEnabled(memoryIo({ env: { FORCE_COLOR: '0' } }).io, pipe, false)).toBe(false);
        expect(colorEnabled(memoryIo({ env: { TERM: 'dumb' } }).io, tty, false)).toBe(false);
    });

    it('wraps text only when enabled', () => {
        expect(palette(false).bad('x')).toBe('x');
        expect(palette(true).ok('x')).toBe('\u001b[32mx\u001b[0m');
        expect([palette(true).warn('w'), palette(true).dim('d'), palette(false).ok('o'), palette(false).warn('w'), palette(false).dim('d'), palette(true).bad('b')])
            .toEqual(['\u001b[33mw\u001b[0m', '\u001b[2md\u001b[0m', 'o', 'w', 'd', '\u001b[31mb\u001b[0m']);
    });
});

describe('version', () => {
    it('reads the CLI version from package.json and the engine version from pkinative', () => {
        expect(CLI_NAME).toBe('pkinative-cli');
        expect(CLI_VERSION).toMatch(/^\d+\.\d+\.\d+/);
        resetEngineVersionCache();
        expect(engineVersion()).toMatch(/^1\./);
        expect(engineVersion(() => { throw new Error('x'); })).toMatch(/^1\./);
        resetEngineVersionCache();
        expect(engineVersion(() => ({ version: 3 }))).toBe('unknown');
        resetEngineVersionCache();
        expect(engineVersion(() => { throw new Error('missing'); })).toBe('unknown');
        resetEngineVersionCache();
    });
});
