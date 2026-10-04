import { existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { clearInFlight, inFlightPaths, markInFlight, removeInFlight, SIGNAL_EXIT } from '../../src/utils/inflight.js';
import { overwriteRefused, processIo, readInput, writeOutput } from '../../src/utils/io.js';
import { emptyDir, memoryIo } from '../helpers/io.js';

const limits = { what: 'thing', maxBytes: 8, limitFlag: 'max-input-bytes' };

describe('readInput', () => {
    it('reads a file under the bound', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'a'), 'abc');
        await expect(readInput(memoryIo().io, join(dir, 'a'), limits)).resolves.toEqual(new TextEncoder().encode('abc'));
    });

    it('refuses an oversize file before reading it', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'big'), '0123456789');
        await expect(readInput(memoryIo().io, join(dir, 'big'), limits)).rejects.toMatchObject({
            code: 'E_LIMIT', detail: { limit: 'max-input-bytes', configured: 8, observed: 10 }, remedy: '--max-input-bytes <size> (trusted input only)',
        });
    });

    it('maps a missing file and a directory to E_IO', async () => {
        const dir = emptyDir();
        await expect(readInput(memoryIo().io, join(dir, 'missing'), limits)).rejects.toMatchObject({ code: 'E_IO', message: expect.stringMatching(/ENOENT/) });
        await expect(readInput(memoryIo().io, dir, limits)).rejects.toMatchObject({ code: 'E_IO', message: expect.stringMatching(/directory/) });
    });

    it('reads stdin, string and byte chunks, bounded', async () => {
        await expect(readInput(memoryIo({ stdin: ['ab', new Uint8Array([0x63])] }).io, '-', limits)).resolves.toEqual(new TextEncoder().encode('abc'));
        await expect(readInput(memoryIo({ stdin: 'x' }).io, undefined, limits)).resolves.toHaveLength(1);
        await expect(readInput(memoryIo({ stdin: '0123456789' }).io, '-', limits)).rejects.toMatchObject({ code: 'E_LIMIT' });
    });

    it('refuses to wait on an interactive stdin unless "-" is explicit', async () => {
        await expect(readInput(memoryIo({ stdinTTY: true }).io, undefined, limits)).rejects.toMatchObject({ code: 'E_USAGE' });
        await expect(readInput(memoryIo({ stdinTTY: true, stdin: 'a' }).io, '-', limits)).resolves.toHaveLength(1);
    });
});

describe('writeOutput', () => {
    it('writes to stdout without a path', async () => {
        const m = memoryIo();
        await writeOutput(m.io, undefined, 'x', { overwrite: false });
        await writeOutput(m.io, '-', 'y', { overwrite: false });
        expect(m.stdout()).toBe('xy');
    });

    it('creates a file exclusively and refuses to overwrite it', async () => {
        const dir = emptyDir();
        const target = join(dir, 'out.pem');
        await writeOutput(memoryIo().io, target, 'one', { overwrite: false });
        expect(readFileSync(target, 'utf8')).toBe('one');
        await expect(writeOutput(memoryIo().io, target, 'two', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO', remedy: '--overwrite' });
        expect(readFileSync(target, 'utf8')).toBe('one');
        expect(inFlightPaths()).toEqual([]);
    });

    it('replaces atomically with --overwrite and leaves no temp file', async () => {
        const dir = emptyDir();
        const target = join(dir, 'out.der');
        writeFileSync(target, 'old');
        await writeOutput(memoryIo().io, target, new Uint8Array([1, 2]), { overwrite: true });
        expect(new Uint8Array(readFileSync(target))).toEqual(new Uint8Array([1, 2]));
        expect(readdirSync(dir)).toEqual(['out.der']);
    });

    it('refuses to write through a dangling symlink without --overwrite', async () => {
        const dir = emptyDir();
        const link = join(dir, 'link');
        try {
            symlinkSync(join(dir, 'elsewhere'), link);
        } catch {
            return; // symlinks need privileges on some Windows hosts
        }
        await expect(writeOutput(memoryIo().io, link, 'x', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO' });
        expect(existsSync(join(dir, 'elsewhere'))).toBe(false);
    });

    it('maps an unwritable target to E_IO', async () => {
        const dir = emptyDir();
        await expect(writeOutput(memoryIo().io, join(dir, 'no', 'such', 'dir'), 'x', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO' });
        await expect(writeOutput(memoryIo().io, join(dir, 'no', 'dir'), 'x', { overwrite: true })).rejects.toMatchObject({ code: 'E_IO' });
    });

    it('cleans the temp file when the rename fails', async () => {
        const dir = emptyDir();
        const target = join(dir, 'isdir');
        mkdirSync(target);
        writeFileSync(join(target, 'keep'), 'x');
        await expect(writeOutput(memoryIo().io, target, 'x', { overwrite: true })).rejects.toMatchObject({ code: 'E_IO' });
        expect(readdirSync(dir)).toEqual(['isdir']);
    });

    it('builds the uniform overwrite refusal', () => {
        expect(overwriteRefused('f').message).toMatch(/Refusing to overwrite existing file f/);
    });

    it('exposes the real process streams', () => {
        const io = processIo();
        expect(io.stdout).toBe(process.stdout);
        expect(io.cwd).toBe(process.cwd());
    });
});

describe('inflight', () => {
    it('removes registered paths only', () => {
        const dir = emptyDir();
        const a = join(dir, 'a');
        writeFileSync(a, 'x');
        markInFlight(a);
        markInFlight(join(dir, 'never-created'));
        markInFlight(join(dir, 'b'));
        clearInFlight(join(dir, 'b'));
        expect(removeInFlight()).toHaveLength(2);
        expect(existsSync(a)).toBe(false);
        expect(inFlightPaths()).toEqual([]);
        expect(SIGNAL_EXIT).toEqual({ SIGINT: 130, SIGTERM: 143 });
    });

    it('keeps going when a removal fails', () => {
        markInFlight('\u0000invalid');
        expect(removeInFlight()).toEqual([]);
    });
});
