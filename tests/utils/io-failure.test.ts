import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type * as FsPromises from 'node:fs/promises';
import { describe, expect, it, vi } from 'vitest';

// Failures the filesystem rarely produces on demand: ENOSPC after the open,
// a close that fails too, and a file created between lstat and open.
const mode = vi.hoisted(() => ({ value: 'write-fails' as 'write-fails' | 'close-fails' | 'race' }));

vi.mock('node:fs/promises', async (importOriginal) => {
    const real = await importOriginal<typeof FsPromises>();
    return {
        ...real,
        open: async (...args: Parameters<typeof real.open>) => {
            if (mode.value === 'race') throw Object.assign(new Error('exists'), { code: 'EEXIST' });
            const handle = await real.open(...args);
            return Object.assign(Object.create(Object.getPrototypeOf(handle) as object) as typeof handle, handle, {
                writeFile: () => Promise.reject(Object.assign(new Error('no space'), { code: 'ENOSPC' })),
                close: async () => {
                    await handle.close();
                    if (mode.value === 'close-fails') throw Object.assign(new Error('io'), { code: 'EIO' });
                },
            });
        },
    };
});

const { writeOutput } = await import('../../src/utils/io.js');
const { inFlightPaths } = await import('../../src/utils/inflight.js');
const { emptyDir, memoryIo } = await import('../helpers/io.js');

describe('writeOutput failure', () => {
    it('removes the partial file and maps the error', async () => {
        mode.value = 'write-fails';
        const target = join(emptyDir(), 'out.pem');
        await expect(writeOutput(memoryIo().io, target, 'x', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO', message: expect.stringMatching(/ENOSPC/) });
        expect(existsSync(target)).toBe(false);
        expect(inFlightPaths()).toEqual([]);
    });

    it('still removes the partial file when close fails too', async () => {
        mode.value = 'close-fails';
        const target = join(emptyDir(), 'out.pem');
        await expect(writeOutput(memoryIo().io, target, 'x', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO', message: expect.stringMatching(/ENOSPC/) });
        expect(existsSync(target)).toBe(false);
    });

    it('turns a file created between lstat and open into the overwrite refusal', async () => {
        mode.value = 'race';
        await expect(writeOutput(memoryIo().io, join(emptyDir(), 'out.pem'), 'x', { overwrite: false })).rejects.toMatchObject({ code: 'E_IO', remedy: '--overwrite' });
    });
});
