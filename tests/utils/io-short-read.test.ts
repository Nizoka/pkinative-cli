// A read call may return fewer bytes than asked (Linux caps one call just
// under 2 GiB, and a file may shrink between the stat and the read): the
// reader loops, and stops at the end of the file (audit A2-05).
import { writeFileSync } from 'node:fs';
import type * as FsPromises from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { emptyDir, memoryIo } from '../helpers/io.js';

const shrinkBy = vi.hoisted(() => ({ bytes: 0 }));

vi.mock('node:fs/promises', async (importOriginal) => {
    const actual = await importOriginal<typeof FsPromises>();
    return {
        ...actual,
        open: async (...args: Parameters<typeof actual.open>) => {
            const handle = await actual.open(...args);
            const read = handle.read.bind(handle) as (b: Uint8Array, o: number, l: number, p: number) => Promise<{ bytesRead: number; buffer: Uint8Array }>;
            // Two bytes per call at most, and nothing past size - shrinkBy.bytes.
            const short = async (buffer: Uint8Array, offset: number, length: number, position: number) => {
                const size = (await handle.stat()).size - shrinkBy.bytes;
                return read(buffer, offset, Math.max(0, Math.min(2, length, size - position)), position);
            };
            return Object.assign(handle, { read: short });
        },
    };
});

const { readInput } = await import('../../src/utils/io.js');

describe('readInput over short reads', () => {
    it('reads the whole file when each call returns a part of it', async () => {
        shrinkBy.bytes = 0;
        const file = join(emptyDir(), 'a');
        writeFileSync(file, 'abcdefg');
        await expect(readInput(memoryIo().io, file, { what: 'thing', maxBytes: 64 })).resolves.toEqual(new TextEncoder().encode('abcdefg'));
    });

    it('stops at the end of a file that ends before its reported size', async () => {
        shrinkBy.bytes = 3;
        const file = join(emptyDir(), 'b');
        writeFileSync(file, 'abcdefg');
        await expect(readInput(memoryIo().io, file, { what: 'thing', maxBytes: 64 })).resolves.toEqual(new TextEncoder().encode('abcd'));
    });
});
