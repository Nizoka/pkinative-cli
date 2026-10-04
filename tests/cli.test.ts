import { describe, expect, it, vi } from 'vitest';
import { run } from '../src/cli.js';

describe('run', () => {
    it('returns exit code 0', async () => {
        const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
        await expect(run([])).resolves.toBe(0);
        write.mockRestore();
    });
});
