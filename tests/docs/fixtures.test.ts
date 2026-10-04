import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = 'tests/fixtures';

describe('fixtures', () => {
    const pinned = new Map(
        readFileSync(join(ROOT, 'SHA256SUMS'), 'utf8').trim().split('\n').map((line) => {
            const [sum, path] = line.split(/\s+/) as [string, string];
            return [path, sum];
        }),
    );

    it('pins every file under pki/ and nothing else', () => {
        const present = readdirSync(join(ROOT, 'pki')).map((f) => `pki/${f}`).sort();
        expect([...pinned.keys()].sort()).toEqual(present);
    });

    it('holds every fixture to its checksum', () => {
        for (const [path, sum] of pinned) {
            const actual = createHash('sha256').update(readFileSync(join(ROOT, path))).digest('hex');
            expect(actual, path).toBe(sum);
        }
    });

    it('stores text fixtures with LF line endings', () => {
        for (const path of pinned.keys()) {
            if (!/\.(pem|txt)$/.test(path)) continue;
            expect(readFileSync(join(ROOT, path), 'utf8').includes('\r'), path).toBe(false);
        }
    });

    it('documents every fixture family in PROVENANCE.md', () => {
        const doc = readFileSync(join(ROOT, 'PROVENANCE.md'), 'utf8');
        for (const path of pinned.keys()) {
            const stem = path.replace(/^pki\//, '').split('.')[0] as string;
            expect(doc.includes(stem), stem).toBe(true);
        }
    });
});
