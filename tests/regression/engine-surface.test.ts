import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { changelogBullets } from '../../scripts/lib/changelog.js';

interface Item {
    readonly id: number;
    readonly section: string;
    readonly bullet: string;
    readonly waiver?: 'LIB' | 'TOOLING' | 'DOCS' | 'tested-upstream';
    readonly note?: string;
    readonly tests?: readonly { file: string; name: string }[];
}

const matrix = JSON.parse(readFileSync('tests/regression/engine-surface.json', 'utf8')) as { engine: string; items: Item[] };
const bullets = changelogBullets(readFileSync('docs/data/pkinative/changelog-1.0.0.md', 'utf8'));

describe('engine surface (pkinative 1.0.0 CHANGELOG)', () => {
    it('pins the engine the CLI depends on', () => {
        const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { dependencies: Record<string, string> };
        expect(pkg.dependencies['pkinative']).toBe(`^${matrix.engine}`);
    });

    it('maps every bullet of the entry exactly once, in order', () => {
        expect(matrix.items.map((i) => i.bullet)).toEqual(bullets.map((b) => b.title));
        expect(matrix.items.map((i) => i.id)).toEqual(bullets.map((_, i) => i + 1));
    });

    it('gives each bullet tests or a typed waiver, and tested-upstream both', () => {
        for (const item of matrix.items) {
            const hasTests = (item.tests ?? []).length > 0;
            if (item.waiver === undefined) expect(hasTests, `#${item.id}`).toBe(true);
            else if (item.waiver === 'tested-upstream') expect(hasTests && item.note !== undefined, `#${item.id}`).toBe(true);
            else expect(!hasTests && (item.note ?? '').length > 0, `#${item.id}`).toBe(true);
        }
    });

    it('names tests that exist in the named files', () => {
        for (const item of matrix.items) {
            for (const t of item.tests ?? []) {
                expect(existsSync(t.file), `#${item.id} ${t.file}`).toBe(true);
                expect(readFileSync(t.file, 'utf8').includes(`it('${t.name}'`), `#${item.id} "${t.name}" in ${t.file}`).toBe(true);
            }
        }
    });
});
