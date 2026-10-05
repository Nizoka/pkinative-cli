import { describe, expect, it } from 'vitest';
import { parseVersion, satisfies } from '../../src/utils/engines.js';

describe('parseVersion', () => {
    it('reads major, minor and patch each from its own field', () => {
        expect(parseVersion('1.2.3')).toEqual([1, 2, 3]);
        expect(parseVersion('v10.20.30-rc.1')).toEqual([10, 20, 30]);
        expect(parseVersion('1.2')).toBeUndefined();
    });
});

describe('satisfies at the clause boundaries', () => {
    it('>= includes its own version and excludes the one just below', () => {
        expect(satisfies('25.8.2', '>=25.8.2')).toBe(true);
        expect(satisfies('25.8.1', '>=25.8.2')).toBe(false);
    });

    it('^ excludes the patch just below its base', () => {
        expect(satisfies('22.22.1', '^22.22.2')).toBe(false);
        expect(satisfies('22.22.2', '^22.22.2')).toBe(true);
    });

    it('an exact clause matches only itself', () => {
        expect(satisfies('1.2.3', '1.2.3')).toBe(true);
        expect(satisfies('1.2.4', '1.2.3')).toBe(false);
    });
});
