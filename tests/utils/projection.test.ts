import { describe, expect, it } from 'vitest';
import { parseFieldList, selectFields, serializeJson } from '../../src/utils/projection.js';

describe('projection', () => {
    const doc = { a: 1, b: { c: 2, d: 3 }, list: [{ n: 1, m: 2 }, { n: 3 }], s: 'x' };

    it('parses field lists', () => {
        expect(parseFieldList(' a, b.c ,,')).toEqual(['a', 'b.c']);
    });

    it('selects and merges dot-paths, mapping over arrays', () => {
        expect(selectFields(doc, ['a', 'b.c', 'list.n'])).toEqual({ a: 1, b: { c: 2 }, list: [{ n: 1 }, { n: 3 }] });
        expect(selectFields(doc, ['b.c', 'b.d'])).toEqual({ b: { c: 2, d: 3 } });
        expect(selectFields(doc, ['list.n', 'list.m'])).toEqual({ list: [{ n: 1, m: 2 }, { n: 3 }] });
    });

    it('omits unknown paths silently', () => {
        expect(selectFields(doc, ['nope', 's.deeper', '', 'b.zz'])).toEqual({});
        expect(selectFields(doc, ['a', 'a'])).toEqual({ a: 1 });
        expect(selectFields([[1]], ['x'])).toEqual([[undefined]]);
    });

    it('never reaches an inherited property', () => {
        expect(selectFields(doc, ['constructor', 'toString', 'b.hasOwnProperty'])).toEqual({});
    });

    it('ignores empty segments inside a path', () => {
        expect(selectFields(doc, ['b..c', '.a', 's.'])).toEqual({ a: 1, b: { c: 2 }, s: 'x' });
    });

    it('serialises compact or pretty', () => {
        expect(serializeJson({ a: 1 }, false)).toBe('{"a":1}');
        expect(serializeJson({ a: 1 }, true)).toBe('{\n  "a": 1\n}');
    });
});
