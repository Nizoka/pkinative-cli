// Boundary cases of the encoding commands (pem, fingerprint, asn1): each one
// pins a limit, an off-by-one or an implementation switch exactly.

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cli, emptyDir, envelope, fixture } from '../helpers/io.js';

function derFile(hex: string): string {
    const path = join(emptyDir(), 'o.der');
    writeFileSync(path, Buffer.from(hex, 'hex'));
    return path;
}

async function encode(value: unknown, extra: string[] = []) {
    const dir = emptyDir();
    writeFileSync(join(dir, 's.json'), JSON.stringify(value));
    return cli(['asn1', 'encode', '--spec', join(dir, 's.json'), '--encoding', 'hex', ...extra]);
}

/** `levels` wrappers of `type` around a NULL: the NULL sits at depth `levels`. */
function nest(type: 'sequence' | 'explicit' | 'implicit', levels: number): unknown {
    let node: unknown = { type: 'null' };
    for (let i = 0; i < levels; i++) node = type === 'sequence' ? { type, children: [node] } : { type, tag: i, inner: node };
    return node;
}

describe('pem decode headers', () => {
    it('lists a single header under --pem-mode lax', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'h.pem'), '-----BEGIN THING-----\nComment: one\n\nBQA=\n-----END THING-----\n');
        const r = await cli(['pem', 'decode', join(dir, 'h.pem'), '--pem-mode', 'lax']);
        expect(r.code).toBe(0);
        expect(r.stdout).toBe('#0  THING  2 bytes  at offset 0  headers: Comment\n');
    });
});

describe('pem encode without --label', () => {
    it('is a usage error before any input is read', async () => {
        const pemInput = await cli(['pem', 'encode', fixture('leaf.crt.pem'), '--json']);
        expect(pemInput.code).toBe(2);
        expect(envelope(pemInput.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
        const missing = await cli(['pem', 'encode', join(emptyDir(), 'absent.der'), '--json']);
        expect(missing.code).toBe(2);
        expect(envelope(missing.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
    });
});

describe('fingerprint --shake256 bound', () => {
    it('accepts exactly 1 MiB of output and refuses one byte more', async () => {
        const max = await cli(['fingerprint', fixture('content.txt'), '--shake256', String(1024 * 1024), '--json']);
        expect(max.code).toBe(0);
        expect(JSON.parse(max.stdout)).toMatchObject({ algorithm: 'SHAKE256', outputLength: 1024 * 1024 });
        expect((JSON.parse(max.stdout) as { hex: string }).hex).toHaveLength(2 * 1024 * 1024);
        const over = await cli(['fingerprint', fixture('content.txt'), '--shake256', String(1024 * 1024 + 1), '--json']);
        expect(over.code).toBe(2);
        // The CLI refuses it itself (no engine code), before reading any input.
        expect(envelope(over.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
        expect((envelope(over.stderr) as { error: { pkiCode?: string } }).error.pkiCode).toBeUndefined();
        const absent = await cli(['fingerprint', join(emptyDir(), 'absent.der'), '--shake256', String(1024 * 1024 + 1), '--json']);
        expect(absent.code).toBe(2);
        expect(envelope(absent.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
    });
});

describe('fingerprint --webcrypto', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('goes through WebCrypto only when asked', async () => {
        const digest = vi.spyOn(globalThis.crypto.subtle, 'digest');
        const plain = await cli(['fingerprint', fixture('leaf.crt.der'), '--json']);
        expect(plain.code).toBe(0);
        expect(digest).not.toHaveBeenCalled();
        const web = await cli(['fingerprint', fixture('leaf.crt.der'), '--webcrypto', '--json']);
        expect(web.code).toBe(0);
        expect(digest).toHaveBeenCalledTimes(1);
        expect(digest.mock.calls[0]?.[0]).toBe('SHA-256');
        expect(JSON.parse(web.stdout)).toEqual(JSON.parse(plain.stdout));
    });
});

describe('asn1 decode previews', () => {
    it('prints a 32-byte value in full and abbreviates a 33-byte one', async () => {
        const full = 'ab'.repeat(32);
        expect((await cli(['asn1', 'decode', derFile(`0420${full}`)])).stdout).toBe(`    0:d=0  hl=2 l=  32 prim: OCTET STRING  ${full}\n`);
        expect((await cli(['asn1', 'decode', derFile(`0421${full}cd`)])).stdout).toBe(`    0:d=0  hl=2 l=  33 prim: OCTET STRING  ${full}… (33 bytes)\n`);
    });

    it('names unused bits only when there are some', async () => {
        expect((await cli(['asn1', 'decode', derFile('030200ff')])).stdout).toBe('    0:d=0  hl=2 l=   2 prim: BIT STRING  ff\n');
        expect((await cli(['asn1', 'decode', derFile('03020180')])).stdout).toBe('    0:d=0  hl=2 l=   2 prim: BIT STRING  80 (1 unused bits)\n');
    });

    it('indents each level by one depth', async () => {
        const r = await cli(['asn1', 'decode', derFile('30053003020101')]);
        expect(r.stdout).toBe([
            '    0:d=0  hl=2 l=   5 cons: SEQUENCE',
            '    2:d=1  hl=2 l=   3 cons:   SEQUENCE',
            '    4:d=2  hl=2 l=   1 prim:     INTEGER  1',
            '',
        ].join('\n'));
    });
});

describe('asn1 encode spec edges', () => {
    it('encodes negative integer strings by their magnitude', async () => {
        expect((await encode({ type: 'integer', value: '-300' })).stdout).toBe('0202fed4\n');
        expect((await encode({ type: 'enumerated', value: '-0x7f' })).stdout).toBe('0a0181\n');
    });

    it('refuses a negative tag, bit number or unused-bit count as a spec error', async () => {
        const cases: [unknown, RegExp][] = [
            [{ type: 'bit-string', hex: '00', unusedBits: -1 }, /asn1 spec \$\.unusedBits: expected an integer from 0 to 7/],
            [{ type: 'named-bits', bits: [-1] }, /asn1 spec \$\.bits: expected an array of bit numbers/],
            [{ type: 'explicit', tag: -1, inner: { type: 'null' } }, /asn1 spec \$\.tag: expected a tag number/],
            [{ type: 'implicit', tag: -1, inner: { type: 'null' } }, /asn1 spec \$\.tag: expected a tag number/],
            [{ type: 'tlv', class: 'private', tag: -1, constructed: false, hex: '' }, /asn1 spec \$\.tag: expected a tag number/],
        ];
        for (const [value, message] of cases) {
            const r = await encode(value, ['--json']);
            expect(r.code, JSON.stringify(value)).toBe(1);
            const error = (envelope(r.stderr) as { error: { code: string; message: string; pkiCode?: string } }).error;
            expect(error.code, JSON.stringify(value)).toBe('E_INPUT');
            expect(error.pkiCode, JSON.stringify(value)).toBeUndefined();
            expect(error.message, JSON.stringify(value)).toMatch(message);
        }
    });

    for (const type of ['sequence', 'explicit', 'implicit'] as const) {
        it(`counts one level per ${type} against --max-depth`, async () => {
            const at = await encode(nest(type, 3), ['--max-depth', '3']);
            expect(at.code).toBe(0);
            const over = await encode(nest(type, 4), ['--max-depth', '3', '--json']);
            expect(over.code).toBe(1);
            expect(envelope(over.stderr)).toMatchObject({ error: { code: 'E_LIMIT', detail: { limit: 'maxDepth', flag: '--max-depth', configured: 3, observed: 4 } } });
        });
    }
});
