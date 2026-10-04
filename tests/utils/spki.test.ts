import { describe, expect, it } from 'vitest';
import { readSpki } from '../../src/utils/spki.js';
import { makeCtx } from '../helpers/ctx.js';

const hex = (h: string) => Uint8Array.from(Buffer.from(h.replace(/\s/g, ''), 'hex'));
const key32 = '00'.repeat(32);

describe('readSpki', () => {
    it('reads Ed25519, Ed448, RSA and RSA-PSS key types', () => {
        expect(readSpki(makeCtx(), hex(`302a300506032b6570032100${key32}`)).type).toEqual({ kind: 'ed25519' });
        expect(readSpki(makeCtx(), hex(`3043300506032b6571033a00${'00'.repeat(57)}`)).type).toEqual({ kind: 'ed448' });
        expect(readSpki(makeCtx(), hex('3012300d06092a864886f70d01010a0500030100')).type).toEqual({ kind: 'rsa-pss' });
    });

    it('returns no type for a key Web Crypto cannot sign with', () => {
        // X25519 (key agreement only)
        expect(readSpki(makeCtx(), hex(`302a300506032b656e032100${key32}`)).type).toBeUndefined();
        // EC on secp256k1, and EC with explicit parameters (a SEQUENCE)
        expect(readSpki(makeCtx(), hex('3016301006072a8648ce3d020106052b8104000a03020004')).type).toBeUndefined();
        expect(readSpki(makeCtx(), hex('3013300d06072a8648ce3d02013002050003020004')).type).toBeUndefined();
        // EC without parameters
        expect(readSpki(makeCtx(), hex('300f300906072a8648ce3d020103020004')).type).toBeUndefined();
    });

    it('refuses a structure that is not an SPKI', () => {
        expect(() => readSpki(makeCtx(), hex('3003020101'))).toThrow(/not a SubjectPublicKeyInfo/);
        expect(() => readSpki(makeCtx(), hex('300a3000030100020101'.slice(0, 16)))).toThrow();
        expect(() => readSpki(makeCtx(), hex('30063000030200'.concat('00')))).toThrow(/not a SubjectPublicKeyInfo/);
    });
});
