import { createHmac, pbkdf2Sync, sign as nodeSign, webcrypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
    decodeAsn1, encodeAlgorithmIdentifier, encodeAttribute, encodeExplicit, encodeInteger, encodeObjectIdentifier, encodeOctetString,
    encodeSequence, encodeSetOf, encodeTlv, parseCertificate, parseSignedData,
} from 'pkinative';
import { renderSignedData } from '../../src/commands/cms.js';
import { AT, cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

const ENV = { PKINATIVE_PASSWORD: 'test-only-password' };
const TRUST = ['--trust', fixture('root.crt.pem')];
const CONTENT_SHA256 = 'b1a1c762480b580288e0737422f01130e824c8014422371ae571880dfc642533';

type Node = ReturnType<typeof decodeAsn1>;

/** The child at `path` (indices from the root), or a test failure. */
function child(node: Node, ...path: number[]): Node {
    let at = node;
    for (const i of path) {
        const next = at.children[i];
        if (next === undefined) throw new Error(`no child ${i}`);
        at = next;
    }
    return at;
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const int = (node: Node): number => Number.parseInt(hex(node.content), 16);

/** The CLI's output file, parsed as SignedData. */
const signedDataAt = (path: string) => parseSignedData(new Uint8Array(readFileSync(path)));

/** A detached SignedData over content.txt whose one signer has NO signed attributes: the signature is over the content. */
function noSignedAttributes(): Uint8Array {
    const cert = parseCertificate(fixtureBytes('leaf.crt.der'));
    const signature = new Uint8Array(nodeSign('sha256', fixtureBytes('content.txt'), readFileSync(fixture('leaf.key.pem'), 'utf8')));
    const sha256 = encodeAlgorithmIdentifier('2.16.840.1.101.3.4.2.1');
    const signerInfo = encodeSequence([
        encodeInteger(1n),
        encodeSequence([cert.issuer.der, encodeTlv('universal', 2, false, cert.serialNumber.bytes)]),
        sha256,
        encodeAlgorithmIdentifier('1.2.840.10045.4.3.2'),
        encodeOctetString(signature),
    ]);
    const signedData = encodeSequence([encodeInteger(1n), encodeSetOf([sha256]), encodeSequence([encodeObjectIdentifier('1.2.840.113549.1.7.1')]), encodeSetOf([signerInfo])]);
    return encodeSequence([encodeObjectIdentifier('1.2.840.113549.1.7.2'), encodeExplicit(0, signedData)]);
}

/** plain-keybag.p12 with its AuthenticatedSafe doubled — two usable keys — and its PBMAC1 recomputed. */
function twoKeyPkcs12(): Uint8Array {
    const pfx = decodeAsn1(fixtureBytes('plain-keybag.p12'));
    const authSafe = decodeAsn1(child(pfx, 1, 1, 0).content);
    const doubled = encodeSequence([...authSafe.children, ...authSafe.children].map((c) => c.bytes));
    const algorithm = child(pfx, 2, 0, 0);
    // PBMAC1 { keyDerivationFunc PBKDF2 { salt, iterations, keyLength, hmacWithSHA256 }, hmacWithSHA256 } (RFC 9579)
    const kdf = child(algorithm, 1, 0, 1);
    const key = pbkdf2Sync(ENV.PKINATIVE_PASSWORD, child(kdf, 0).content, int(child(kdf, 1)), int(child(kdf, 2)), 'sha256');
    const mac = new Uint8Array(createHmac('sha256', key).update(doubled).digest());
    return encodeSequence([
        child(pfx, 0).bytes,
        encodeSequence([child(pfx, 1, 0).bytes, encodeExplicit(0, encodeOctetString(doubled))]),
        encodeSequence([encodeSequence([algorithm.bytes, encodeOctetString(mac)]), child(pfx, 2, 1).bytes, child(pfx, 2, 2).bytes]),
    ]);
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe('cms sign — what reaches the SignedData', () => {
    it('writes the --content-type, --signed-attribute and --unsigned-attribute it is given', async () => {
        const dir = emptyDir();
        const signedAttr = join(dir, 'signed.der');
        const unsignedAttr = join(dir, 'unsigned.der');
        writeFileSync(signedAttr, encodeAttribute('1.2.3.4', [encodeObjectIdentifier('1.2.3.4.5')]));
        writeFileSync(unsignedAttr, encodeAttribute('1.2.3.6', [encodeObjectIdentifier('1.2.3.6.7')]));
        const out = join(dir, 's.p7s');
        const r = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem'),
            '--content-type', '1.2.840.113549.1.9.16.1.4', '--signed-attribute', signedAttr, '--unsigned-attribute', unsignedAttr, '-o', out]);
        expect(r.code).toBe(0);
        const sd = signedDataAt(out);
        expect(sd.contentType).toBe('1.2.840.113549.1.9.16.1.4');
        const signer = sd.signerInfos[0];
        expect(signer?.signedAttributes?.map((a) => a.oid)).toContain('1.2.3.4');
        expect(signer?.unsignedAttributes?.map((a) => a.oid)).toEqual(['1.2.3.6']);
    });

    it('refuses --hash SHA-1 as a usage error before any key is used, unless --allow-sha1', async () => {
        const args = ['cms', 'sign', '--content', fixture('content.txt'), '--cert', fixture('leaf.crt.pem'), '--key', fixture('leaf.key.pem'), '--hash', 'SHA-1', '--json'];
        const refused = await cli(args);
        expect(refused.code).toBe(2);
        expect(envelope(refused.stderr)).toMatchObject({ ok: false, error: { code: 'E_USAGE' } });
        expect((envelope(refused.stderr)['error'] as Record<string, unknown>)['pkiCode']).toBeUndefined();
        expect((await cli([...args, '--allow-sha1', '-o', join(emptyDir(), 's.p7s')])).code).toBe(0);
    });

    it('signs with the --salt-length of a --p12 RSA-PSS key', async () => {
        const out = join(emptyDir(), 'pss.p7s');
        const r = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--p12', fixture('rsa.p12'), '--rsa-scheme', 'pss', '--salt-length', '48', '-o', out], { env: ENV });
        expect(r.code).toBe(0);
        // RSASSA-PSS-params saltLength [2] INTEGER 48
        expect(hex(signedDataAt(out).signerInfos[0]?.signatureAlgorithm.der ?? new Uint8Array())).toContain('a203020130');
    });

    it('refuses a PKCS#12 that holds two usable keys', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'two.p12'), twoKeyPkcs12());
        const r = await cli(['cms', 'sign', '--content', fixture('content.txt'), '--p12', join(dir, 'two.p12'), '-o', join(dir, 's.p7s'), '--json'], { env: ENV });
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_INPUT', message: expect.stringMatching(/holds 2 usable keys/) } });
    });
});

describe('cms verify — what reaches the engine', () => {
    it('refuses an empty --content-digest as a usage error', async () => {
        const r = await cli(['cms', 'verify', fixture('detached.p7s'), '--content-digest', '0x', ...TRUST, '--at', AT, '--json']);
        expect(r.code).toBe(2);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
    });

    it('holds the signer to every --purpose', async () => {
        const r = await cli(['cms', 'verify', fixture('attached.p7s'), ...TRUST, '--at', AT, '--purpose', 'timeStamping', '--json']);
        expect(r.code).toBe(1);
        expect(envelope(r.stderr)).toMatchObject({ ok: false, error: { code: 'E_VERIFY_FAILED' } });
        expect(JSON.parse(r.stdout)).toMatchObject({ valid: false });
    });

    it('reads BER only under --ber', async () => {
        const dir = emptyDir();
        const der = fixtureBytes('attached.p7s');
        // 30 82 LL LL → 30 83 00 LL LL: a non-minimal length, valid BER, not DER.
        expect(hex(der.subarray(0, 2))).toBe('3082');
        writeFileSync(join(dir, 'ber.p7s'), Buffer.concat([Buffer.from([0x30, 0x83, 0x00]), der.subarray(2)]));
        const strict = await cli(['cms', 'verify', join(dir, 'ber.p7s'), ...TRUST, '--at', AT, '--json', '--summary']);
        expect(strict.code).toBe(1);
        expect(JSON.parse(strict.stdout)).toMatchObject({ valid: false, reasons: ['PKI_REASON_INPUT_MALFORMED'] });
        expect((await cli(['cms', 'verify', join(dir, 'ber.p7s'), ...TRUST, '--at', AT, '--ber'])).code).toBe(0);
    });
});

describe('cms verify-signer and add-attribute — inputs', () => {
    it('hands --content to a signer that has no signed attributes, and reads no content without --content', async () => {
        const dir = emptyDir();
        const p7s = join(dir, 'nosa.p7s');
        writeFileSync(p7s, noSignedAttributes());
        expect(parseSignedData(new Uint8Array(readFileSync(p7s))).signerInfos[0]?.signedAttributesDer).toBeUndefined();
        const withContent = await cli(['cms', 'verify-signer', p7s, '--cert', fixture('leaf.crt.pem'), '--content', fixture('content.txt'), '--json']);
        expect(withContent.code).toBe(0);
        expect(JSON.parse(withContent.stdout)).toEqual({ valid: true, index: 0 });
        // Without --content, stdin is not read as the content: the engine says the content is missing.
        const without = await cli(['cms', 'verify-signer', p7s, '--cert', fixture('leaf.crt.pem'), '--json'], { stdin: fixtureBytes('content.txt') });
        expect(without.code).toBe(2);
        expect(envelope(without.stderr)).toMatchObject({ error: { code: 'E_USAGE', pkiCode: 'PKI_API_MISUSE' } });
    });

    it('never reads the attribute from stdin', async () => {
        const r = await cli(['cms', 'add-attribute', fixture('attached.p7s'), '--json', '-o', join(emptyDir(), 'a.p7s')],
            { stdin: encodeAttribute('1.2.3.4', [encodeObjectIdentifier('1.2.3.4.5')]) });
        expect(r.code).toBe(2);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
    });
});

describe('cms inspect rendering', () => {
    it('names no time-stamp for a signer that carries none', () => {
        const alg = (oid: string) => ({ oid, parameters: undefined, der: new Uint8Array() });
        const text = renderSignedData({
            version: 1, contentType: '1.2.840.113549.1.7.1', content: undefined, digestAlgorithms: [alg('1.2.3.5')],
            certificates: [], crls: [], ocspResponses: [],
            signerInfos: [{ sid: { kind: 'subjectKeyIdentifier', keyIdentifier: new Uint8Array([0xab]) }, digestAlgorithm: alg('1.2.3.5'), signatureAlgorithm: alg('1.2.3.6'), signingTime: undefined, timeStampTokens: [] }],
        } as never);
        expect(text.split('\n').slice(-2)).toEqual(['  Signer 0: key id ab', '    1.2.3.5 / 1.2.3.6']);
    });
});

describe('tsp request — what reaches the TimeStampReq', () => {
    /** The fields of a TimeStampReq after its messageImprint: reqPolicy, nonce, certReq. */
    const optional = (der: Uint8Array): Node[] => decodeAsn1(der).children.slice(2);

    it('writes the --nonce, --policy and --no-cert-req it is given', async () => {
        const full = await cli(['tsp', 'request', '--digest', CONTENT_SHA256, '--nonce', '0x2a', '--policy', '1.2.3', '--no-cert-req']);
        expect(full.code).toBe(0);
        expect(optional(full.stdoutBytes).map((n) => hex(n.bytes))).toEqual(['06022a03', '02012a']);
        const bare = await cli(['tsp', 'request', '--digest', CONTENT_SHA256]);
        // certReq TRUE: the TSA is asked to include its certificate.
        expect(optional(bare.stdoutBytes).map((n) => hex(n.bytes))).toEqual(['0101ff']);
    });

    it('clears the top bit of a random nonce, and only that bit', async () => {
        vi.spyOn(webcrypto, 'getRandomValues').mockImplementation(<T>(array: T): T => {
            (array as Uint8Array).set([0xff, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
            return array;
        });
        const r = await cli(['tsp', 'request', '--digest', CONTENT_SHA256, '--nonce', 'random', '--json']);
        expect(r.code).toBe(0);
        expect(envelope(r.stderr)['nonce']).toBe(BigInt('0x7fdcba9876543210').toString());
        expect(optional(r.stdoutBytes).map((n) => hex(n.bytes))).toEqual(['02087fdcba9876543210', '0101ff']);
    });

    it('refuses --data with --digest even when the digest alone would do', async () => {
        const r = await cli(['tsp', 'request', '--data', fixture('content.txt'), '--digest', CONTENT_SHA256, '--json']);
        expect(r.code).toBe(2);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
    });
});

describe('tsp verify — inputs', () => {
    const verify = (args: string[], stdin?: Uint8Array) => cli(['tsp', 'verify', ...args, ...TRUST, '--at', AT, '--json'], stdin === undefined ? {} : { stdin });

    it('refuses an empty --digest, and hands a one-byte digest to the engine', async () => {
        const empty = await verify(['--token', fixture('content.tst'), '--digest', '0x']);
        expect(empty.code).toBe(2);
        expect(envelope(empty.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
        const short = await verify(['--token', fixture('content.tst'), '--digest', '00']);
        expect(short.code).toBe(1);
        expect(JSON.parse(short.stdout).reasons.map((x: { code: string }) => x.code)).toContain('PKI_REASON_TSP_IMPRINT_MISMATCH');
    });

    it('takes exactly one of --token and --response, never stdin by default', async () => {
        const both = await verify(['--token', fixture('content.tst'), '--response', fixture('content.tsr'), '--digest', CONTENT_SHA256]);
        expect(both.code).toBe(2);
        expect(envelope(both.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
        const neither = await verify(['--digest', CONTENT_SHA256], fixtureBytes('content.tsr'));
        expect(neither.code).toBe(2);
        expect(envelope(neither.stderr)).toMatchObject({ error: { code: 'E_USAGE' } });
        // The same digest verifies once the input is named.
        expect((await verify(['--token', fixture('content.tst'), '--digest', CONTENT_SHA256])).code).toBe(0);
    });
});
