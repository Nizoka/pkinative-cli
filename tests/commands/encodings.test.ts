import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AT, cli, emptyDir, envelope, fixture, fixtureBytes } from '../helpers/io.js';

// Oracles computed by OpenSSL 3.5.5 on the same fixtures.
const LEAF_SHA256 = '00:37:7D:D9:30:5C:C2:7F:EB:BD:1D:D3:C1:F8:5D:61:CD:49:ED:E6:04:30:74:BA:2B:7C:BA:09:9A:83:49:98';
const LEAF_SKI = '8C:82:55:89:3D:6F:73:6E:8E:C2:9A:EC:75:FE:C0:72:FA:38:31:74';

describe('pem decode', () => {
    it('lists the blocks of a bundle', async () => {
        const dir = emptyDir();
        const bundle = join(dir, 'b.pem');
        writeFileSync(bundle, readFileSync(fixture('leaf.crt.pem'), 'utf8') + readFileSync(fixture('leaf.key.pem'), 'utf8'));
        const r = await cli(['pem', 'decode', bundle]);
        expect(r.code).toBe(0);
        expect(r.stdout).toMatch(/^#0 {2}CERTIFICATE {2}701 bytes {2}at offset 0\n#1 {2}PRIVATE KEY {2}\d+ bytes {2}at offset \d+/);
        const json = await cli(['pem', 'decode', bundle, '--json', '--summary']);
        expect(JSON.parse(json.stdout)).toEqual({ blocks: [{ index: 0, label: 'CERTIFICATE', size: 701 }, { index: 1, label: 'PRIVATE KEY', size: 138 }] });
        expect(envelope(json.stderr)).toMatchObject({ ok: true, command: 'pem decode', blocks: 2 });
    });

    it('extracts one block as DER, hex or PEM', async () => {
        const der = await cli(['pem', 'decode', '-i', fixture('leaf.crt.pem'), '--index', '0']);
        expect(der.stdoutBytes).toEqual(fixtureBytes('leaf.crt.der'));
        const hex = await cli(['pem', 'decode', fixture('leaf.crt.pem'), '--index', '0', '--encoding', 'hex']);
        expect(hex.stdout).toMatch(/^308202b9/);
        const pem = await cli(['pem', 'decode', fixture('leaf.crt.pem'), '--index', '0', '--encoding', 'pem']);
        expect(pem.stdout).toBe(readFileSync(fixture('leaf.crt.pem'), 'utf8'));
    });

    it('refuses an out-of-range index and a label mismatch', async () => {
        const out = await cli(['pem', 'decode', fixture('leaf.crt.pem'), '--index', '3', '--json']);
        expect(out.code).toBe(1);
        expect(envelope(out.stderr)).toMatchObject({ error: { code: 'E_NOT_FOUND' } });
        const label = await cli(['pem', 'decode', fixture('leaf.crt.pem'), '--label', 'X509 CRL']);
        expect(label.code).toBe(1);
        expect(label.stderr).toMatch(/E_INPUT \(PKI_PEM_UNEXPECTED_LABEL\)/);
        expect(label.stderr).toMatch(/remedy: pkinative pem decode/);
    });

    it('reads PEM from stdin', async () => {
        const r = await cli(['pem', 'decode', '--json'], { stdin: readFileSync(fixture('root.crt.pem'), 'utf8') });
        expect(JSON.parse(r.stdout).blocks[0].label).toBe('CERTIFICATE');
    });

    it('refuses --output without --index rather than drop it (audit N-3)', async () => {
        for (const output of [['--output', 'out.der'], ['-o']]) {
            const r = await cli(['pem', 'decode', fixture('leaf.crt.pem'), ...output]);
            expect(r.code, output.join(' ')).toBe(2);
            expect(r.stderr, output.join(' ')).toMatch(/--output needs --index <n>/);
        }
    });
});

describe('pem encode', () => {
    it('wraps DER, identically to OpenSSL', async () => {
        const r = await cli(['pem', 'encode', fixture('leaf.crt.der'), '--label', 'CERTIFICATE']);
        expect(r.stdout).toBe(readFileSync(fixture('leaf.crt.pem'), 'utf8'));
    });

    it('needs a label, a valid one, and DER input', async () => {
        expect((await cli(['pem', 'encode', fixture('leaf.crt.der')])).code).toBe(2);
        expect((await cli(['pem', 'encode', fixture('leaf.crt.der'), '--label', 'bad-'])).stderr).toMatch(/PKI_PEM_LABEL_INVALID/);
        const pem = await cli(['pem', 'encode', fixture('leaf.crt.pem'), '--label', 'X']);
        expect(pem.code).toBe(1);
        expect(pem.stderr).toMatch(/already PEM/);
    });

    it('refuses --encoding, which encode does not take', async () => {
        expect((await cli(['pem', 'encode', fixture('leaf.crt.der'), '--label', 'X', '--encoding', 'der'])).stderr).toMatch(/Unknown flag --encoding for "pem encode"/);
    });
});

describe('oid', () => {
    it('names OIDs', async () => {
        const r = await cli(['oid', 'name', '2.5.4.3', '1.2.3.4', '--json']);
        expect(JSON.parse(r.stdout)).toEqual({ oids: [{ oid: '2.5.4.3', name: 'commonName' }, { oid: '1.2.3.4' }] });
        expect((await cli(['oid', 'name'])).code).toBe(2);
    });

    it('encodes content octets, TLV and relative OIDs', async () => {
        expect((await cli(['oid', 'encode', '1.2.840.113549'])).stdout).toBe('2a864886f70d\n');
        expect((await cli(['oid', 'encode', '1.2.840.113549', '--tlv'])).stdout).toBe('06062a864886f70d\n');
        expect((await cli(['oid', 'encode', '8571.3.2', '--tlv', '--relative'])).stdout).toBe('0d04c27b0302\n');
        expect((await cli(['oid', 'encode', '1.2', '--relative'])).stderr).toMatch(/--relative needs --tlv/);
        expect((await cli(['oid', 'encode', '1.2', '1.3'])).stderr).toMatch(/exactly one OID/);
        expect((await cli(['oid', 'encode', 'x.y'])).stderr).toMatch(/E_PARSE \(PKI_OID_INVALID\)/);
    });

    it('decodes hex, TLV files and relative OIDs', async () => {
        expect((await cli(['oid', 'decode', '2a864886f70d'])).stdout).toBe('1.2.840.113549\n');
        expect((await cli(['oid', 'decode', '550403'])).stdout).toBe('2.5.4.3  commonName\n');
        expect((await cli(['oid', 'decode', '0d04c27b0302', '--tlv', '--relative'])).stdout).toBe('8571.3.2\n');
        const dir = emptyDir();
        writeFileSync(join(dir, 'oid.der'), Buffer.from('0603550403', 'hex'));
        expect(JSON.parse((await cli(['oid', 'decode', '-i', join(dir, 'oid.der'), '--tlv', '--json'])).stdout)).toEqual({ oid: '2.5.4.3', name: 'commonName' });
    });

    it('refuses ambiguous or malformed decode input', async () => {
        expect((await cli(['oid', 'decode'])).code).toBe(2);
        expect((await cli(['oid', 'decode', '55', '-i', 'f'])).code).toBe(2);
        expect((await cli(['oid', 'decode', 'zz'])).stderr).toMatch(/not hexadecimal/);
        expect((await cli(['oid', 'decode', '0d0100', '--relative'])).stderr).toMatch(/--relative needs --tlv/);
        expect((await cli(['oid', 'decode', '80'])).code).toBe(1);
    });

    it('validates, failing with E_CHECK_FAILED after the report', async () => {
        const ok = await cli(['oid', 'validate', '1.2.3']);
        expect(ok.code).toBe(0);
        const bad = await cli(['oid', 'validate', '1.2.3', 'x.y', '--json']);
        expect(bad.code).toBe(1);
        expect(JSON.parse(bad.stdout)).toEqual({ oids: [{ oid: '1.2.3', valid: true }, { oid: 'x.y', valid: false }] });
        expect(envelope(bad.stderr)).toMatchObject({ error: { code: 'E_CHECK_FAILED' } });
    });

    it('lists the registry, filtered', async () => {
        const all = JSON.parse((await cli(['oid', 'list', '--json'])).stdout) as { registry: unknown[] };
        expect(all.registry.length).toBeGreaterThan(300);
        const some = await cli(['oid', 'list', '--filter', 'OCSPSIGNING']);
        expect(some.stdout).toMatch(/^1\.3\.6\.1\.5\.5\.7\.3\.9 +OCSPSigning +RFC 5280\n$/);
    });
});

describe('fingerprint', () => {
    it('matches OpenSSL on PEM and DER', async () => {
        expect((await cli(['fingerprint', fixture('leaf.crt.pem')])).stdout).toBe(`SHA-256 Fingerprint=${LEAF_SHA256}\n`);
        const json = JSON.parse((await cli(['fingerprint', '-i', fixture('leaf.crt.der'), '--json'])).stdout);
        expect(json).toEqual({ algorithm: 'SHA-256', fingerprint: LEAF_SHA256, hex: LEAF_SHA256.replace(/:/g, '').toLowerCase() });
    });

    it('formats and switches algorithm and implementation', async () => {
        const r = await cli(['fingerprint', fixture('leaf.crt.pem'), '--alg', 'SHA-1', '--separator', '', '--case', 'lower', '--webcrypto', '--json']);
        expect(JSON.parse(r.stdout).fingerprint).toMatch(/^[0-9a-f]{40}$/);
        expect(JSON.parse(r.stdout).label).toBe('CERTIFICATE');
    });

    it('computes the key identifier of a certificate, a request and a public key', async () => {
        for (const f of ['leaf.crt.der', 'leaf.crt.pem', 'leaf.pub.pem']) {
            expect((await cli(['fingerprint', fixture(f), '--key-id', '--json'])).stdout, f).toContain(LEAF_SKI);
        }
        const csr = JSON.parse((await cli(['fingerprint', fixture('leaf.csr.pem'), '--key-id', '--json'])).stdout);
        expect(csr).toMatchObject({ from: 'csr', keyIdentifier: LEAF_SKI });
        const csrDer = JSON.parse((await cli(['fingerprint', fixture('leaf.csr.der'), '--key-id', '--json'])).stdout);
        expect(csrDer.from).toBe('csr');
        const wide = JSON.parse((await cli(['fingerprint', fixture('leaf.crt.der'), '--key-id', '--alg', 'SHA-256', '--json'])).stdout);
        expect(wide.hex).toHaveLength(64);
    });

    it('refuses --key-id on something that holds no public key', async () => {
        const r = await cli(['fingerprint', fixture('leaf.crl.der') === '' ? '' : fixture('inter.crl.der'), '--key-id']);
        expect(r.code).toBe(1);
        expect(r.stderr).toMatch(/not a certificate, a request or a public key/);
        const dir = emptyDir();
        writeFileSync(join(dir, 'two.der'), Buffer.from('300603010100050000', 'hex').subarray(0, 8));
        writeFileSync(join(dir, 'pair.der'), Buffer.from('3006020101020102', 'hex'));
        expect((await cli(['fingerprint', join(dir, 'pair.der'), '--key-id'])).stderr).toMatch(/E_PARSE/);
        writeFileSync(join(dir, 'spki.pem'), '-----BEGIN PUBLIC KEY-----\nMAYCAQECAQI=\n-----END PUBLIC KEY-----\n');
        expect((await cli(['fingerprint', join(dir, 'spki.pem'), '--key-id'])).stderr).toMatch(/E_PARSE/);
        writeFileSync(join(dir, 'one.pem'), '-----BEGIN PUBLIC KEY-----\nMAMCAQE=\n-----END PUBLIC KEY-----\n');
        expect((await cli(['fingerprint', join(dir, 'one.pem'), '--key-id'])).stderr).toMatch(/not a SubjectPublicKeyInfo/);
    });

    it('computes SHAKE256 of any length', async () => {
        expect((await cli(['fingerprint', fixture('content.txt'), '--shake256', '16'])).stdout).toMatch(/^[0-9a-f]{32}\n$/);
        expect((await cli(['fingerprint', fixture('content.txt'), '--shake256', '0'])).code).toBe(2);
    });

    it('refuses mixed modes', async () => {
        expect((await cli(['fingerprint', fixture('leaf.crt.der'), '--key-id', '--shake256', '8'])).stderr).toMatch(/separate modes/);
        expect((await cli(['fingerprint', fixture('leaf.crt.der'), '--key-id', '--webcrypto'])).stderr).toMatch(/fingerprint mode only/);
        expect((await cli(['fingerprint', fixture('leaf.crt.der'), '--key-id', '--alg', 'SHA-512'])).code).toBe(2);
    });
});

describe('asn1 decode', () => {
    it('prints the tree like openssl asn1parse', async () => {
        const r = await cli(['asn1', 'decode', fixture('root.crt.pem')]);
        expect(r.stdout).toMatch(/^ {4}0:d=0 {2}hl=4 l= 467 cons: SEQUENCE\n/);
        expect(r.stdout).toContain('OBJECT IDENTIFIER  1.2.840.10045.4.3.2 (ecdsa-with-SHA256)');
        expect(r.stdout).toContain('PrintableString  "FR"');
        expect(r.stdout).toContain('UTCTime  260101000000Z');
        expect(r.stdout).toContain('BOOLEAN  true');
        expect(r.stdout).toMatch(/BIT STRING {2}[0-9a-f]{64}… \(\d+ bytes\)/);
        expect(r.stdout).toContain('[0]');
    });

    it('selects a node and reads it with every typed reader', async () => {
        const cases: [string, string, unknown][] = [
            ['0.1', 'integer', '1'],
            ['0.1', 'small-integer', 1],
            ['0.2.0', 'oid', '1.2.840.10045.4.3.2'],
            ['0.3.0.0.1', 'string', { stringType: 'printable', value: 'FR' }],
            ['0.4.0', 'time', { type: 'UTCTime', epochMilliseconds: Date.UTC(2026, 0, 1), text: '260101000000Z' }],
        ];
        for (const [path, type, value] of cases) {
            const r = await cli(['asn1', 'decode', fixture('root.crt.der'), '--path', path, '--read', type, '--json']);
            expect(JSON.parse(r.stdout), `${path} ${type}`).toMatchObject({ type, value });
        }
        const ext = await cli(['asn1', 'decode', fixture('root.crt.der'), '--path', '0.7.0.1.1', '--read', 'boolean']);
        expect(ext.stdout).toBe('true\n');
        const bits = await cli(['asn1', 'decode', fixture('root.crt.der'), '--path', '2', '--read', 'bit-string']);
        expect(bits.stdout).toMatch(/"unusedBits": 0/);
        const octets = await cli(['asn1', 'decode', fixture('root.crt.der'), '--path', '0.7.0.0.1', '--read', 'octet-string']);
        expect(octets.stdout).toMatch(/^[0-9a-f]+\n$/);
    });

    it('reads IMPLICIT-tagged strings and times with --string-type / --time-type', async () => {
        const dir = emptyDir();
        // [0] IMPLICIT PrintableString "FR", [1] IMPLICIT UTCTime 270101000000Z
        writeFileSync(join(dir, 'str.der'), Buffer.from('80024652', 'hex'));
        writeFileSync(join(dir, 'time.der'), Buffer.from(`810d${Buffer.from('270101000000Z').toString('hex')}`, 'hex'));
        const str = await cli(['asn1', 'decode', join(dir, 'str.der'), '--read', 'string', '--string-type', 'printable']);
        expect(str.stdout).toMatch(/"value": "FR"/);
        const time = await cli(['asn1', 'decode', join(dir, 'time.der'), '--read', 'time', '--time-type', 'UTCTime', '--json']);
        expect(JSON.parse(time.stdout).value.epochMilliseconds).toBe(Date.UTC(2027, 0, 1));
        const missing = await cli(['asn1', 'decode', join(dir, 'time.der'), '--read', 'time', '--json']);
        expect(missing.code).toBe(2);
        expect(envelope(missing.stderr)).toMatchObject({ error: { code: 'E_USAGE', pkiCode: 'PKI_API_MISUSE' } });
    });

    it('reads null, enumerated, relative-oid and refuses a wrong type', async () => {
        const dir = emptyDir();
        const write = (name: string, hex: string) => { writeFileSync(join(dir, name), Buffer.from(hex, 'hex')); return join(dir, name); };
        expect((await cli(['asn1', 'decode', write('null.der', '0500'), '--read', 'null'])).stdout).toBe('null\n');
        expect((await cli(['asn1', 'decode', write('enum.der', '0a0102'), '--read', 'enumerated'])).stdout).toBe('2\n');
        expect((await cli(['asn1', 'decode', write('rel.der', '0d04c27b0302'), '--read', 'relative-oid'])).stdout).toBe('8571.3.2\n');
        const wrong = await cli(['asn1', 'decode', join(dir, 'null.der'), '--read', 'integer', '--json']);
        expect(wrong.code).toBe(1);
        expect(envelope(wrong.stderr)).toMatchObject({ error: { code: 'E_PARSE', pkiCode: 'PKI_ASN1_UNEXPECTED_TAG' } });
        const tree = await cli(['asn1', 'decode', write('mix.der', '30170500 0a0102 0d04c27b0302 1f2201ff 6003020101 c00100'.replace(/ /g, ''))]);
        expect(tree.stdout).toContain('NULL  null');
        expect(tree.stdout).toContain('ENUMERATED  2');
        expect(tree.stdout).toContain('RELATIVE-OID  8571.3.2');
        expect(tree.stdout).toContain('UNIVERSAL 34');
        expect(tree.stdout).toContain('[APPLICATION 0]');
        expect(tree.stdout).toContain('[PRIVATE 0]');
        const bad = await cli(['asn1', 'decode', write('badbool.der', '3003010102')]);
        expect(bad.stdout).toContain('<unreadable: 02>');
    });

    it('decodes a sequence of objects and tolerates trailing bytes on request', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'two.der'), Buffer.from('05000500', 'hex'));
        const seq = await cli(['asn1', 'decode', join(dir, 'two.der'), '--sequence', '--json']);
        expect(JSON.parse(seq.stdout).nodes).toHaveLength(2);
        expect((await cli(['asn1', 'decode', join(dir, 'two.der'), '--sequence'])).stdout.trim().split('\n')).toHaveLength(2);
        expect((await cli(['asn1', 'decode', join(dir, 'two.der')])).stderr).toMatch(/PKI_ASN1_TRAILING_DATA/);
        expect((await cli(['asn1', 'decode', join(dir, 'two.der'), '--allow-trailing'])).code).toBe(0);
        expect((await cli(['asn1', 'decode', join(dir, 'two.der'), '--sequence', '--read', 'null'])).code).toBe(2);
    });

    it('re-encodes a node byte for byte', async () => {
        const r = await cli(['asn1', 'decode', fixture('leaf.crt.der'), '--reencode', '--json']);
        expect(r.stdoutBytes).toEqual(fixtureBytes('leaf.crt.der'));
        expect(envelope(r.stderr)).toMatchObject({ identical: true, bytes: 701 });
        const tbs = await cli(['asn1', 'decode', fixture('leaf.crt.pem'), '--path', '0', '--reencode', '--encoding', 'hex']);
        expect(tbs.stdout).toMatch(/^3082/);
        expect((await cli(['asn1', 'decode', fixture('leaf.crt.der'), '--reencode', '--read', 'integer'])).code).toBe(2);
    });

    it('refuses a bad path', async () => {
        expect((await cli(['asn1', 'decode', fixture('leaf.crt.der'), '--path', 'a.b'])).code).toBe(2);
        const missing = await cli(['asn1', 'decode', fixture('leaf.crt.der'), '--path', '0.99', '--json']);
        expect(envelope(missing.stderr)).toMatchObject({ error: { code: 'E_NOT_FOUND' } });
    });

    it('accepts BER only with --ber', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'ber.der'), Buffer.from('30800500 0000'.replace(/ /g, ''), 'hex'));
        const der = await cli(['asn1', 'decode', join(dir, 'ber.der')]);
        expect(der.stderr).toMatch(/PKI_ASN1_INDEFINITE_LENGTH_FORBIDDEN/);
        expect(der.stderr).toMatch(/remedy: --ber/);
        const ber = await cli(['asn1', 'decode', join(dir, 'ber.der'), '--ber']);
        expect(ber.stdout).toMatch(/l= inf cons: SEQUENCE/);
    });

    it('emits the node tree as wire JSON', async () => {
        const r = await cli(['asn1', 'decode', fixture('root.crt.der'), '--json', '--fields', 'tagNumber,children.tagNumber']);
        expect(JSON.parse(r.stdout)).toEqual({ tagNumber: 16, children: [{ tagNumber: 16 }, { tagNumber: 16 }, { tagNumber: 3 }] });
    });
});

describe('asn1 encode', () => {
    const spec = {
        type: 'sequence', children: [
            { type: 'boolean', value: true },
            { type: 'integer', value: '0x7f' },
            { type: 'integer', value: -129 },
            { type: 'integer', value: '-5' },
            { type: 'enumerated', value: 3 },
            { type: 'null' },
            { type: 'bit-string', hex: '0a', unusedBits: 1 },
            { type: 'bit-string', hex: '' },
            { type: 'named-bits', bits: [0, 5] },
            { type: 'octet-string', hex: '00ff' },
            { type: 'oid', value: '2.5.4.3' },
            { type: 'relative-oid', value: '8571.3.2' },
            { type: 'string', stringType: 'printable', value: 'FR' },
            { type: 'time', value: AT },
            { type: 'time', value: Date.UTC(2051, 0, 1), timeType: 'GeneralizedTime' },
            { type: 'set', children: [{ type: 'null' }] },
            { type: 'set-of', children: [{ type: 'integer', value: 2 }, { type: 'integer', value: 1 }] },
            { type: 'explicit', tag: 0, inner: { type: 'integer', value: 2 } },
            { type: 'implicit', tag: 1, class: 'context', inner: { type: 'octet-string', hex: 'aa' } },
            { type: 'tlv', class: 'private', tag: 5, constructed: false, hex: '01' },
            { type: 'der', hex: '0500' },
        ],
    };

    async function encode(value: unknown, extra: string[] = []) {
        const dir = emptyDir();
        writeFileSync(join(dir, 's.json'), JSON.stringify(value));
        return cli(['asn1', 'encode', '--spec', join(dir, 's.json'), '--encoding', 'hex', ...extra]);
    }

    it('encodes every node type, and the result decodes back', async () => {
        const r = await encode(spec);
        expect(r.code).toBe(0);
        const dir = emptyDir();
        writeFileSync(join(dir, 'o.der'), Buffer.from(r.stdout.trim(), 'hex'));
        const tree = await cli(['asn1', 'decode', join(dir, 'o.der')]);
        expect(tree.stdout).toContain('INTEGER  127');
        expect(tree.stdout).toContain('INTEGER  -129');
        expect(tree.stdout).toContain('UTCTime  270101000000Z');
        expect(tree.stdout).toContain('GeneralizedTime  20510101000000Z');
        expect(tree.stdout).toContain('[PRIVATE 5]');
        expect(tree.stdout).toMatch(/SET\n.*INTEGER {2}1\n.*INTEGER {2}2/);
    });

    it('reads the spec from stdin and a positional', async () => {
        const r = await cli(['asn1', 'encode', '-', '--encoding', 'pem', '--label', 'TEST'], { stdin: JSON.stringify({ type: 'null' }) });
        expect(r.stdout).toBe('-----BEGIN TEST-----\nBQA=\n-----END TEST-----\n');
        expect((await cli(['asn1', 'encode'])).code).toBe(2);
    });

    it('names the JSON path of a faulty node', async () => {
        const cases: [unknown, RegExp][] = [
            [[1], /\$: expected an object/],
            [{ type: 'frob' }, /\$\.type: unknown type "frob"/],
            [{ type: 'sequence', children: [{ type: 'integer', value: 1.5 }] }, /\$\.children\[0\]\.value: expected a safe integer/],
            [{ type: 'boolean', value: 'yes' }, /\$\.value: expected a boolean/],
            [{ type: 'bit-string', hex: 'zz' }, /\$\.hex: expected a hexadecimal string/],
            [{ type: 'bit-string', hex: '00', unusedBits: -1 }, /unusedBits/],
            [{ type: 'named-bits', bits: ['a'] }, /\$\.bits/],
            [{ type: 'string', stringType: 'klingon', value: 'x' }, /stringType: expected one of/],
            [{ type: 'explicit', tag: 0, class: 'weird', inner: { type: 'null' } }, /class: expected one of/],
            [{ type: 'sequence' }, /children: expected an array/],
            [{ type: 'der', hex: '0500ff' }, /PKI_ASN1_TRAILING_DATA/],
            [{ type: 'string', stringType: 'printable', value: 'é' }, /PKI_ASN1_STRING_INVALID|PKI_ASN1_VALUE_OUT_OF_RANGE/],
        ];
        for (const [value, message] of cases) {
            const r = await encode(value);
            expect(r.code, JSON.stringify(value)).toBe(1);
            expect(r.stderr, JSON.stringify(value)).toMatch(message);
        }
    });

    it('bounds nesting by --max-depth', async () => {
        let deep: unknown = { type: 'null' };
        for (let i = 0; i < 5; i++) deep = { type: 'sequence', children: [deep] };
        const r = await encode(deep, ['--max-depth', '3', '--json']);
        expect(envelope(r.stderr)).toMatchObject({ error: { code: 'E_LIMIT', remedy: expect.stringMatching(/--max-depth/) } });
    });

    it('refuses a spec that is not JSON', async () => {
        const r = await cli(['asn1', 'encode', '--spec', '-'], { stdin: '{nope' });
        expect(r.stderr).toMatch(/E_PARSE.*not valid UTF-8 JSON/);
    });
});

describe('text renderings and edge forms', () => {
    it('lists PEM headers under --pem-mode lax', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'h.pem'), '-----BEGIN THING-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nBQA=\n-----END THING-----\n');
        expect((await cli(['pem', 'decode', join(dir, 'h.pem')])).stderr).toMatch(/PKI_PEM_HEADERS_FORBIDDEN/);
        const lax = await cli(['pem', 'decode', join(dir, 'h.pem'), '--pem-mode', 'lax']);
        expect(lax.stdout).toMatch(/headers: Proc-Type, DEK-Info/);
    });

    it('renders oid name and validate as text', async () => {
        expect((await cli(['oid', 'name', '2.5.4.3', '1.2.3.4'])).stdout).toBe('2.5.4.3  commonName\n1.2.3.4  (not registered)\n');
        const bad = await cli(['oid', 'validate', '1.2', 'x']);
        expect(bad.stdout).toBe('valid    1.2\ninvalid  x\n');
        expect((await cli(['oid', 'validate', '1.2'], { env: { FORCE_COLOR: '1' } })).stdout).toContain('\u001b[32m');
    });

    it('renders a key identifier as text', async () => {
        expect((await cli(['fingerprint', fixture('leaf.crt.der'), '--key-id'])).stdout).toMatch(/^SHA-1 key identifier \(certificate\): 8C:82/);
    });

    it('shows an unregistered OID as dotted only', async () => {
        const dir = emptyDir();
        writeFileSync(join(dir, 'o.der'), Buffer.from('06032a0304', 'hex'));
        expect((await cli(['asn1', 'decode', join(dir, 'o.der')])).stdout).toMatch(/OBJECT IDENTIFIER {2}1\.2\.3\.4\n$/);
    });
});

describe('subcommand dispatch', () => {
    it('requires a subcommand, and refuses an unknown one', async () => {
        const none = await cli(['pem']);
        expect(none.code).toBe(2);
        expect(none.stderr).toMatch(/"pem" needs a subcommand: decode, encode/);
        const unknown = await cli(['pem', 'frob']);
        expect(unknown.code).toBe(2);
        expect(unknown.stderr).toMatch(/Unknown subcommand "pem frob"\. Subcommands: decode, encode/);
        expect((await cli(['pem', '--help'])).stdout).toMatch(/^pkinative pem —/);
        expect((await cli(['oid', 'list', '-h'])).stdout).toMatch(/^pkinative oid —/);
    });
});
