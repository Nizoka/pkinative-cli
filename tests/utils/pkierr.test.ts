import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
    PkiCertificateError,
    PkiCmsError,
    PkiCryptoError,
    PkiEncodingError,
    PkiError,
    PkiKeyError,
    PkiLimitError,
    decodePem,
    parseCertificate,
} from 'pkinative';
import { CliError, ERROR_CODES, ErrorCode, usageError } from '../../src/utils/error.js';
import { PKI_ERROR_CODES, PKI_REMEDY, PKI_TO_CLI, UNVERIFIED_INTEGRITY_REMEDY, guard, guardAsync, isFsError, mapPkiError, pkcs12Failure, remedyFor } from '../../src/utils/pkierr.js';

const registry = JSON.parse(readFileSync('docs/data/pkinative/errors.json', 'utf8')) as { errors: { code: string }[] };

describe('CliError', () => {
    it('defaults the code from the exit code', () => {
        expect(new CliError('x', 2).code).toBe('E_USAGE');
        expect(new CliError('x').code).toBe('E_RUNTIME');
        expect(new CliError('x', 1, ErrorCode.IO, { pkiCode: 'P', detail: { a: 1 }, remedy: 'r', reasons: [] })).toMatchObject({
            exitCode: 1, code: 'E_IO', pkiCode: 'P', detail: { a: 1 }, remedy: 'r', reasons: [],
        });
        expect(usageError('u', 'r')).toMatchObject({ exitCode: 2, code: 'E_USAGE', remedy: 'r' });
        expect(usageError('u').remedy).toBeUndefined();
    });

    it('lists the 13 E_* codes', () => {
        expect(ERROR_CODES).toHaveLength(13);
        expect(new Set(ERROR_CODES).size).toBe(13);
    });
});

describe('PKI_TO_CLI', () => {
    it('maps exactly the 57 codes of the pinned registry', () => {
        expect(PKI_ERROR_CODES).toHaveLength(57);
        expect([...PKI_ERROR_CODES].sort()).toEqual(registry.errors.map((e) => e.code).sort());
    });

    it('maps every code to a known class, exit 2 only for usage', () => {
        for (const [code, [cli, exit]] of Object.entries(PKI_TO_CLI)) {
            expect(ERROR_CODES, code).toContain(cli);
            expect(exit === 2, code).toBe(cli === 'E_USAGE');
        }
    });

    it('names remedies only for registered codes', () => {
        for (const code of Object.keys(PKI_REMEDY)) expect(PKI_ERROR_CODES).toContain(code);
    });
});

describe('mapPkiError', () => {
    it('passes a CliError through', () => {
        const e = new CliError('x');
        expect(mapPkiError(e, 'ctx')).toBe(e);
    });

    it('maps a real engine refusal with its offset', () => {
        const e = mapPkiError(caught(() => parseCertificate(new Uint8Array([0x30, 0x05, 0x02]))), 'Cannot read');
        expect(e).toMatchObject({ code: 'E_PARSE', exitCode: 1, pkiCode: 'PKI_ASN1_TRUNCATED' });
        expect(e.message).toMatch(/^Cannot read: pkinative: /);
        expect(e.detail).toHaveProperty('offset');
    });

    it('maps the PEM label code with its CLI remedy', () => {
        const e = mapPkiError(caught(() => decodePem('-----BEGIN A-----\nAA==\n-----END A-----\n', { label: 'B' })), 'pem');
        expect(e).toMatchObject({ code: 'E_INPUT', pkiCode: 'PKI_PEM_UNEXPECTED_LABEL' });
        expect(remedyFor(e)).toMatch(/pem decode/);
    });

    it('carries limit details and names the --max flag', () => {
        const e = mapPkiError(new PkiLimitError('PKI_LIMIT_EXCEEDED', 'too deep', 'maxDepth', 2, 3), 'x');
        expect(e).toMatchObject({ code: 'E_LIMIT', detail: { limit: 'maxDepth', configured: 2, observed: 3 } });
        expect(e.remedy).toMatch(/^--max-depth/);
        const unknown = mapPkiError(new PkiLimitError('PKI_LIMIT_EXCEEDED', 'x', 'other', 1, 2), 'x');
        expect(unknown.remedy).toBeUndefined();
    });

    it('collects algorithm, path and offset details per class', () => {
        expect(mapPkiError(new PkiCryptoError('PKI_CRYPTO_ALGORITHM_REFUSED', 'sha1', '1.2.3'), 'x'))
            .toMatchObject({ code: 'E_SECURITY', detail: { algorithm: '1.2.3' } });
        expect(mapPkiError(new PkiCryptoError('PKI_CRYPTO_UNAVAILABLE', 'none'), 'x').detail).toBeUndefined();
        expect(mapPkiError(new PkiCertificateError('PKI_X509_NAME_INVALID', 'n', 'issuer', 4), 'x').detail)
            .toEqual({ path: 'issuer', offset: 4 });
        expect(mapPkiError(new PkiCmsError('PKI_CMS_STRUCTURE_INVALID', 'c', 'p'), 'x').detail).toEqual({ path: 'p' });
        expect(mapPkiError(new PkiKeyError('PKI_KEY_MAC_UNSUPPORTED', 'k', undefined, 1), 'x')).toMatchObject({ code: 'E_SECURITY', detail: { offset: 1 } });
        expect(mapPkiError(new PkiEncodingError('PKI_OID_INVALID', 'o'), 'x').detail).toBeUndefined();
    });

    it('maps an engine code it does not know to E_RUNTIME', () => {
        expect(mapPkiError(new PkiError('PKI_FUTURE_CODE' as never, 'new'), 'x')).toMatchObject({ code: 'E_RUNTIME', pkiCode: 'PKI_FUTURE_CODE' });
    });

    it('maps filesystem errors to E_IO without echoing the OS message', () => {
        const fs = Object.assign(new Error('ENOENT: secret detail'), { code: 'ENOENT', path: '/x' });
        expect(isFsError(fs)).toBe(true);
        const e = mapPkiError(fs, 'Cannot read');
        expect(e).toMatchObject({ code: 'E_IO', message: 'Cannot read: ENOENT (/x)' });
        expect(mapPkiError(Object.assign(new Error('x'), { code: 'EACCES' }), 'c').message).toBe('c: EACCES');
        expect(isFsError(Object.assign(new Error('x'), { code: 'ENOTFS' }))).toBe(false);
        expect(isFsError('ENOENT')).toBe(false);
    });

    it('maps anything else to E_RUNTIME', () => {
        expect(mapPkiError(new Error('boom'), 'c')).toMatchObject({ code: 'E_RUNTIME', message: 'c: boom' });
        expect(mapPkiError('str', 'c').message).toBe('c: str');
    });

    it('remedyFor prefers the explicit remedy and ignores unknown codes', () => {
        expect(remedyFor(new CliError('x', 1, undefined, { remedy: 'mine', pkiCode: 'PKI_ASN1_BOOLEAN_INVALID' }))).toBe('mine');
        expect(remedyFor(new CliError('x', 1, undefined, { pkiCode: 'PKI_ASN1_BOOLEAN_INVALID' }))).toMatch(/--ber/);
        expect(remedyFor(new CliError('x', 1, undefined, { pkiCode: 'PKI_INTERNAL' }))).toBeUndefined();
        expect(remedyFor(new CliError('x'))).toBeUndefined();
        // An inherited name is not a registered code.
        expect(remedyFor(new CliError('x', 1, undefined, { pkiCode: 'constructor' }))).toBeUndefined();
    });
});

describe('pkcs12Failure', () => {
    it('offers --allow-unverified-integrity only when the integrity reason is there', () => {
        const unverified = pkcs12Failure({ integrity: 'none', reasons: [{ code: 'PKI_REASON_PKCS12_INTEGRITY_UNVERIFIED' }] });
        expect(unverified).toMatchObject({ code: 'E_VERIFY_FAILED', remedy: UNVERIFIED_INTEGRITY_REMEDY });
        const other = pkcs12Failure({ integrity: 'ok', reasons: [{ code: 'PKI_REASON_SOMETHING_ELSE' }] });
        expect(other).toMatchObject({ code: 'E_VERIFY_FAILED', remedy: undefined, reasons: [{ code: 'PKI_REASON_SOMETHING_ELSE' }] });
        expect(other.message).not.toMatch(/integrity/);
    });
});

describe('guard', () => {
    it('returns the value or maps the failure', async () => {
        expect(guard('c', () => 1)).toBe(1);
        expect(() => guard('c', () => { throw new Error('x'); })).toThrow('c: x');
        await expect(guardAsync('c', async () => 2)).resolves.toBe(2);
        await expect(guardAsync('c', async () => { throw new Error('y'); })).rejects.toThrow('c: y');
    });
});

function caught(fn: () => unknown): unknown {
    try {
        fn();
    } catch (e) {
        return e;
    }
    throw new Error('expected a throw');
}
