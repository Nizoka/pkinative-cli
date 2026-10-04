// A public key from whatever the user has at hand: a certificate, a PKCS#10
// request, or a bare SubjectPublicKeyInfo (`PUBLIC KEY` PEM). pkinative never
// exports a key, so the CLI takes the public half from one of these.

import { decodeAsn1, parseCertificate, parseCertificationRequest, readBitString } from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { CliError, ErrorCode } from './error.js';
import { guard, mapPkiError } from './pkierr.js';
import { LABELS, type PkiObject } from './pki-input.js';

export interface PublicKey {
    /** The SubjectPublicKeyInfo DER. */
    readonly spki: Uint8Array;
    /** The BIT STRING content of the key (what computeKeyIdentifier hashes). */
    readonly bits: Uint8Array;
    /** Where it came from. */
    readonly from: 'certificate' | 'csr' | 'spki';
}

function fromSpki(ctx: Ctx, der: Uint8Array): PublicKey {
    const node = guard('Cannot read the public key', () => decodeAsn1(der, parseOptions(ctx)));
    const bitString = node.children[1];
    if (node.children.length !== 2 || bitString === undefined) {
        throw new CliError('Cannot read the public key: not a SubjectPublicKeyInfo (SEQUENCE { algorithm, subjectPublicKey }).', 1, ErrorCode.PARSE);
    }
    const bits = guard('Cannot read the public key', () => readBitString(bitString, parseOptions(ctx)));
    return { spki: der, bits: bits.bytes, from: 'spki' };
}

/** Extract the public key of a certificate, a CSR or an SPKI object. */
export function publicKeyOf(ctx: Ctx, obj: PkiObject): PublicKey {
    if (obj.label !== undefined && (LABELS.publicKey as readonly string[]).includes(obj.label)) return fromSpki(ctx, obj.der);
    if (obj.label !== undefined && (LABELS.csr as readonly string[]).includes(obj.label)) {
        const csr = guard('Cannot read the request', () => parseCertificationRequest(obj.der, parseOptions(ctx)));
        return { spki: csr.subjectPublicKeyInfo.der, bits: csr.subjectPublicKeyInfo.publicKey.bytes, from: 'csr' };
    }
    if (obj.label !== undefined) {
        const cert = guard('Cannot read the certificate', () => parseCertificate(obj.der, parseOptions(ctx)));
        return { spki: cert.subjectPublicKeyInfo.der, bits: cert.subjectPublicKeyInfo.publicKey.bytes, from: 'certificate' };
    }
    // DER of unknown kind: an SPKI has two top-level members, a certificate
    // and a request three; a request is tried when the certificate reader refuses.
    const top = guard('Cannot read the public key', () => decodeAsn1(obj.der, parseOptions(ctx)));
    if (top.children.length === 2) return fromSpki(ctx, obj.der);
    try {
        const cert = parseCertificate(obj.der, parseOptions(ctx));
        return { spki: cert.subjectPublicKeyInfo.der, bits: cert.subjectPublicKeyInfo.publicKey.bytes, from: 'certificate' };
    } catch (certError) {
        try {
            const csr = parseCertificationRequest(obj.der, parseOptions(ctx));
            return { spki: csr.subjectPublicKeyInfo.der, bits: csr.subjectPublicKeyInfo.publicKey.bytes, from: 'csr' };
        } catch {
            throw mapPkiError(certError, `${obj.source} is not a certificate, a request or a public key`);
        }
    }
}

