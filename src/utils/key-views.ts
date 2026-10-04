// Curated, secret-free views of key material for `key` and `p12` reports.
//
// The engine results here carry secret bytes: PrivateKeyInfo.der is the
// plaintext key, a PKCS#12 keyBag or secretBag holds plaintext in valueDer,
// and Pkcs12.authenticatedSafe holds every unencrypted bag. Unlike every
// other command, these reports are therefore built field by field from an
// allow-list, never by serialising the engine object: no secret byte can
// reach stdout, an envelope or a log, whatever a future engine adds.

import {
    getOidName,
    parseCertificate,
    type EncryptedPrivateKeyInfo,
    type PasswordEncryption,
    type Pkcs12Mac,
    type PkiParseOptions,
    type PrivateKeyInfo,
    type SafeBag,
    type SigningKey,
} from '../core-bridge/index.js';
import { dn } from './render.js';
import { toHex, toWire } from './wire.js';

export function encryptionView(e: PasswordEncryption): Record<string, unknown> {
    return {
        scheme: e.scheme,
        algorithm: e.algorithm.oid,
        ...(e.pbes2 !== undefined ? {
            pbes2: {
                iterations: e.pbes2.iterations,
                prf: e.pbes2.prf,
                keyBits: e.pbes2.keyBits,
                cipher: getOidName(e.pbes2.cipherOid) ?? e.pbes2.cipherOid,
                saltBytes: e.pbes2.salt.length,
            },
        } : {}),
    };
}

export function privateKeyView(info: PrivateKeyInfo): Record<string, unknown> {
    return {
        format: 'pkcs8',
        version: info.version,
        kind: info.kind,
        ...(info.curve !== undefined ? { curve: info.curve } : {}),
        algorithm: info.algorithm.oid,
        attributes: info.attributes.map((a) => a.oid),
        publicKey: info.publicKey !== undefined,
    };
}

export function encryptedKeyView(e: EncryptedPrivateKeyInfo): Record<string, unknown> {
    return { format: 'encrypted-pkcs8', encryption: encryptionView(e.encryption), encryptedBytes: e.encryptedData.length };
}

export function macView(mac: Pkcs12Mac | undefined): Record<string, unknown> | null {
    if (mac === undefined) return null;
    return {
        kind: mac.kind,
        algorithm: mac.algorithm.oid,
        iterations: mac.iterations,
        ...(mac.pbmac1 !== undefined ? { pbmac1: { iterations: mac.pbmac1.iterations, prf: mac.pbmac1.prf, hmac: mac.pbmac1.hmac, keyLength: mac.pbmac1.keyLength } } : {}),
    };
}

/** A bag without its secret bytes: certificates by subject, keys by their algorithm only. */
export function bagView(bag: SafeBag, opts: PkiParseOptions): Record<string, unknown> {
    const view: Record<string, unknown> = { path: bag.path, kind: bag.kind, oid: bag.oid };
    if (bag.friendlyName !== undefined) view['friendlyName'] = bag.friendlyName;
    if (bag.localKeyId !== undefined) view['localKeyId'] = toHex(bag.localKeyId);
    if (bag.certificateDer !== undefined) {
        const der = bag.certificateDer;
        try {
            const cert = parseCertificate(der, opts);
            view['certificate'] = { subject: dn(cert.subject), issuer: dn(cert.issuer), serialNumber: cert.serialNumber.hex };
        } catch {
            view['certificate'] = { unreadable: true, bytes: der.length };
        }
    }
    if (bag.crlDer !== undefined) view['crlBytes'] = bag.crlDer.length;
    if (bag.privateKey !== undefined) view['key'] = privateKeyView(bag.privateKey);
    if (bag.encryptedKey !== undefined) view['key'] = encryptedKeyView(bag.encryptedKey);
    return view;
}

/** A signing key: its algorithm and the Web Crypto handle described (type, extractable, usages), never exported. */
export function signingKeyView(key: SigningKey): Record<string, unknown> {
    return { algorithm: key.algorithm, key: toWire(key.key) };
}
