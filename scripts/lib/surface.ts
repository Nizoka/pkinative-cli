// The surface matrix: how every one of pkinative's 294 exports is reached
// from the command line. Runtime exports (functions, classes, constants) are
// mapped by hand to the subcommands that call them; type exports are derived:
// a type is reached when its name appears in the signature of a reached
// export or of a reached type (the transitive closure over api.frozen.json),
// because its values then travel through that command's input or its
// ADR 0018 wire-form report. tests/docs/surface.test.ts holds the committed
// docs/data/core-exports.json to this module and to the source.

import apiFrozen from '../../docs/data/pkinative/api.frozen.json' with { type: 'json' };

export const RUNTIME_VIA: Readonly<Record<string, readonly string[]>> = {
    // errors: every engine failure is mapped by utils/pkierr.ts; explain documents them
    PkiError: ['explain', '*'],
    PkiEncodingError: ['explain', '*'],
    PkiCertificateError: ['explain', '*'],
    PkiLimitError: ['explain', '*'],
    PkiCryptoError: ['explain', '*'],
    PkiCmsError: ['explain', '*'],
    PkiKeyError: ['explain', '*'],
    // limits
    DEFAULT_PKI_LIMITS: ['limits', '*'],
    // asn1
    decodeAsn1: ['asn1 decode', 'oid decode'],
    decodeAsn1Sequence: ['asn1 decode'],
    readBoolean: ['asn1 decode'],
    readInteger: ['asn1 decode'],
    readSmallInteger: ['asn1 decode'],
    readEnumerated: ['asn1 decode'],
    readNull: ['asn1 decode'],
    readBitString: ['asn1 decode', 'fingerprint'],
    readOctetString: ['asn1 decode', 'ocsp check'],
    readObjectIdentifier: ['asn1 decode', 'oid decode'],
    readRelativeOid: ['asn1 decode', 'oid decode'],
    readString: ['asn1 decode'],
    readTime: ['asn1 decode'],
    encodeTlv: ['asn1 encode'],
    encodeSequence: ['asn1 encode'],
    encodeSet: ['asn1 encode'],
    encodeSetOf: ['asn1 encode'],
    encodeInteger: ['asn1 encode'],
    encodeEnumerated: ['asn1 encode'],
    encodeBoolean: ['asn1 encode'],
    encodeNull: ['asn1 encode'],
    encodeBitString: ['asn1 encode'],
    encodeNamedBits: ['asn1 encode'],
    encodeOctetString: ['asn1 encode'],
    encodeObjectIdentifier: ['asn1 encode', 'oid encode'],
    encodeRelativeOid: ['asn1 encode', 'oid encode'],
    encodeString: ['asn1 encode'],
    encodeTime: ['asn1 encode'],
    encodeAsn1Node: ['asn1 decode'],
    encodeExplicit: ['asn1 encode'],
    encodeImplicit: ['asn1 encode'],
    // oid
    encodeOid: ['oid encode'],
    decodeOid: ['oid decode'],
    isValidOid: ['oid validate'],
    getOidName: ['oid name', 'asn1 decode', 'cert inspect'],
    OID_REGISTRY: ['oid list', 'cert create'],
    // pem
    decodePem: ['pem decode', '*'],
    encodePem: ['pem encode', '*'],
    // fingerprint
    computeFingerprint: ['fingerprint', 'cert inspect', 'tsp request'],
    computeFingerprintAsync: ['fingerprint'],
    formatFingerprint: ['fingerprint', 'cert inspect'],
    computeKeyIdentifier: ['fingerprint', 'cert create'],
    shake256: ['fingerprint'],
    // x509-parse
    parseCertificate: ['cert inspect', '*'],
    getExtension: ['cert inspect', 'cert create'],
    decodeExtensionValue: ['cert decode-extension'],
    formatDistinguishedName: ['cert inspect', '*'],
    // x509-verify
    verifyCertificateSignature: ['cert verify-signature', 'cert create', 'chain validate', 'ocsp check'],
    verifySelfSignature: ['cert verify-signature', 'cert create'],
    canVerify: ['doctor'],
    // x509-create
    createCertificate: ['cert create'],
    createCertificationRequest: ['csr create'],
    canSign: ['doctor'],
    encodeSignatureAlgorithm: ['cert encode'],
    encodeAlgorithmIdentifier: ['cert encode'],
    encodeAttribute: ['cert encode'],
    encodeAuthorityKeyIdentifier: ['cert encode', 'cert create'],
    encodeBasicConstraints: ['cert encode', 'cert create', 'csr create'],
    encodeDistinguishedName: ['cert encode', 'cert create'],
    encodeExtendedKeyUsage: ['cert encode', 'cert create', 'csr create'],
    encodeExtension: ['cert encode'],
    encodeExtensions: ['cert encode'],
    encodeKeyUsage: ['cert encode', 'cert create', 'csr create'],
    encodeNameAttribute: ['cert encode'],
    encodeSubjectAltName: ['cert encode', 'cert create', 'csr create'],
    encodeSubjectKeyIdentifier: ['cert encode', 'cert create', 'csr create'],
    encodeSubjectPublicKeyInfo: ['cert encode'],
    encodeValidity: ['cert encode'],
    KEY_USAGE_BITS: ['cert create', 'cert encode'],
    // x509-csr
    parseCertificationRequest: ['csr inspect', 'fingerprint', 'cert create'],
    verifyCertificationRequest: ['csr verify', 'csr create'],
    // paths
    verifyCertificateChain: ['chain verify'],
    validateCertificatePath: ['chain validate'],
    buildCertificatePath: ['chain build'],
    // names and purposes
    checkServerName: ['cert check-name'],
    matchDnsName: ['cert match-name'],
    checkExtendedKeyUsage: ['cert check-purpose', 'ocsp check'],
    KEY_PURPOSES: ['cert check-purpose', 'chain verify', 'cert create', 'ocsp check'],
    ANY_EXTENDED_KEY_USAGE: ['cert check-purpose', 'cert create'],
    // crl
    parseCertificateList: ['crl inspect', 'crl check'],
    findRevocation: ['crl find'],
    verifyCrlSignature: ['crl verify-signature', 'crl check'],
    checkRevocation: ['crl check'],
    // ocsp
    createOcspRequest: ['ocsp request'],
    encodeOcspCertId: ['ocsp cert-id', 'ocsp check'],
    parseOcspResponse: ['ocsp inspect', 'ocsp check'],
    verifyOcspSignature: ['ocsp verify-signature', 'ocsp check'],
    checkOcspStatus: ['ocsp check'],
    OCSP_NONCE_OID: ['ocsp inspect'],
    // cms
    parseSignedData: ['cms inspect', 'cms sign', 'cms verify-signer', 'cms add-attribute', 'cms add-timestamp'],
    createSignedData: ['cms sign'],
    addUnsignedAttribute: ['cms add-attribute'],
    verifySignerInfoSignature: ['cms verify-signer', 'cms sign'],
    verifySignedData: ['cms verify'],
    // time-stamps
    createTimeStampRequest: ['tsp request'],
    parseTimeStampResponse: ['tsp inspect', 'cms add-timestamp'],
    parseTimeStampToken: ['tsp inspect'],
    parseTstInfo: ['tsp inspect'],
    verifyTimeStampToken: ['tsp verify'],
    addTimeStampToken: ['cms add-timestamp'],
    // keys
    parsePrivateKeyInfo: ['key inspect', 'cert create'],
    parseEncryptedPrivateKeyInfo: ['key inspect'],
    importPrivateKey: ['key check', 'cert create', 'csr create', 'cms sign'],
    decryptPrivateKey: ['key check', 'cert create', 'csr create', 'cms sign'],
    canDecrypt: ['doctor'],
    openPkcs12: ['p12 open', 'cert create', 'cert encode', 'csr create', 'cms sign'],
    parsePkcs12: ['p12 inspect', 'p12 bags', 'p12 verify-mac'],
    verifyPkcs12Mac: ['p12 verify-mac'],
    openSafeContents: ['p12 bags'],
};

export interface ExportEntry {
    readonly name: string;
    readonly kind: string;
    readonly reach: 'capability' | 'type-only';
    readonly via: readonly string[];
}

interface FrozenExport {
    readonly name: string;
    readonly kind: string;
    readonly signature: string;
}

const EXPORTS = (apiFrozen as { exports: FrozenExport[] }).exports;

/** The 294 entries: runtime exports from RUNTIME_VIA, types by signature closure. */
export function buildSurface(): ExportEntry[] {
    const via = new Map<string, Set<string>>();
    for (const e of EXPORTS) {
        if (e.kind !== 'type') via.set(e.name, new Set(RUNTIME_VIA[e.name] ?? []));
    }
    const types = EXPORTS.filter((e) => e.kind === 'type');
    const mentions = (signature: string, name: string): boolean => new RegExp(`\\b${name}\\b`).test(signature);
    let changed = true;
    while (changed) {
        changed = false;
        for (const t of types) {
            const into = via.get(t.name) ?? new Set<string>();
            for (const e of EXPORTS) {
                const from = via.get(e.name);
                if (from === undefined || from.size === 0 || e.name === t.name || !mentions(e.signature, t.name)) continue;
                for (const v of from) {
                    if (!into.has(v)) {
                        into.add(v);
                        changed = true;
                    }
                }
            }
            if (into.size > 0) via.set(t.name, into);
        }
    }
    return EXPORTS.map((e) => ({
        name: e.name,
        kind: e.kind,
        reach: e.kind === 'type' ? 'type-only' : 'capability',
        via: [...(via.get(e.name) ?? [])].sort(),
    }));
}

export function surfaceDocument(): object {
    const entries = buildSurface();
    return {
        $comment: 'Generated by scripts/build-surface.ts from pkinative 1.0.0 api.frozen.json; held by tests/docs/surface.test.ts. "*" means every command that reads or reports PKI objects.',
        schemaVersion: 1,
        pkinative: '1.0.0',
        counts: {
            exports: entries.length,
            capability: entries.filter((e) => e.reach === 'capability').length,
            typeOnly: entries.filter((e) => e.reach === 'type-only').length,
        },
        exports: entries,
    };
}
