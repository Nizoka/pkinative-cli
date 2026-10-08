// The ONLY module that imports `pkinative`. Every engine symbol the CLI
// reaches enters here, grouped by the capability ids of pkinative's
// docs/data/surfaces.json, so tests/docs/surface.test.ts can prove that each
// of the 117 runtime exports is re-exported once and reached by a command.

export type * from 'pkinative';

export {
    // errors
    PkiError,
    PkiEncodingError,
    PkiCertificateError,
    PkiLimitError,
    PkiCryptoError,
    PkiCmsError,
    PkiKeyError,
    // limits
    DEFAULT_PKI_LIMITS,
    // asn1-decode
    decodeAsn1,
    decodeAsn1Sequence,
    // asn1-read
    readBoolean,
    readInteger,
    readSmallInteger,
    readEnumerated,
    readNull,
    readBitString,
    readOctetString,
    readObjectIdentifier,
    readRelativeOid,
    readString,
    readTime,
    // asn1-encode
    encodeTlv,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeInteger,
    encodeEnumerated,
    encodeBoolean,
    encodeNull,
    encodeBitString,
    encodeNamedBits,
    encodeOctetString,
    encodeObjectIdentifier,
    encodeRelativeOid,
    encodeString,
    encodeTime,
    encodeAsn1Node,
    encodeExplicit,
    encodeImplicit,
    // oid
    encodeOid,
    decodeOid,
    isValidOid,
    getOidName,
    OID_REGISTRY,
    // pem
    decodePem,
    encodePem,
    // fingerprint
    computeFingerprint,
    computeFingerprintAsync,
    formatFingerprint,
    computeKeyIdentifier,
    shake256,
    // x509-parse
    parseCertificate,
    getExtension,
    decodeExtensionValue,
    formatDistinguishedName,
    // x509-verify
    verifyCertificateSignature,
    verifySelfSignature,
    canVerify,
    // x509-create
    createCertificate,
    createCertificationRequest,
    canSign,
    encodeSignatureAlgorithm,
    encodeAlgorithmIdentifier,
    encodeAttribute,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeExtension,
    encodeExtensions,
    encodeKeyUsage,
    encodeNameAttribute,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    KEY_USAGE_BITS,
    // x509-csr
    parseCertificationRequest,
    verifyCertificationRequest,
    // x509-verify-chain
    verifyCertificateChain,
    // x509-path
    validateCertificatePath,
    buildCertificatePath,
    // x509-server-name
    checkServerName,
    matchDnsName,
    // x509-purpose
    checkExtendedKeyUsage,
    KEY_PURPOSES,
    ANY_EXTENDED_KEY_USAGE,
    // x509-crl
    parseCertificateList,
    findRevocation,
    verifyCrlSignature,
    checkRevocation,
    // x509-ocsp
    createOcspRequest,
    encodeOcspCertId,
    parseOcspResponse,
    verifyOcspSignature,
    checkOcspStatus,
    OCSP_NONCE_OID,
    // cms-signed-data
    parseSignedData,
    createSignedData,
    addUnsignedAttribute,
    verifySignerInfoSignature,
    verifySignedData,
    // cms-timestamp
    createTimeStampRequest,
    parseTimeStampResponse,
    parseTimeStampToken,
    parseTstInfo,
    verifyTimeStampToken,
    addTimeStampToken,
    // keys-pkcs8
    parsePrivateKeyInfo,
    parseEncryptedPrivateKeyInfo,
    importPrivateKey,
    decryptPrivateKey,
    canDecrypt,
    // keys-pkcs12
    openPkcs12,
    parsePkcs12,
    verifyPkcs12Mac,
    openSafeContents,
} from 'pkinative';
