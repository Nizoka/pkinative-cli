// The sample plan: one documented invocation per subcommand, run against the
// BUILT CLI by scripts/verify-samples.ts and pinned in
// tests/regression/baselines/samples.sha256.json. samples/<command>/<id>.sh
// and .ps1 are generated from this plan (scripts/generate-samples.ts), so the
// examples a user reads are the ones CI runs.
//
// Fingerprint modes:
//   stdout   SHA-256 of stdout (deterministic text or JSON: --at is pinned)
//   file     SHA-256 of the written artefact (deterministic: Ed25519, requests)
//   tbs      SHA-256 of the first element of the written DER (an ECDSA
//            signature is randomised; what was signed is not)
//   exit     only the exit code
//
// doctor has no sample: its verdict depends on the host (both outcomes are
// unit-tested in tests/commands/meta.test.ts).

export type SampleMode = 'stdout' | 'file' | 'tbs' | 'exit';

export interface Sample {
    readonly id: string;
    readonly command: string;
    readonly summary: string;
    /** Arguments after `pkinative`; $F = fixtures dir, $O = output dir. */
    readonly argv: readonly string[];
    readonly mode: SampleMode;
    /** The written artefact, relative to $O, for file / tbs modes. */
    readonly output?: string;
    readonly exit: 0 | 1 | 2;
    readonly env?: Readonly<Record<string, string>>;
}

const AT = '2027-01-01T00:00:00Z';
const PW = { PKINATIVE_PASSWORD: 'test-only-password' };

export const SAMPLES: readonly Sample[] = [
    // Encodings
    { id: 'pem-decode', command: 'pem', summary: 'List the PEM blocks of a file', argv: ['pem', 'decode', '$F/leaf.crt.pem', '--json'], mode: 'stdout', exit: 0 },
    { id: 'pem-encode', command: 'pem', summary: 'Wrap DER bytes in PEM', argv: ['pem', 'encode', '$F/leaf.crt.der', '--label', 'CERTIFICATE', '-o', '$O/leaf.pem'], mode: 'file', output: 'leaf.pem', exit: 0 },
    { id: 'oid-name', command: 'oid', summary: 'Name an OID', argv: ['oid', 'name', '1.2.840.10045.4.3.2', '--json'], mode: 'stdout', exit: 0 },
    { id: 'oid-encode', command: 'oid', summary: 'Encode an OID as a TLV', argv: ['oid', 'encode', '1.2.840.113549.1.1.11', '--tlv'], mode: 'stdout', exit: 0 },
    { id: 'oid-decode', command: 'oid', summary: 'Decode OID content octets', argv: ['oid', 'decode', '2a864886f70d01010b'], mode: 'stdout', exit: 0 },
    { id: 'oid-validate', command: 'oid', summary: 'Validate dotted OIDs (one is invalid)', argv: ['oid', 'validate', '2.5.4.3', '2.99.x'], mode: 'stdout', exit: 1 },
    { id: 'oid-list', command: 'oid', summary: 'Search the OID registry', argv: ['oid', 'list', '--filter', 'ecdsa', '--json'], mode: 'stdout', exit: 0 },
    { id: 'fingerprint', command: 'fingerprint', summary: 'SHA-256 fingerprint of a certificate', argv: ['fingerprint', '$F/leaf.crt.pem'], mode: 'stdout', exit: 0 },
    { id: 'fingerprint-key-id', command: 'fingerprint', summary: 'RFC 5280 key identifier of a public key', argv: ['fingerprint', '$F/leaf.pub.pem', '--key-id'], mode: 'stdout', exit: 0 },
    { id: 'asn1-decode', command: 'asn1', summary: 'Print the ASN.1 tree of a certificate', argv: ['asn1', 'decode', '$F/root.crt.pem'], mode: 'stdout', exit: 0 },
    { id: 'asn1-read', command: 'asn1', summary: 'Read one node of the tree', argv: ['asn1', 'decode', '$F/root.crt.der', '--path', '0.4.0', '--read', 'time', '--json'], mode: 'stdout', exit: 0 },
    { id: 'asn1-encode', command: 'asn1', summary: 'Encode a JSON node spec', argv: ['asn1', 'encode', '--spec', '$S/asn1-spec.json', '--encoding', 'hex'], mode: 'stdout', exit: 0 },
    // Certificates
    { id: 'cert-inspect', command: 'cert', summary: 'Decode a certificate', argv: ['cert', 'inspect', '$F/leaf.crt.pem'], mode: 'stdout', exit: 0 },
    { id: 'cert-extension', command: 'cert', summary: 'Print one decoded extension as JSON', argv: ['cert', 'inspect', '$F/leaf.crt.pem', '--extension', 'subjectAltName', '--json'], mode: 'stdout', exit: 0 },
    { id: 'cert-create-ca', command: 'cert', summary: 'Issue a self-signed Ed25519 CA', argv: ['cert', 'create', '--spec', '$S/ca.json', '--key', '$F/ed25519.key.pem', '-o', '$O/ca.pem'], mode: 'file', output: 'ca.pem', exit: 0 },
    { id: 'cert-create-leaf', command: 'cert', summary: 'Issue a leaf under that CA', argv: ['cert', 'create', '--spec', '$S/leaf.json', '--key', '$F/ed25519.key.pem', '--issuer', '$O/ca.pem', '--public-key', '$F/leaf.pub.pem', '-o', '$O/leaf-issued.pem'], mode: 'file', output: 'leaf-issued.pem', exit: 0 },
    { id: 'cert-encode', command: 'cert', summary: 'Encode a subjectAltName value', argv: ['cert', 'encode', 'subject-alt-name', '--spec', '$S/san.json'], mode: 'stdout', exit: 0 },
    { id: 'cert-decode-extension', command: 'cert', summary: 'Decode an extension value', argv: ['cert', 'decode-extension', '--oid', '2.5.29.19', '--value', '30030101ff', '--critical'], mode: 'stdout', exit: 0 },
    { id: 'cert-verify-signature', command: 'cert', summary: 'Verify a certificate signature against its issuer', argv: ['cert', 'verify-signature', '$F/leaf.crt.pem', '--issuer', '$F/inter.crt.pem'], mode: 'stdout', exit: 0 },
    { id: 'cert-check-name', command: 'cert', summary: 'Check a host name (wildcard SAN)', argv: ['cert', 'check-name', '$F/leaf.crt.pem', '--host', 'api.wild.example.test'], mode: 'stdout', exit: 0 },
    { id: 'cert-match-name', command: 'cert', summary: 'Match a presented DNS name', argv: ['cert', 'match-name', '*.example.test', 'a.b.example.test'], mode: 'stdout', exit: 1 },
    { id: 'cert-check-purpose', command: 'cert', summary: 'Check an extended key usage along a path', argv: ['cert', 'check-purpose', '$F/leaf.crt.pem', '--chain', '$F/inter.crt.pem', '--purpose', 'serverAuth'], mode: 'stdout', exit: 0 },
    { id: 'csr-inspect', command: 'csr', summary: 'Decode a request', argv: ['csr', 'inspect', '$F/leaf.csr.pem'], mode: 'stdout', exit: 0 },
    { id: 'csr-create', command: 'csr', summary: 'Create a request (ECDSA: the signed part is pinned)', argv: ['csr', 'create', '--spec', '$S/csr.json', '--key', '$F/leaf.key.pem', '--encoding', 'der', '-o', '$O/req.der'], mode: 'tbs', output: 'req.der', exit: 0 },
    { id: 'csr-verify', command: 'csr', summary: 'Verify a request', argv: ['csr', 'verify', '$F/leaf.csr.pem'], mode: 'stdout', exit: 0 },
    // Paths and revocation
    { id: 'chain-verify', command: 'chain', summary: 'One-call verdict with revocation', argv: ['chain', 'verify', '$F/leaf.crt.pem', '--untrusted', '$F/inter.crt.pem', '--trust', '$F/root.crt.pem', '--host', 'example.test', '--crl', '$F/inter.crl.pem', '--ocsp', '$F/leaf.ocsp.der', '--require-revocation', '--at', AT], mode: 'stdout', exit: 0 },
    { id: 'chain-verify-revoked', command: 'chain', summary: 'A revoked leaf fails the verdict', argv: ['chain', 'verify', '$F/revoked.crt.pem', '--untrusted', '$F/inter.crt.pem', '--trust', '$F/root.crt.pem', '--crl', '$F/inter.crl.pem', '--at', AT, '-q'], mode: 'stdout', exit: 1 },
    { id: 'chain-build', command: 'chain', summary: 'Find a path to a trust anchor', argv: ['chain', 'build', '$F/leaf.crt.pem', '--untrusted', '$F/inter.crt.pem', '--trust', '$F/root.crt.pem', '--at', AT, '--json', '--summary'], mode: 'stdout', exit: 0 },
    { id: 'chain-validate', command: 'chain', summary: 'Validate an ordered path', argv: ['chain', 'validate', '--path', '$F/leaf.crt.pem', '--path', '$F/inter.crt.pem', '--trust', '$F/root.crt.pem', '--at', AT], mode: 'stdout', exit: 0 },
    { id: 'crl-inspect', command: 'crl', summary: 'Decode a CRL', argv: ['crl', 'inspect', '$F/inter.crl.pem', '--json', '--summary'], mode: 'stdout', exit: 0 },
    { id: 'crl-find', command: 'crl', summary: 'Look a serial up in a CRL', argv: ['crl', 'find', '$F/inter.crl.der', '--serial', '1002'], mode: 'stdout', exit: 0 },
    { id: 'crl-verify-signature', command: 'crl', summary: 'Verify a CRL signature', argv: ['crl', 'verify-signature', '$F/inter.crl.der', '--issuer', '$F/inter.crt.pem'], mode: 'stdout', exit: 0 },
    { id: 'crl-check', command: 'crl', summary: 'Decide a status from a CRL', argv: ['crl', 'check', '$F/inter.crl.der', '--cert', '$F/leaf.crt.pem', '--issuer', '$F/inter.crt.pem', '--at', AT], mode: 'stdout', exit: 0 },
    { id: 'ocsp-request', command: 'ocsp', summary: 'Build an OCSP request', argv: ['ocsp', 'request', '--cert', '$F/leaf.crt.pem', '--issuer', '$F/inter.crt.pem', '-o', '$O/ocsp-req.der'], mode: 'file', output: 'ocsp-req.der', exit: 0 },
    { id: 'ocsp-cert-id', command: 'ocsp', summary: 'Encode a CertID', argv: ['ocsp', 'cert-id', '--cert', '$F/leaf.crt.pem', '--issuer', '$F/inter.crt.pem', '--hash', 'SHA-256'], mode: 'stdout', exit: 0 },
    { id: 'ocsp-inspect', command: 'ocsp', summary: 'Decode an OCSP response', argv: ['ocsp', 'inspect', '$F/leaf.ocsp.der'], mode: 'stdout', exit: 0 },
    { id: 'ocsp-verify-signature', command: 'ocsp', summary: 'Verify the responder signature', argv: ['ocsp', 'verify-signature', '$F/leaf.ocsp.der'], mode: 'stdout', exit: 0 },
    { id: 'ocsp-check', command: 'ocsp', summary: 'Decide a status from an OCSP response', argv: ['ocsp', 'check', '$F/revoked.ocsp.der', '--cert', '$F/revoked.crt.pem', '--issuer', '$F/inter.crt.pem', '--at', AT, '-q'], mode: 'stdout', exit: 1 },
    // Signatures and time-stamps
    { id: 'cms-sign', command: 'cms', summary: 'Sign detached (Ed25519: deterministic)', argv: ['cms', 'sign', '--content', '$F/content.txt', '--cert', '$O/ca.pem', '--key', '$F/ed25519.key.pem', '--detached', '--signing-time', AT, '-o', '$O/content.p7s'], mode: 'file', output: 'content.p7s', exit: 0 },
    { id: 'cms-verify', command: 'cms', summary: 'Verify an attached signature', argv: ['cms', 'verify', '$F/attached.p7s', '--trust', '$F/root.crt.pem', '--at', AT, '--json', '--summary'], mode: 'stdout', exit: 0 },
    { id: 'cms-inspect', command: 'cms', summary: 'Decode a SignedData', argv: ['cms', 'inspect', '$F/attached.p7s'], mode: 'stdout', exit: 0 },
    { id: 'cms-verify-signer', command: 'cms', summary: 'Verify one signer against a certificate', argv: ['cms', 'verify-signer', '$F/detached.p7s', '--cert', '$F/leaf.crt.pem', '--content', '$F/content.txt'], mode: 'stdout', exit: 0 },
    { id: 'cms-add-attribute', command: 'cms', summary: 'Add an unsigned attribute', argv: ['cms', 'add-attribute', '$O/content.p7s', '--attribute', '$S/attribute.der', '-o', '$O/content-attr.p7s'], mode: 'file', output: 'content-attr.p7s', exit: 0 },
    { id: 'cms-add-timestamp', command: 'cms', summary: 'Refuse a token that stamps the content, not the signature value', argv: ['cms', 'add-timestamp', '$F/attached.p7s', '--token', '$F/content.tsr', '-o', '$O/stamped.p7s'], mode: 'exit', exit: 1 },
    { id: 'tsp-request', command: 'tsp', summary: 'Build a time-stamp request', argv: ['tsp', 'request', '--data', '$F/content.txt', '--nonce', '42', '-o', '$O/req.tsq'], mode: 'file', output: 'req.tsq', exit: 0 },
    { id: 'tsp-inspect', command: 'tsp', summary: 'Decode a time-stamp response', argv: ['tsp', 'inspect', '$F/content.tsr'], mode: 'stdout', exit: 0 },
    { id: 'tsp-verify', command: 'tsp', summary: 'Verify a time-stamp against its request and data', argv: ['tsp', 'verify', '--response', '$F/content.tsr', '--request', '$F/content.tsq', '--data', '$F/content.txt', '--trust', '$F/root.crt.pem', '--at', AT, '-q'], mode: 'stdout', exit: 0 },
    // Keys
    { id: 'key-inspect', command: 'key', summary: 'Describe an encrypted key (no password needed)', argv: ['key', 'inspect', '$F/leaf.key.enc.pem', '--json'], mode: 'stdout', exit: 0 },
    { id: 'key-check', command: 'key', summary: 'Prove an encrypted key decrypts', argv: ['key', 'check', '$F/leaf.key.enc.pem', '--key-type', 'ec-p256', '--json'], mode: 'stdout', exit: 0, env: PW },
    { id: 'p12-inspect', command: 'p12', summary: 'Describe a PKCS#12 file', argv: ['p12', 'inspect', '$F/leaf.p12'], mode: 'stdout', exit: 0 },
    { id: 'p12-verify-mac', command: 'p12', summary: 'Verify the PBMAC1 integrity', argv: ['p12', 'verify-mac', '$F/leaf.p12'], mode: 'stdout', exit: 0, env: PW },
    { id: 'p12-bags', command: 'p12', summary: 'List the bags, decrypted', argv: ['p12', 'bags', '$F/leaf.p12'], mode: 'stdout', exit: 0, env: PW },
    { id: 'p12-open', command: 'p12', summary: 'Open a PKCS#12 and export its certificates', argv: ['p12', 'open', '$F/leaf.p12', '--certs-out', '$O/bundle.pem', '-q'], mode: 'file', output: 'bundle.pem', exit: 0, env: PW },
    // Meta
    { id: 'limits', command: 'limits', summary: 'The security bounds, one raised', argv: ['limits', '--max-chain-length', '16', '--json', '--summary'], mode: 'stdout', exit: 0 },
    { id: 'explain', command: 'explain', summary: 'Explain an engine code', argv: ['explain', 'PKI_CRYPTO_ALGORITHM_REFUSED', '--json'], mode: 'stdout', exit: 0 },
    { id: 'schema', command: 'schema', summary: 'The JSON Schema of a cert create spec', argv: ['schema', 'cert-spec'], mode: 'exit', exit: 0 },
    { id: 'completion', command: 'completion', summary: 'A bash completion script', argv: ['completion', 'bash'], mode: 'stdout', exit: 0 },
];

/** Inputs the samples read besides the PKI fixtures ($S). */
export const SAMPLE_INPUTS: Readonly<Record<string, string>> = {
    'asn1-spec.json': JSON.stringify({ type: 'sequence', children: [{ type: 'oid', value: '2.5.4.3' }, { type: 'string', stringType: 'utf8', value: 'pkinative' }] }, null, 2),
    'ca.json': JSON.stringify({ serialNumber: '0x5a', subject: { C: 'FR', O: 'pkinative samples', CN: 'Sample CA' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 3650, extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign', 'digitalSignature'] } }, null, 2),
    'leaf.json': JSON.stringify({ serialNumber: 4242, subject: { CN: 'sample.example.test' }, notBefore: '2026-01-01T00:00:00Z', validityDays: 397, extensions: { keyUsage: ['digitalSignature'], extendedKeyUsage: ['serverAuth'], subjectAltName: { dns: ['sample.example.test'] } } }, null, 2),
    'csr.json': JSON.stringify({ subject: { CN: 'request.example.test' }, extensions: { subjectAltName: { dns: ['request.example.test'] } } }, null, 2),
    'san.json': JSON.stringify({ dns: ['a.example.test'], ip: ['192.0.2.1'] }, null, 2),
};

/** DER inputs, as hex ($S). */
export const SAMPLE_BINARY_INPUTS: Readonly<Record<string, string>> = {
    // Attribute { 1.2.3.4, SET { OID 1.2.3.4.5 } }
    'attribute.der': '300d06032a0304310606042a030405',
};
