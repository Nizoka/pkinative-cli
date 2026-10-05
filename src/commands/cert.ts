// `pkinative cert …` — X.509 certificates (RFC 5280).

import {
    computeKeyIdentifier,
    createCertificate,
    decodeExtensionValue,
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
    encodeSignatureAlgorithm,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    encodeSubjectPublicKeyInfo,
    encodeValidity,
    getExtension,
    matchDnsName,
    parseCertificate,
    checkExtendedKeyUsage,
    checkServerName,
    verifyCertificateSignature,
    verifySelfSignature,
    type Certificate,
    type DecodedExtensionKind,
    type PkiReason,
    type ServerIdentity,
} from '../core-bridge/index.js';
import { CERT_ENCODE_STRUCTURES } from './registry.js';
import { parseOptions, type Ctx } from '../context.js';
import { getStringFlag, getStringFlagAll, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { parseIp, parseNameAttribute, parseNameSpec } from '../utils/names.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiBundle, readPkiBytes, readPkiObject } from '../utils/pki-input.js';
import { dn, extensionLine, renderCertificate, renderVerdict } from '../utils/render.js';
import { loadSigner } from '../utils/signer.js';
import { readPublicKey, readSpki, type PublicKey } from '../utils/spki.js';
import { fromHex } from '../utils/wire.js';
import {
    buildExtensions,
    generalNames,
    hexValue,
    isSpec,
    keyUsages,
    nameOf,
    purposeOid,
    readJsonSpec,
    readJsonValue,
    serialNumber,
    specError,
    validity,
} from '../utils/x509-spec.js';

export const EXTENSION_KINDS: readonly DecodedExtensionKind[] = [
    'basicConstraints', 'keyUsage', 'extendedKeyUsage', 'subjectAltName', 'issuerAltName', 'subjectKeyIdentifier',
    'authorityKeyIdentifier', 'nameConstraints', 'certificatePolicies', 'policyMappings', 'policyConstraints',
    'inhibitAnyPolicy', 'authorityInfoAccess', 'subjectInfoAccess', 'crlDistributionPoints', 'freshestCRL',
    'signedCertificateTimestampList', 'ocspNoCheck', 'subjectDirectoryAttributes',
];

function inputPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0];
}

/** Read and parse one certificate. */
export async function readCertificate(ctx: Ctx, path: string | undefined, what = 'certificate', decodeExtensions = true): Promise<Certificate> {
    const obj = await readPkiObject(ctx, path, what, LABELS.certificate);
    return guard(`Cannot read the ${what}`, () => parseCertificate(obj.der, { ...parseOptions(ctx), decodeExtensions }));
}

/** Every certificate of every file of a repeatable flag. */
export async function readCertificates(ctx: Ctx, paths: readonly string[], what: string): Promise<Certificate[]> {
    const objects = await readPkiBundle(ctx, paths, what, LABELS.certificate);
    return objects.map((o) => guard(`Cannot read the ${what} in ${o.source}`, () => parseCertificate(o.der, parseOptions(ctx))));
}

async function inspect(ctx: Ctx): Promise<void> {
    const raw = hasFlag(ctx.args.flags, 'raw-extensions');
    const certificate = await readCertificate(ctx, inputPath(ctx), 'certificate', !raw);
    const kind = getStringFlag(ctx.args.flags, 'extension');
    if (kind !== undefined) {
        if (!(EXTENSION_KINDS as readonly string[]).includes(kind)) throw usageError(`--extension expects one of ${EXTENSION_KINDS.join(', ')}.`);
        if (raw) throw usageError('--extension reads a decoded extension; drop --raw-extensions.');
        const ext = guard('Cannot read the extension', () => getExtension(certificate, kind as DecodedExtensionKind));
        if (ext === undefined) throw new CliError(`The certificate has no ${kind} extension.`, 1, ErrorCode.NOT_FOUND);
        emitReport(ctx, ext, () => extensionLine(ext));
        return;
    }
    emitReport(ctx, certificate, () => renderCertificate(certificate), () => ({
        serialNumber: certificate.serialNumber.hex,
        issuer: dn(certificate.issuer),
        subject: dn(certificate.subject),
        notBefore: certificate.validity.notBefore.epochMilliseconds,
        notAfter: certificate.validity.notAfter.epochMilliseconds,
        publicKey: certificate.subjectPublicKeyInfo.kind,
        extensions: certificate.extensions.map((e) => e.kind),
    }));
}

async function decodeExtension(ctx: Ctx): Promise<void> {
    const oid = getStringFlag(ctx.args.flags, 'oid');
    if (oid === undefined) throw usageError('cert decode-extension needs --oid <oid>.');
    const hex = getStringFlag(ctx.args.flags, 'value');
    const path = getStringFlag(ctx.args.flags, 'input', 'i');
    if ((hex === undefined) === (path === undefined)) throw usageError('Give the extnValue content as --value <hex> or --input <file>, not both.');
    let value: Uint8Array;
    if (hex !== undefined) {
        const bytes = fromHex(hex);
        if (bytes === undefined) throw usageError(`--value "${hex}" is not hexadecimal.`);
        value = bytes;
    } else {
        value = await readPkiBytes(ctx, path, 'extension value');
    }
    const ext = guard('Cannot decode the extension', () => decodeExtensionValue(oid, value, { ...parseOptions(ctx), critical: hasFlag(ctx.args.flags, 'critical') }));
    emitReport(ctx, ext, () => extensionLine(ext));
}

async function verifySignature(ctx: Ctx): Promise<void> {
    const certificate = await readCertificate(ctx, inputPath(ctx));
    const issuerPath = getStringFlag(ctx.args.flags, 'issuer');
    const options = { requireAlgorithmMatch: !hasFlag(ctx.args.flags, 'allow-algorithm-mismatch'), allowSha1: ctx.opts.allowSha1 };
    const issuer = issuerPath === undefined ? undefined : await readCertificate(ctx, issuerPath, 'issuer certificate');
    const valid = await guardAsync('Cannot verify the signature', () => (issuer === undefined ? verifySelfSignature(certificate, options) : verifyCertificateSignature(certificate, issuer, options)));
    const what = issuer === undefined ? 'self-signature' : 'signature';
    emitReport(ctx, { valid, selfSigned: issuer === undefined }, () => renderVerdict(ctx.color, valid, what, []));
    if (!valid) throw new CliError(`The ${what} does not verify.`, 1, ErrorCode.VERIFY_FAILED);
}

async function checkName(ctx: Ctx): Promise<void> {
    const certificate = await readCertificate(ctx, inputPath(ctx));
    const host = getStringFlag(ctx.args.flags, 'host');
    const ip = getStringFlag(ctx.args.flags, 'ip');
    const given = host ?? ip;
    if (given === undefined || (host !== undefined && ip !== undefined)) throw usageError('Give the reference identity as --host <dns-name> or --ip <address>.');
    const reference: ServerIdentity = host !== undefined ? { kind: 'dns', value: host } : { kind: 'ip', value: parseIp(given, '--ip') };
    const chain = await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'chain'), 'chain certificate');
    const reasons = guard('Cannot check the name', () => checkServerName(certificate, reference, {
        allowCommonNameFallback: hasFlag(ctx.args.flags, 'allow-cn-fallback'),
        allowWildcards: !hasFlag(ctx.args.flags, 'no-wildcards'),
        ...(chain.length > 0 ? { path: [certificate, ...chain] } : {}),
    }));
    finishCheck(ctx, reasons, `name ${given}`);
}

function finishCheck(ctx: Ctx, reasons: readonly PkiReason[], what: string): void {
    const valid = reasons.length === 0;
    emitReport(ctx, { valid, reasons }, () => renderVerdict(ctx.color, valid, what, reasons));
    if (!valid) throw new CliError(`The ${what} check failed: ${reasons.map((r) => r.code).join(', ')}.`, 1, ErrorCode.CHECK_FAILED, { reasons });
}

async function matchName(ctx: Ctx): Promise<void> {
    const [presented, reference] = ctx.args.positionals;
    if (presented === undefined || reference === undefined) throw usageError('cert match-name takes <presented> <reference>.');
    const match = guard('Cannot match the names', () => matchDnsName(presented, reference, { allowWildcards: !hasFlag(ctx.args.flags, 'no-wildcards') }));
    emitReport(ctx, { match }, () => (match ? ctx.color.ok('match') : ctx.color.bad('no match')));
    if (!match) throw new CliError(`"${presented}" does not match "${reference}".`, 1, ErrorCode.CHECK_FAILED);
}

async function checkPurpose(ctx: Ctx): Promise<void> {
    const leaf = await readCertificate(ctx, inputPath(ctx));
    const purpose = getStringFlag(ctx.args.flags, 'purpose');
    if (purpose === undefined) throw usageError('cert check-purpose needs --purpose <name|oid|any>.');
    const oid = guard('--purpose', () => purposeOid(purpose, '--purpose'));
    const chain = await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'chain'), 'chain certificate');
    const reasons = guard('Cannot check the purpose', () => checkExtendedKeyUsage([leaf, ...chain], oid, {
        restrictIssuers: !hasFlag(ctx.args.flags, 'no-restrict-issuers'),
        requireExplicitPurpose: hasFlag(ctx.args.flags, 'require-explicit-purpose'),
    }));
    finishCheck(ctx, reasons, `purpose ${purpose}`);
}

async function create(ctx: Ctx): Promise<void> {
    const specPath = getStringFlag(ctx.args.flags, 'spec');
    if (specPath === undefined) throw usageError('cert create needs --spec <file.json>.');
    const spec = await readJsonSpec(ctx, specPath);
    const subject = nameOf(spec, 'subject');
    if (subject === undefined) throw specError('subject', 'is required');
    const issuerPath = getStringFlag(ctx.args.flags, 'issuer');
    const issuer = issuerPath === undefined ? undefined : await readCertificate(ctx, issuerPath, 'issuer certificate');
    if (issuer !== undefined && spec['issuer'] !== undefined) throw specError('issuer', 'comes from --issuer; drop it from the spec');
    const pubPath = getStringFlag(ctx.args.flags, 'public-key');
    const subjectKey = pubPath === undefined ? undefined : await readPublicKey(ctx, pubPath);
    const issuerKey = issuer === undefined ? undefined : readSpki(ctx, issuer.subjectPublicKeyInfo.der);
    const loaded = await loadSigner(ctx, { hint: issuerKey?.type ?? (spec['issuer'] === undefined ? subjectKey?.type : undefined), stdinTaken: specPath === '-' });
    const key: PublicKey | undefined = subjectKey ?? (issuer === undefined && loaded.publicKey !== undefined
        ? { spki: loaded.publicKey, ...readSpki(ctx, loaded.publicKey), from: 'spki' }
        : undefined);
    if (key === undefined) {
        throw usageError('The subject public key is needed: pass --public-key <cert|csr|public key> (it is derived from --key only for a self-signed certificate from an unencrypted key).');
    }
    const issuerKeyId = issuer !== undefined
        ? getExtension(issuer, 'subjectKeyIdentifier')?.keyIdentifier ?? computeKeyIdentifier(issuer.subjectPublicKeyInfo.publicKey.bytes)
        : spec['issuer'] === undefined ? computeKeyIdentifier(key.bits) : undefined;
    const extensions = buildExtensions(spec['extensions'], { subjectKeyBits: key.bits, issuerKeyId, defaults: { ski: true, aki: issuerKeyId !== undefined } });
    const specIssuer = nameOf(spec, 'issuer');
    const { notBefore, notAfter } = validity(spec);
    const der = await guardAsync('Cannot create the certificate', () => createCertificate({
        serialNumber: serialNumber(spec['serialNumber']),
        subject,
        ...(issuer !== undefined ? { issuerDer: issuer.subject.der } : specIssuer !== undefined ? { issuer: specIssuer } : {}),
        notBefore,
        notAfter,
        subjectPublicKey: key.spki,
        extensions,
    }, loaded.signer, { limits: ctx.opts.limits }));
    // The signature must verify under the issuer the certificate names: a key
    // that does not belong to --issuer would otherwise yield a dead certificate.
    const created = guard('Cannot read the new certificate', () => parseCertificate(der, parseOptions(ctx)));
    const opts = { allowSha1: ctx.opts.allowSha1 };
    const verified = issuer !== undefined
        ? await guardAsync('Cannot verify the new certificate', () => verifyCertificateSignature(created, issuer, opts))
        : specIssuer === undefined ? await guardAsync('Cannot verify the new certificate', () => verifySelfSignature(created, opts)) : undefined;
    if (verified === false) {
        throw new CliError(issuer !== undefined ? 'The signing key does not belong to the --issuer certificate.' : 'The signing key does not match the subject public key of a self-signed certificate.', 1, ErrorCode.INPUT);
    }
    ctx.status['serialNumber'] = created.serialNumber.hex;
    ctx.status['selfSigned'] = issuer === undefined && specIssuer === undefined;
    await emitArtifact(ctx, der, { label: 'CERTIFICATE', defaultEncoding: 'pem' });
}

async function encodeStructure(ctx: Ctx): Promise<void> {
    const [structure] = ctx.args.positionals;
    if (structure === undefined || !(CERT_ENCODE_STRUCTURES as readonly string[]).includes(structure)) {
        throw usageError(`cert encode takes one structure: ${CERT_ENCODE_STRUCTURES.join(', ')}.`);
    }
    if (structure === 'signature-algorithm') {
        const loaded = await loadSigner(ctx, { stdinTaken: false });
        await emitArtifact(ctx, guard('Cannot encode', () => encodeSignatureAlgorithm(loaded.signer)), { label: undefined, defaultEncoding: 'hex' });
        return;
    }
    const specPath = getStringFlag(ctx.args.flags, 'spec');
    if (specPath === undefined) throw usageError(`cert encode ${structure} needs --spec <file.json> (or "-").`);
    const spec = await readJsonValue(ctx, specPath);
    const obj = (): Readonly<Record<string, unknown>> => {
        if (!isSpec(spec)) throw specError('$', 'expected a JSON object');
        return spec;
    };
    // Required members are checked here, with the spec path in the message, so a
    // missing "algorithm" is E_INPUT and never the engine's "undefined is not an
    // OID" (audit B-05); `pkinative schema cert-encode-spec` documents them.
    const oidMember = (s: Readonly<Record<string, unknown>>, key: string): string => {
        const v = s[key];
        if (typeof v !== 'string' || !/^\d+(\.\d+)+$/.test(v)) throw specError(key, 'expected a dotted OID string');
        return v;
    };
    const der = guard(`Cannot encode the ${structure}`, () => {
        switch (structure) {
            case 'name': return encodeDistinguishedName(parseNameSpec(spec, 'spec $'), { limits: ctx.opts.limits });
            case 'name-attribute': return encodeNameAttribute(parseNameAttribute(spec, 'spec $'));
            case 'validity': {
                // An encoded Validity names its own start: no implicit 'now'.
                if (obj()['notBefore'] === undefined) throw specError('notBefore', 'required: the start of the validity period');
                const v = validity(obj());
                return encodeValidity(v.notBefore, v.notAfter);
            }
            case 'spki': {
                const s = obj();
                const params = s['parameters'] === undefined ? undefined : hexValue(s['parameters'], 'parameters');
                return encodeSubjectPublicKeyInfo(oidMember(s, 'algorithm'), hexValue(s['publicKey'], 'publicKey'), params);
            }
            case 'algorithm-identifier': {
                const s = obj();
                return s['parameters'] === undefined ? encodeAlgorithmIdentifier(oidMember(s, 'oid')) : encodeAlgorithmIdentifier(oidMember(s, 'oid'), hexValue(s['parameters'], 'parameters'));
            }
            case 'attribute': {
                const s = obj();
                const values = s['values'];
                if (!Array.isArray(values)) throw specError('values', 'expected an array of hex strings');
                return encodeAttribute(oidMember(s, 'oid'), values.map((v: unknown, i) => hexValue(v, `values[${i}]`)));
            }
            case 'extension': {
                const s = obj();
                return encodeExtension({ oid: oidMember(s, 'oid'), critical: s['critical'] === true, value: hexValue(s['value'], 'value') });
            }
            case 'extensions': return encodeExtensions(buildExtensions(spec, { subjectKeyBits: new Uint8Array(), issuerKeyId: undefined, defaults: { ski: false, aki: false } }), { limits: ctx.opts.limits });
            case 'basic-constraints': {
                const s = obj();
                const pathLen = s['pathLen'];
                if (typeof s['ca'] !== 'boolean') throw specError('ca', 'expected a boolean');
                if (pathLen !== undefined && (typeof pathLen !== 'number' || !Number.isSafeInteger(pathLen) || pathLen < 0)) throw specError('pathLen', 'expected a non-negative integer');
                return encodeBasicConstraints({ cA: s['ca'], ...(typeof pathLen === 'number' ? { pathLenConstraint: pathLen } : {}) });
            }
            case 'key-usage': return encodeKeyUsage(keyUsages(stringList(spec), '$'));
            case 'extended-key-usage': return encodeExtendedKeyUsage(stringList(spec).map((p) => purposeOid(p, '$')));
            case 'subject-alt-name': return encodeSubjectAltName(generalNames(spec, '$'));
            case 'subject-key-identifier': return encodeSubjectKeyIdentifier(hexValue(obj()['keyIdentifier'], 'keyIdentifier'));
            default: return encodeAuthorityKeyIdentifier(hexValue(obj()['keyIdentifier'], 'keyIdentifier'));
        }
    });
    await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'hex' });
}

function stringList(spec: unknown): string[] {
    if (!Array.isArray(spec) || !spec.every((v) => typeof v === 'string')) throw specError('$', 'expected an array of strings');
    return spec;
}

export async function cert(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'cert inspect': return inspect(ctx);
        case 'cert create': return create(ctx);
        case 'cert encode': return encodeStructure(ctx);
        case 'cert decode-extension': return decodeExtension(ctx);
        case 'cert verify-signature': return verifySignature(ctx);
        case 'cert check-name': return checkName(ctx);
        case 'cert match-name': return matchName(ctx);
        default: return checkPurpose(ctx);
    }
}
