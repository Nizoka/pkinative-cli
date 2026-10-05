// `pkinative ocsp request|cert-id|inspect|verify-signature|check` — OCSP
// (RFC 6960). Offline: the CLI writes the request and judges the response;
// sending one to a responder is the caller's (curl --data-binary @req.der).

import { webcrypto } from 'node:crypto';
import {
    checkExtendedKeyUsage,
    checkOcspStatus,
    createOcspRequest,
    decodeAsn1,
    encodeOcspCertId,
    KEY_PURPOSES,
    OCSP_NONCE_OID,
    parseCertificate,
    parseOcspResponse,
    readOctetString,
    verifyCertificateSignature,
    verifyOcspSignature,
    type Asn1Node,
    type Certificate,
    type OcspBasicResponse,
    type OcspHashAlgorithm,
    type OcspResponse,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getIntFlag, getStringFlag, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { dn, renderVerdict } from '../utils/render.js';
import { formatInstant, parseInstant } from '../utils/time.js';
import { fromHex, toHex } from '../utils/wire.js';
import { readCertificate } from './cert.js';

const HASH_OIDS: Readonly<Record<string, OcspHashAlgorithm>> = {
    '1.3.14.3.2.26': 'SHA-1',
    '2.16.840.1.101.3.4.2.1': 'SHA-256',
};

async function subjectAndIssuer(ctx: Ctx): Promise<{ certificate: Certificate; issuer: Certificate }> {
    const certPath = getStringFlag(ctx.args.flags, 'cert') ?? ctx.args.positionals[0];
    const issuerPath = getStringFlag(ctx.args.flags, 'issuer');
    if (issuerPath === undefined) throw usageError(`${ctx.command} needs --issuer <cert>: the CA that issued the certificate.`);
    return { certificate: await readCertificate(ctx, certPath), issuer: await readCertificate(ctx, issuerPath, 'issuer certificate') };
}

function hashFlag(ctx: Ctx): OcspHashAlgorithm | undefined {
    return getChoiceFlag(ctx.args.flags, 'hash', ['SHA-1', 'SHA-256'] as const);
}

function nonceFlag(ctx: Ctx): Uint8Array | undefined {
    const raw = getStringFlag(ctx.args.flags, 'nonce');
    if (raw === undefined) return undefined;
    if (raw === 'random') return webcrypto.getRandomValues(new Uint8Array(16));
    const bytes = fromHex(raw);
    if (bytes === undefined) throw usageError(`--nonce expects "random" or hexadecimal, got "${raw}".`);
    if (bytes.length < 1 || bytes.length > 32) throw usageError(`--nonce takes 1 to 32 octets (RFC 8954 §2.1), got ${bytes.length}.`);
    return bytes;
}

async function request(ctx: Ctx): Promise<void> {
    const { certificate, issuer } = await subjectAndIssuer(ctx);
    const nonce = nonceFlag(ctx);
    const hash = hashFlag(ctx);
    const der = guard('Cannot create the OCSP request', () => createOcspRequest(certificate, issuer, {
        ...(hash !== undefined ? { hashAlgorithm: hash } : {}),
        ...(nonce !== undefined ? { nonce } : {}),
    }));
    if (nonce !== undefined) ctx.status['nonce'] = toHex(nonce);
    await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'der' });
}

async function certId(ctx: Ctx): Promise<void> {
    const { certificate, issuer } = await subjectAndIssuer(ctx);
    await emitArtifact(ctx, guard('Cannot encode the CertID', () => encodeOcspCertId(certificate, issuer, hashFlag(ctx))), { label: undefined, defaultEncoding: 'hex' });
}

async function readResponse(ctx: Ctx): Promise<OcspResponse> {
    const obj = await readPkiObject(ctx, getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0], 'OCSP response', LABELS.any);
    return guard('Cannot read the OCSP response', () => parseOcspResponse(obj.der, parseOptions(ctx)));
}

export function renderOcsp(response: OcspResponse): string {
    const basic = response.basicResponse;
    if (basic === undefined) return `OCSP response: ${response.status}`;
    const responder = basic.responderId.kind === 'byName' ? 'by name' : 'by key';
    return [
        `OCSP response: ${response.status}`,
        `  Produced at:  ${formatInstant(basic.producedAt.epochMilliseconds)}`,
        `  Responder:    ${responder}`,
        `  Certificates: ${basic.certificates.length}`,
        `  Nonce:        ${basic.extensions.some((e) => e.oid === OCSP_NONCE_OID) ? 'present' : 'absent'}`,
        ...basic.responses.map((r) => `  serial ${r.certId.serialNumber.hex}: ${r.status.kind}${r.status.kind === 'revoked' ? ` at ${formatInstant(r.status.revocationTime.epochMilliseconds)}` : ''}  (this ${formatInstant(r.thisUpdate.epochMilliseconds)}${r.nextUpdate !== undefined ? `, next ${formatInstant(r.nextUpdate.epochMilliseconds)}` : ''})`),
    ].join('\n');
}

async function inspect(ctx: Ctx): Promise<void> {
    const response = await readResponse(ctx);
    emitReport(ctx, response, () => renderOcsp(response), () => ({
        status: response.status,
        responses: response.basicResponse?.responses.map((r) => ({ serial: r.certId.serialNumber.hex, status: r.status.kind })) ?? [],
    }));
}

function basicOf(response: OcspResponse): OcspBasicResponse {
    if (response.basicResponse === undefined) {
        throw new CliError(`The OCSP response status is "${response.status}": it carries no signed answer.`, 1, ErrorCode.CHECK_FAILED);
    }
    return response.basicResponse;
}

/** The responder candidates: --responder, else the certificates the response embeds. */
async function responders(ctx: Ctx, basic: OcspBasicResponse, fallback: readonly Certificate[]): Promise<Certificate[]> {
    const path = getStringFlag(ctx.args.flags, 'responder');
    if (path !== undefined) return [await readCertificate(ctx, path, 'responder certificate')];
    const embedded = basic.certificates.map((der) => guard('Cannot read a certificate embedded in the response', () => parseCertificate(der, parseOptions(ctx))));
    return [...embedded, ...fallback];
}

async function findSigner(basic: OcspBasicResponse, candidates: readonly Certificate[]): Promise<Certificate | undefined> {
    for (const c of candidates) {
        if (await guardAsync('Cannot verify the OCSP signature', () => verifyOcspSignature(basic, c))) return c;
    }
    return undefined;
}

async function verifySignature(ctx: Ctx): Promise<void> {
    const basic = basicOf(await readResponse(ctx));
    const signer = await findSigner(basic, await responders(ctx, basic, []));
    const valid = signer !== undefined;
    emitReport(ctx, { valid, ...(signer !== undefined ? { signer: dn(signer.subject) } : {}) }, () => renderVerdict(ctx.color, valid, 'OCSP signature', []));
    if (!valid) throw new CliError('No responder certificate verifies the OCSP signature.', 1, ErrorCode.VERIFY_FAILED);
}

/**
 * RFC 6960 §4.2.2.2: the CA itself, or a delegate the CA issued that carries
 * id-kp-OCSPSigning. --responder-trusted states an out-of-band trust instead.
 */
async function authorized(ctx: Ctx, signer: Certificate, issuer: Certificate): Promise<boolean> {
    if (hasFlag(ctx.args.flags, 'responder-trusted')) return true;
    if (Buffer.compare(signer.der, issuer.der) === 0) return true;
    const issuedByCa = await guardAsync('Cannot verify the responder certificate', () => verifyCertificateSignature(signer, issuer, { allowSha1: ctx.opts.allowSha1 }));
    const eku = guard('Cannot check the responder purpose', () => checkExtendedKeyUsage([signer], KEY_PURPOSES.ocspSigning, { restrictIssuers: false, requireExplicitPurpose: true }));
    return issuedByCa && eku.length === 0;
}

async function check(ctx: Ctx): Promise<void> {
    const response = await readResponse(ctx);
    const certPath = getStringFlag(ctx.args.flags, 'cert');
    const issuerPath = getStringFlag(ctx.args.flags, 'issuer');
    if (certPath === undefined || issuerPath === undefined) throw usageError('ocsp check needs --cert <file> and --issuer <file>.');
    const certificate = await readCertificate(ctx, certPath);
    const issuer = await readCertificate(ctx, issuerPath, 'issuer certificate');
    const basic = response.basicResponse;
    // The CertID is recomputed with the hash the responder answered with, unless --hash says otherwise.
    const answered = basic?.responses.find((r) => Buffer.compare(r.certId.serialNumber.bytes, certificate.serialNumber.bytes) === 0);
    const hash = hashFlag(ctx) ?? (answered === undefined ? undefined : HASH_OIDS[answered.certId.hashAlgorithm.oid]) ?? 'SHA-1';
    const idNode = guard('Cannot compute the CertID', () => decodeAsn1(encodeOcspCertId(certificate, issuer, hash), parseOptions(ctx)));
    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }, from our own encoder.
    const expected = {
        issuerNameHash: readOctetString(idNode.children[1] as Asn1Node, parseOptions(ctx)),
        issuerKeyHash: readOctetString(idNode.children[2] as Asn1Node, parseOptions(ctx)),
        serialNumber: certificate.serialNumber.bytes,
    };
    const signer = basic === undefined ? undefined : await findSigner(basic, await responders(ctx, basic, [issuer]));
    const responderAuthorized = signer === undefined ? undefined : await authorized(ctx, signer, issuer);
    const nonce = nonceFlag(ctx);
    const stale = getIntFlag(ctx.args.flags, 'stale-tolerance');
    const future = getIntFlag(ctx.args.flags, 'future-tolerance');
    const at = getStringFlag(ctx.args.flags, 'at');
    const reasons = checkOcspStatus({
        response,
        expected,
        at: at === undefined ? Date.now() : parseInstant(at, 'at'),
        ...(basic !== undefined ? { signatureVerified: signer !== undefined } : {}),
        ...(responderAuthorized !== undefined ? { responderAuthorized } : {}),
        ...(signer !== undefined ? { signer } : {}),
        ...(nonce !== undefined ? { nonce } : {}),
        requireNonce: hasFlag(ctx.args.flags, 'require-nonce'),
        ...(stale !== undefined ? { staleTolerance: stale } : {}),
        ...(future !== undefined ? { futureTolerance: future } : {}),
        onDiagnostic: parseOptions(ctx).onDiagnostic,
    });
    const valid = reasons.length === 0;
    const report = {
        valid,
        reasons,
        status: answered?.status.kind ?? null,
        signatureVerified: signer !== undefined,
        responderAuthorized: responderAuthorized ?? false,
    };
    emitReport(ctx, report, () => renderVerdict(ctx.color, valid, `revocation (OCSP, ${report.status ?? 'no answer'})`, reasons));
    if (!valid) throw new CliError(`OCSP check failed: ${reasons.map((r) => r.code).join(', ')}.`, 1, ErrorCode.CHECK_FAILED, { reasons });
}

export async function ocsp(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'ocsp request': return request(ctx);
        case 'ocsp cert-id': return certId(ctx);
        case 'ocsp inspect': return inspect(ctx);
        case 'ocsp verify-signature': return verifySignature(ctx);
        default: return check(ctx);
    }
}
