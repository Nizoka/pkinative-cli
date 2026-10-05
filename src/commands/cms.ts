// `pkinative cms sign|verify|inspect|verify-signer|add-attribute|add-timestamp`
// — CMS SignedData (RFC 5652) with ESS signing-certificate-v2 (RFC 5035),
// CMS algorithm protection (RFC 6211) and RFC 3161 counter time-stamps.

import {
    addTimeStampToken,
    addUnsignedAttribute,
    createSignedData,
    getOidName,
    parseSignedData,
    parseTimeStampResponse,
    verifySignedData,
    verifySignerInfoSignature,
    type Certificate,
    type SignedData,
    type SignerInfo,
    type VerifySignedDataReport,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getIntFlag, getStringFlag, getStringFlagAll, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readContentBytes, readPkiBundle, readPkiBytes, readPkiObject } from '../utils/pki-input.js';
import { dn, reasonLine, renderVerdict } from '../utils/render.js';
import { loadSigner } from '../utils/signer.js';
import { readSpki } from '../utils/spki.js';
import { formatInstant, parseInstant } from '../utils/time.js';
import { fromHex, toHex } from '../utils/wire.js';
import { purposeOid } from '../utils/x509-spec.js';
import { readCertificate, readCertificates } from './cert.js';


function cmsPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0];
}

async function readSignedDataDer(ctx: Ctx): Promise<Uint8Array> {
    return (await readPkiObject(ctx, cmsPath(ctx), 'CMS SignedData', LABELS.cms)).der;
}

function parse(ctx: Ctx, der: Uint8Array): SignedData {
    return guard('Cannot read the SignedData', () => parseSignedData(der, { ...parseOptions(ctx), allowTrailingData: hasFlag(ctx.args.flags, 'allow-trailing') }));
}

function hexFlag(ctx: Ctx, name: string): Uint8Array | undefined {
    const raw = getStringFlag(ctx.args.flags, name);
    if (raw === undefined) return undefined;
    const bytes = fromHex(raw);
    if (bytes === undefined || bytes.length === 0) throw usageError(`--${name} expects hexadecimal, got "${raw}".`);
    return bytes;
}

/** --content <file> or --content-digest <hex>, never both. */
async function contentInputs(ctx: Ctx): Promise<{ content?: Uint8Array; contentDigest?: Uint8Array }> {
    const path = getStringFlag(ctx.args.flags, 'content');
    const digest = hexFlag(ctx, 'content-digest');
    if (path !== undefined && digest !== undefined) throw usageError('Give --content or --content-digest, not both.');
    if (path !== undefined) return { content: await readContentBytes(ctx, path, 'content') };
    return digest !== undefined ? { contentDigest: digest } : {};
}

function signingTime(ctx: Ctx): number | undefined {
    const raw = getStringFlag(ctx.args.flags, 'signing-time') ?? 'now';
    if (raw === 'none') return undefined;
    // CMS signingTime carries whole seconds.
    return Math.floor(parseInstant(raw, 'signing-time') / 1000) * 1000;
}

async function sign(ctx: Ctx): Promise<void> {
    const { content, contentDigest } = await contentInputs(ctx);
    if (content === undefined && contentDigest === undefined) throw usageError('cms sign needs --content <file> (or --content-digest <hex> with --detached).');
    const detached = hasFlag(ctx.args.flags, 'detached');
    if (contentDigest !== undefined && !detached) throw usageError('--content-digest signs a digest only, so it needs --detached.');
    const certPath = getStringFlag(ctx.args.flags, 'cert');
    const fromFlag = certPath === undefined ? undefined : await readCertificate(ctx, certPath, 'signer certificate');
    const loaded = await loadSigner(ctx, { hint: fromFlag === undefined ? undefined : readSpki(ctx, fromFlag.subjectPublicKeyInfo.der).type, stdinTaken: false });
    const certificate = fromFlag ?? loaded.certificate;
    if (certificate === undefined) throw usageError('cms sign needs the signer certificate: --cert <file> (or a PKCS#12 that holds it).');
    const extra = [...await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'chain'), 'chain certificate'), ...loaded.chain];
    const crls = (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'crl'), 'CRL', LABELS.crl)).map((o) => o.der);
    const readAttributes = async (flag: string): Promise<Uint8Array[]> => {
        const out: Uint8Array[] = [];
        for (const p of getStringFlagAll(ctx.args.flags, flag)) out.push(await readPkiBytes(ctx, p, 'attribute'));
        return out;
    };
    const signed = await readAttributes('signed-attribute');
    const unsigned = await readAttributes('unsigned-attribute');
    const time = signingTime(ctx);
    const contentType = getStringFlag(ctx.args.flags, 'content-type');
    const sid = getChoiceFlag(ctx.args.flags, 'sid', ['issuer-serial', 'ski'] as const, 'issuer-serial');
    const der = await guardAsync('Cannot sign', () => createSignedData({
        ...(content !== undefined ? { content } : {}),
        ...(contentDigest !== undefined ? { contentDigest } : {}),
        detached,
        ...(contentType !== undefined ? { contentType } : {}),
        certificate,
        sid: sid === 'ski' ? 'subjectKeyIdentifier' : 'issuerAndSerialNumber',
        certificates: [certificate.der, ...extra.map((c) => c.der)],
        crls,
        ...(time !== undefined ? { signingTime: time } : {}),
        signingCertificateV2: !hasFlag(ctx.args.flags, 'no-signing-certificate'),
        algorithmProtection: !hasFlag(ctx.args.flags, 'no-algorithm-protection'),
        // pkinative reads an empty list as none.
        signedAttributes: signed,
        unsignedAttributes: unsigned,
    }, loaded.signer, { limits: ctx.opts.limits }));
    // A key that does not belong to --cert would yield a signature nobody verifies.
    // createSignedData always writes signed attributes, so the signature covers them, never the content.
    const signerInfo = parse(ctx, der).signerInfos[0] as SignerInfo;
    const ok = await guardAsync('Cannot verify the new signature', () => verifySignerInfoSignature(signerInfo, certificate, { allowSha1: ctx.opts.allowSha1 }));
    if (!ok) throw new CliError('The signing key does not belong to the signer certificate.', 1, ErrorCode.INPUT);
    ctx.status['detached'] = detached;
    await emitArtifact(ctx, der, { label: 'CMS', defaultEncoding: 'der' });
}

export function renderSignedData(sd: SignedData): string {
    return [
        `SignedData v${sd.version}`,
        `  Content type:  ${getOidName(sd.contentType) ?? sd.contentType}`,
        `  Content:       ${sd.content === undefined ? 'detached' : `${sd.content.length} bytes`}`,
        `  Digests:       ${sd.digestAlgorithms.map((a) => getOidName(a.oid) ?? a.oid).join(', ')}`,
        `  Certificates:  ${sd.certificates.length}   CRLs: ${sd.crls.length}   OCSP: ${sd.ocspResponses.length}`,
        ...sd.signerInfos.map((s, i) => [
            `  Signer ${i}: ${s.sid.kind === 'issuerAndSerialNumber' ? `issuer ${dn(s.sid.issuer)}, serial ${s.sid.serialNumber.hex}` : `key id ${toHex(s.sid.keyIdentifier)}`}`,
            `    ${getOidName(s.digestAlgorithm.oid) ?? s.digestAlgorithm.oid} / ${getOidName(s.signatureAlgorithm.oid) ?? s.signatureAlgorithm.oid}`
            + (s.signingTime !== undefined ? `, signed ${formatInstant(s.signingTime.epochMilliseconds)}` : '')
            + (s.timeStampTokens.length > 0 ? `, ${s.timeStampTokens.length} time-stamp(s)` : ''),
        ].join('\n')),
    ].join('\n');
}

async function inspect(ctx: Ctx): Promise<void> {
    const sd = parse(ctx, await readSignedDataDer(ctx));
    emitReport(ctx, sd, () => renderSignedData(sd), () => ({
        contentType: sd.contentType,
        detached: sd.content === undefined,
        certificates: sd.certificates.length,
        signers: sd.signerInfos.length,
    }));
}

export function renderReport(ctx: Ctx, report: VerifySignedDataReport): string {
    return [
        renderVerdict(ctx.color, report.valid, 'signature', report.reasons),
        ...report.signers.map((s) => [
            `  signer ${s.index}: ${s.valid ? 'valid' : 'INVALID'}${s.certificate !== undefined ? ` — ${dn(s.certificate.subject)}` : ''}${s.signingTime !== undefined ? `, signed ${formatInstant(s.signingTime.epochMilliseconds)}` : ''}`,
            ...s.reasons.map((r) => `  ${reasonLine(r)}`),
        ].join('\n')),
    ].join('\n');
}

async function verify(ctx: Ctx): Promise<void> {
    const der = await readSignedDataDer(ctx);
    const { content, contentDigest } = await contentInputs(ctx);
    const trustPaths = getStringFlagAll(ctx.args.flags, 'trust');
    if (trustPaths.length === 0) throw usageError('cms verify needs --trust <file> (repeatable): the trust anchors.');
    const trustAnchors = await readCertificates(ctx, trustPaths, 'trust anchor');
    const certificates = await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'untrusted'), 'untrusted certificate');
    const crls = (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'crl'), 'CRL', LABELS.crl)).map((o) => o.der);
    const ocsp = (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'ocsp'), 'OCSP response', LABELS.any)).map((o) => o.der);
    const purposes = getStringFlagAll(ctx.args.flags, 'purpose').map((p) => guard('--purpose', () => purposeOid(p, '--purpose')));
    const at = getStringFlag(ctx.args.flags, 'at');
    const report = await guardAsync('Cannot verify the SignedData', () => verifySignedData({
        signedData: der,
        ...(content !== undefined ? { content } : {}),
        ...(contentDigest !== undefined ? { contentDigest } : {}),
        certificates,
        trustAnchors,
        // An empty list requires no purpose, as an absent one does.
        purposes,
        crls,
        ocspResponses: ocsp,
        requireRevocation: hasFlag(ctx.args.flags, 'require-revocation'),
        ...(at !== undefined ? { at: parseInstant(at, 'at') } : {}),
        atTimeStamp: hasFlag(ctx.args.flags, 'at-timestamp'),
        allowSha1: ctx.opts.allowSha1,
        requireSigningCertificate: hasFlag(ctx.args.flags, 'require-signing-certificate'),
        requireAlgorithmProtection: hasFlag(ctx.args.flags, 'require-algorithm-protection'),
        allowTrailingData: hasFlag(ctx.args.flags, 'allow-trailing'),
        encodingRules: ctx.opts.ber ? 'ber' : 'der',
        limits: ctx.opts.limits,
    }));
    ctx.status['valid'] = report.valid;
    emitReport(ctx, report, () => renderReport(ctx, report), () => ({
        valid: report.valid,
        reasons: report.reasons.map((r) => r.code),
        signers: report.signers.map((s) => ({ index: s.index, valid: s.valid, reasons: s.reasons.map((r) => r.code) })),
    }));
    if (!report.valid) {
        throw new CliError(`The signature does not verify: ${[...report.reasons, ...report.signers.flatMap((s) => s.reasons)].map((r) => r.code).join(', ')}.`, 1, ErrorCode.VERIFY_FAILED, { reasons: report.reasons });
    }
}

function signerAt(ctx: Ctx, sd: SignedData): { index: number; signerInfo: SignerInfo } {
    const index = getIntFlag(ctx.args.flags, 'signer-index') ?? 0;
    const signerInfo = sd.signerInfos[index];
    if (signerInfo === undefined) throw new CliError(`--signer-index ${index} is out of range: ${sd.signerInfos.length} signer(s).`, 1, ErrorCode.NOT_FOUND);
    return { index, signerInfo };
}

async function verifySigner(ctx: Ctx): Promise<void> {
    const sd = parse(ctx, await readSignedDataDer(ctx));
    const { index, signerInfo } = signerAt(ctx, sd);
    const certPath = getStringFlag(ctx.args.flags, 'cert');
    if (certPath === undefined) throw usageError('cms verify-signer needs --cert <file>: the signer certificate.');
    const certificate: Certificate = await readCertificate(ctx, certPath, 'signer certificate');
    const contentPath = getStringFlag(ctx.args.flags, 'content');
    const content = contentPath === undefined ? undefined : await readContentBytes(ctx, contentPath, 'content');
    const valid = await guardAsync('Cannot verify the signer', () => verifySignerInfoSignature(signerInfo, certificate, {
        ...(content !== undefined ? { content } : {}),
        allowSha1: ctx.opts.allowSha1,
    }));
    emitReport(ctx, { valid, index }, () => renderVerdict(ctx.color, valid, `signer ${index} signature`, []));
    if (!valid) throw new CliError(`Signer ${index}'s signature does not verify under --cert.`, 1, ErrorCode.VERIFY_FAILED);
}

async function addAttribute(ctx: Ctx): Promise<void> {
    const der = await readSignedDataDer(ctx);
    const { index } = signerAt(ctx, parse(ctx, der));
    const attributePath = getStringFlag(ctx.args.flags, 'attribute');
    if (attributePath === undefined) throw usageError('cms add-attribute needs --attribute <file>: the DER of one Attribute.');
    const attribute = await readPkiBytes(ctx, attributePath, 'attribute');
    const out = guard('Cannot add the attribute', () => addUnsignedAttribute(der, index, attribute, { limits: ctx.opts.limits }));
    await emitArtifact(ctx, out, { label: 'CMS', defaultEncoding: 'der' });
}

async function addTimestamp(ctx: Ctx): Promise<void> {
    const der = await readSignedDataDer(ctx);
    const { index } = signerAt(ctx, parse(ctx, der));
    const tokenPath = getStringFlag(ctx.args.flags, 'token');
    if (tokenPath === undefined) throw usageError('cms add-timestamp needs --token <file>: a TimeStampToken or a TimeStampResp.');
    let token = await readPkiBytes(ctx, tokenPath, 'time-stamp token');
    // A TimeStampResp (what a TSA returns) is unwrapped to its token.
    try {
        const response = parseTimeStampResponse(token, parseOptions(ctx));
        if (response.tokenDer === undefined) throw new CliError(`The time-stamp response status is "${response.status}": it carries no token.`, 1, ErrorCode.INPUT);
        token = response.tokenDer;
    } catch (e) {
        if (e instanceof CliError) throw e;
    }
    const out = guard('Cannot add the time-stamp', () => addTimeStampToken(der, index, token, { limits: ctx.opts.limits }));
    await emitArtifact(ctx, out, { label: 'CMS', defaultEncoding: 'der' });
}

export async function cms(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'cms sign': return sign(ctx);
        case 'cms verify': return verify(ctx);
        case 'cms inspect': return inspect(ctx);
        case 'cms verify-signer': return verifySigner(ctx);
        case 'cms add-attribute': return addAttribute(ctx);
        default: return addTimestamp(ctx);
    }
}

