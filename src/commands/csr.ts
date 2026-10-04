// `pkinative csr inspect|create|verify` — PKCS#10 certification requests (RFC 2986).

import { createCertificationRequest, parseCertificationRequest, verifyCertificationRequest, type CertificationRequest } from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getStringFlag, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { dn, renderRequest, renderVerdict } from '../utils/render.js';
import { loadSigner } from '../utils/signer.js';
import { readPublicKey, readSpki } from '../utils/spki.js';
import { buildExtensions, nameOf, readJsonSpec, specError } from '../utils/x509-spec.js';

function inputPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0];
}

async function readRequestDer(ctx: Ctx): Promise<Uint8Array> {
    return (await readPkiObject(ctx, inputPath(ctx), 'certification request', LABELS.csr)).der;
}

async function inspect(ctx: Ctx): Promise<void> {
    const der = await readRequestDer(ctx);
    const request: CertificationRequest = guard('Cannot read the request', () => parseCertificationRequest(der, {
        ...parseOptions(ctx),
        decodeExtensions: !hasFlag(ctx.args.flags, 'raw-extensions'),
    }));
    emitReport(ctx, request, () => renderRequest(request), () => ({
        subject: dn(request.subject),
        publicKey: request.subjectPublicKeyInfo.kind,
        extensions: (request.extensions ?? []).map((e) => e.kind),
    }));
}

async function verify(ctx: Ctx): Promise<void> {
    const der = await readRequestDer(ctx);
    const report = await guardAsync('Cannot verify the request', () => verifyCertificationRequest(der, { ...parseOptions(ctx), allowSha1: ctx.opts.allowSha1 }));
    emitReport(ctx, report, () => renderVerdict(ctx.color, report.valid, 'request signature', report.reasons), () => ({
        valid: report.valid,
        reasons: report.reasons.map((r) => r.code),
    }));
    if (!report.valid) {
        throw new CliError(`The request does not verify: ${report.reasons.map((r) => r.code).join(', ')}.`, 1, ErrorCode.VERIFY_FAILED, { reasons: report.reasons });
    }
}

async function create(ctx: Ctx): Promise<void> {
    const specPath = getStringFlag(ctx.args.flags, 'spec');
    if (specPath === undefined) throw usageError('csr create needs --spec <file.json>.');
    const spec = await readJsonSpec(ctx, specPath);
    const subject = nameOf(spec, 'subject');
    if (subject === undefined) throw specError('subject', 'is required');
    for (const key of Object.keys(spec)) {
        if (key !== 'subject' && key !== 'extensions') throw specError(key, 'a request carries only "subject" and "extensions"');
    }
    const pubPath = getStringFlag(ctx.args.flags, 'public-key');
    const subjectKey = pubPath === undefined ? undefined : await readPublicKey(ctx, pubPath);
    const loaded = await loadSigner(ctx, { hint: subjectKey?.type, stdinTaken: specPath === '-' });
    const spki = subjectKey?.spki ?? loaded.publicKey;
    if (spki === undefined) {
        throw usageError('The public key is needed: pass --public-key <cert|csr|public key> (it is derived from --key only for an unencrypted key).');
    }
    const bits = subjectKey?.bits ?? readSpki(ctx, spki).bits;
    const extensions = buildExtensions(spec['extensions'], { subjectKeyBits: bits, issuerKeyId: undefined, defaults: { ski: false, aki: false } });
    const der = await guardAsync('Cannot create the request', () => createCertificationRequest({
        subject,
        subjectPublicKey: spki,
        ...(extensions.length > 0 ? { extensions } : {}),
    }, loaded.signer, { limits: ctx.opts.limits }));
    // A request signed by a key that is not the one it names is useless to a CA.
    const check = await guardAsync('Cannot verify the new request', () => verifyCertificationRequest(der, { ...parseOptions(ctx), allowSha1: ctx.opts.allowSha1 }));
    if (!check.valid) throw new CliError('The signing key does not match the request public key.', 1, ErrorCode.INPUT, { reasons: check.reasons });
    await emitArtifact(ctx, der, { label: 'CERTIFICATE REQUEST', defaultEncoding: 'pem' });
}

export async function csr(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'csr inspect': return inspect(ctx);
        case 'csr create': return create(ctx);
        default: return verify(ctx);
    }
}
