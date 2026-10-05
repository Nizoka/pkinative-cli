// `pkinative chain verify|build|validate` — certification paths (RFC 5280 §6).
//   verify    the one-call verdict: build, signatures, validation, name,
//             purpose and revocation (verifyCertificateChain)
//   build     path discovery from untrusted candidates to a trust anchor
//             (buildCertificatePath); signatures are not checked here
//   validate  §6.1 validation of a path the caller ordered, with every link's
//             signature verified by the CLI first (validateCertificatePath)

import {
    buildCertificatePath,
    validateCertificatePath,
    verifyCertificateChain,
    verifyCertificateSignature,
    type Certificate,
    type PkiReason,
    type ServerIdentity,
    type SignatureResult,
    type ValidateCertificatePathReport,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getStringFlag, getStringFlagAll, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { parseIp } from '../utils/names.js';
import { emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiBundle } from '../utils/pki-input.js';
import { dn, renderVerdict } from '../utils/render.js';
import { parseInstant } from '../utils/time.js';
import { fromHex } from '../utils/wire.js';
import { purposeOid } from '../utils/x509-spec.js';
import { readCertificate, readCertificates } from './cert.js';

export const SIGNATURE_NOT_CHECKED = 'PKI_REASON_SIGNATURE_NOT_CHECKED';

function at(ctx: Ctx): number {
    const raw = getStringFlag(ctx.args.flags, 'at');
    return raw === undefined ? Date.now() : parseInstant(raw, 'at');
}

async function trustAnchors(ctx: Ctx): Promise<Certificate[]> {
    const paths = getStringFlagAll(ctx.args.flags, 'trust');
    if (paths.length === 0) throw usageError(`${ctx.command} needs --trust <file> (repeatable): the trust anchors.`);
    return readCertificates(ctx, paths, 'trust anchor');
}

function purposes(ctx: Ctx): string[] {
    return getStringFlagAll(ctx.args.flags, 'purpose').map((p) => guard('--purpose', () => purposeOid(p, '--purpose')));
}

/** The RFC 5280 §6.1.1 policy inputs shared by the three subcommands. */
function policyInputs(ctx: Ctx): { initialPolicySet?: string[]; requireExplicitPolicy: boolean; inhibitPolicyMapping: boolean; inhibitAnyPolicy: boolean } {
    const set = getStringFlagAll(ctx.args.flags, 'policy');
    return {
        ...(set.length > 0 ? { initialPolicySet: [...set] } : {}),
        requireExplicitPolicy: hasFlag(ctx.args.flags, 'require-explicit-policy'),
        inhibitPolicyMapping: hasFlag(ctx.args.flags, 'inhibit-policy-mapping'),
        inhibitAnyPolicy: hasFlag(ctx.args.flags, 'inhibit-any-policy'),
    };
}

function serverName(ctx: Ctx): ServerIdentity | undefined {
    const host = getStringFlag(ctx.args.flags, 'host');
    const ip = getStringFlag(ctx.args.flags, 'ip');
    if (host !== undefined && ip !== undefined) throw usageError('Give --host or --ip, not both.');
    if (host !== undefined) return { kind: 'dns', value: host };
    return ip === undefined ? undefined : { kind: 'ip', value: parseIp(ip, '--ip') };
}

function renderPath(path: readonly Certificate[]): string[] {
    return path.map((c, i) => `  ${i}: ${dn(c.subject)}  (serial ${c.serialNumber.hex})`);
}

/** Print the report, then fail with `code` when the verdict is negative. */
function finish(ctx: Ctx, report: ValidateCertificatePathReport, what: string, failing: readonly PkiReason[], extra: Record<string, unknown>): void {
    emitReport(ctx, { ...report, ...extra }, () => [
        renderVerdict(ctx.color, failing.length === 0, what, report.reasons),
        // pkinative always returns at least the leaf, with the reason that stopped the walk.
        'Path:',
        ...renderPath(report.path),
    ].join('\n'), () => ({ valid: report.valid, reasons: report.reasons.map((r) => r.code), path: report.path.map((c) => dn(c.subject)), ...extra }));
    ctx.status['valid'] = report.valid;
    ctx.status['pathLength'] = report.path.length;
    // A path that reaches no anchor always carries a reason (pkinative never returns an empty failure).
    if (failing.length > 0) {
        throw new CliError(`The ${what} failed: ${failing.map((r) => r.code).join(', ')}.`, 1, ErrorCode.VERIFY_FAILED, { reasons: report.reasons });
    }
}

async function verify(ctx: Ctx): Promise<void> {
    const leaf = await readCertificate(ctx, getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0], 'leaf certificate');
    const candidates = await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'untrusted'), 'untrusted certificate');
    const anchors = await trustAnchors(ctx);
    const crls = (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'crl'), 'CRL', LABELS.crl)).map((o) => o.der);
    const ocsp = (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'ocsp'), 'OCSP response', LABELS.any)).map((o) => o.der);
    const nonceHex = getStringFlag(ctx.args.flags, 'ocsp-nonce');
    const nonce = nonceHex === undefined ? undefined : fromHex(nonceHex);
    if (nonceHex !== undefined && nonce === undefined) throw usageError(`--ocsp-nonce "${nonceHex}" is not hexadecimal.`);
    const name = serverName(ctx);
    const purposeOids = purposes(ctx);
    const report = await guardAsync('Cannot verify the chain', () => verifyCertificateChain({
        leaf,
        candidates,
        trustAnchors: anchors,
        at: at(ctx),
        ...(name !== undefined ? { serverName: name } : {}),
        ...(purposeOids.length > 0 ? { purposes: purposeOids } : {}),
        crls,
        ocspResponses: ocsp,
        ...(nonce !== undefined ? { ocspNonce: nonce } : {}),
        requireOcspNonce: hasFlag(ctx.args.flags, 'require-ocsp-nonce'),
        requireRevocation: hasFlag(ctx.args.flags, 'require-revocation'),
        allowSha1: ctx.opts.allowSha1,
        ...policyInputs(ctx),
        limits: ctx.opts.limits,
        onDiagnostic: parseOptions(ctx).onDiagnostic,
    }));
    finish(ctx, report, 'chain', report.valid ? [] : report.reasons, { explored: report.explored, signatureVerifications: report.signatureVerifications });
}

async function build(ctx: Ctx): Promise<void> {
    const leaf = await readCertificate(ctx, getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0], 'leaf certificate');
    const candidates = await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'untrusted'), 'untrusted certificate');
    const anchors = await trustAnchors(ctx);
    const purposeOids = purposes(ctx);
    const report = guard('Cannot build the path', () => buildCertificatePath({
        leaf,
        candidates,
        trustAnchors: anchors,
        at: at(ctx),
        ...(purposeOids.length > 0 ? { purposes: purposeOids } : {}),
        ...policyInputs(ctx),
        limits: ctx.opts.limits,
    }));
    // Path discovery does not verify signatures; only the other reasons fail it.
    const structural = report.reasons.filter((r) => r.code !== SIGNATURE_NOT_CHECKED);
    finish(ctx, report, 'path (signatures not checked)', structural, { explored: report.explored, signaturesChecked: false });
}

/** Verify each link: certificate i against i+1, the last against the anchor whose subject is its issuer. */
async function linkSignatures(ctx: Ctx, path: readonly Certificate[], anchors: readonly Certificate[]): Promise<SignatureResult[]> {
    const out: SignatureResult[] = [];
    for (const [i, certificate] of path.entries()) {
        const issuer = path[i + 1] ?? anchors.find((a) => Buffer.compare(a.subject.der, certificate.issuer.der) === 0);
        if (issuer === undefined) continue;
        const ok = await guardAsync('Cannot verify a signature of the path', () => verifyCertificateSignature(certificate, issuer, { allowSha1: ctx.opts.allowSha1 }));
        out.push({ certificate, issuer, verdict: ok ? 'valid' : 'invalid' });
    }
    return out;
}

async function validate(ctx: Ctx): Promise<void> {
    const files = [...getStringFlagAll(ctx.args.flags, 'path'), ...ctx.args.positionals];
    if (files.length === 0) throw usageError('chain validate needs the path, leaf first: --path <file>... or positional files.');
    const path = await readCertificates(ctx, files, 'path certificate');
    const anchors = await trustAnchors(ctx);
    const checkSignatures = !hasFlag(ctx.args.flags, 'no-signatures');
    const signatures = checkSignatures ? await linkSignatures(ctx, path, anchors) : [];
    const report = guard('Cannot validate the path', () => validateCertificatePath({
        path,
        trustAnchors: anchors,
        at: at(ctx),
        signatures,
        ...policyInputs(ctx),
        limits: ctx.opts.limits,
    }));
    const failing = checkSignatures ? report.reasons : report.reasons.filter((r) => r.code !== SIGNATURE_NOT_CHECKED);
    // Without signatures the verdict is structural: the headline says so (audit A-15).
    finish(ctx, report, checkSignatures ? 'path' : 'path structure (signatures NOT checked)', report.valid ? [] : failing, { signaturesChecked: checkSignatures });
}

export async function chain(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'chain verify': return verify(ctx);
        case 'chain build': return build(ctx);
        default: return validate(ctx);
    }
}
