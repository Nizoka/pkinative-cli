// `pkinative crl inspect|find|verify-signature|check` — certificate revocation
// lists (RFC 5280 §5).

import {
    checkRevocation,
    findRevocation,
    parseCertificateList,
    verifyCrlSignature,
    type Certificate,
    type CertificateList,
    type RevokedCertificate,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getIntFlag, getStringFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { dn, extensionLine, renderVerdict } from '../utils/render.js';
import { formatInstant, parseInstant } from '../utils/time.js';
import { fromHex } from '../utils/wire.js';
import { readCertificate } from './cert.js';

export interface LoadedCrl {
    readonly der: Uint8Array;
    readonly crl: CertificateList;
}

export async function readCrl(ctx: Ctx, path: string | undefined, what = 'CRL'): Promise<LoadedCrl> {
    const obj = await readPkiObject(ctx, path, what, LABELS.crl);
    return { der: obj.der, crl: guard(`Cannot read the ${what}`, () => parseCertificateList(obj.der, parseOptions(ctx))) };
}

function crlPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0];
}

function at(ctx: Ctx): number {
    const raw = getStringFlag(ctx.args.flags, 'at');
    return raw === undefined ? Date.now() : parseInstant(raw, 'at');
}

export function renderCrl(list: CertificateList): string {
    return [
        `CRL v${list.version}${list.isDelta ? ' (delta)' : ''}`,
        `  Issuer:       ${dn(list.issuer)}`,
        `  This update:  ${formatInstant(list.thisUpdate.epochMilliseconds)}`,
        `  Next update:  ${list.nextUpdate === undefined ? '(none)' : formatInstant(list.nextUpdate.epochMilliseconds)}`,
        `  CRL number:   ${list.crlNumber?.toString() ?? '(none)'}${list.baseCrlNumber !== undefined ? ` (base ${list.baseCrlNumber.toString()})` : ''}`,
        `  Entries:      ${list.entryCount}`,
        `  Extensions (${list.extensions.length}):`,
        ...list.extensions.map((e) => `    ${extensionLine(e)}`),
    ].join('\n');
}

async function inspect(ctx: Ctx): Promise<void> {
    const { crl: list } = await readCrl(ctx, crlPath(ctx));
    emitReport(ctx, list, () => renderCrl(list), () => ({
        issuer: dn(list.issuer),
        thisUpdate: list.thisUpdate.epochMilliseconds,
        nextUpdate: list.nextUpdate?.epochMilliseconds,
        crlNumber: list.crlNumber,
        entries: list.entryCount,
        delta: list.isDelta,
    }));
}

/** One CRL entry lookup, as text. */
export function renderEntry(entry: RevokedCertificate | undefined): string {
    if (entry === undefined) return 'not listed';
    return `revoked ${formatInstant(entry.revocationDate.epochMilliseconds)}${entry.reason !== undefined ? ` (${entry.reason})` : ''}`;
}

async function find(ctx: Ctx): Promise<void> {
    const { der } = await readCrl(ctx, crlPath(ctx));
    const serialHex = getStringFlag(ctx.args.flags, 'serial');
    const certPath = getStringFlag(ctx.args.flags, 'cert');
    if ((serialHex === undefined) === (certPath === undefined)) throw usageError('crl find takes --serial <hex> or --cert <file>.');
    let serial: Uint8Array;
    let issuerDer: Uint8Array | undefined;
    if (certPath !== undefined) {
        const cert = await readCertificate(ctx, certPath);
        serial = cert.serialNumber.bytes;
        issuerDer = cert.issuer.der;
    } else {
        const bytes = fromHex(serialHex as string);
        if (bytes === undefined || bytes.length === 0) throw usageError(`--serial "${serialHex as string}" is not a hexadecimal serial number.`);
        serial = bytes;
    }
    const entry = guard('Cannot search the CRL', () => findRevocation(der, serial, { ...parseOptions(ctx), ...(issuerDer !== undefined ? { issuerDer } : {}) }));
    const report = { revoked: entry !== undefined, ...(entry !== undefined ? { entry } : {}) };
    ctx.status['revoked'] = report.revoked;
    emitReport(ctx, report, () => renderEntry(entry));
}

async function issuerCertificate(ctx: Ctx): Promise<Certificate | undefined> {
    const path = getStringFlag(ctx.args.flags, 'issuer');
    return path === undefined ? undefined : readCertificate(ctx, path, 'issuer certificate');
}

async function verifySignature(ctx: Ctx): Promise<void> {
    const { crl: list } = await readCrl(ctx, crlPath(ctx));
    const issuer = await issuerCertificate(ctx);
    if (issuer === undefined) throw usageError('crl verify-signature needs --issuer <cert>.');
    const valid = await guardAsync('Cannot verify the CRL', () => verifyCrlSignature(list, issuer, { allowSha1: ctx.opts.allowSha1 }));
    emitReport(ctx, { valid }, () => renderVerdict(ctx.color, valid, 'CRL signature', []));
    if (!valid) throw new CliError('The CRL signature does not verify against --issuer.', 1, ErrorCode.VERIFY_FAILED);
}

async function check(ctx: Ctx): Promise<void> {
    const certPath = getStringFlag(ctx.args.flags, 'cert');
    if (certPath === undefined) throw usageError('crl check needs --cert <file>, the certificate to check.');
    const certificate = await readCertificate(ctx, certPath);
    const base = await readCrl(ctx, crlPath(ctx));
    const deltaPath = getStringFlag(ctx.args.flags, 'delta');
    const delta = deltaPath === undefined ? undefined : await readCrl(ctx, deltaPath, 'delta CRL');
    if (delta !== undefined && !delta.crl.isDelta) {
        throw new CliError(`--delta ${deltaPath as string} is not a delta CRL (it has no deltaCRLIndicator extension).`, 1, ErrorCode.INPUT);
    }
    const issuer = await issuerCertificate(ctx);
    const verify = async (list: CertificateList): Promise<boolean | undefined> => (issuer === undefined
        ? undefined
        : guardAsync('Cannot verify the CRL', () => verifyCrlSignature(list, issuer, { allowSha1: ctx.opts.allowSha1 })));
    const signatureVerified = await verify(base.crl);
    const deltaVerified = delta === undefined ? undefined : await verify(delta.crl);
    const stale = getIntFlag(ctx.args.flags, 'stale-tolerance');
    const reasons = guard('Cannot check revocation', () => checkRevocation({
        certificate,
        crl: base.crl,
        crlDer: base.der,
        at: at(ctx),
        ...(signatureVerified !== undefined ? { signatureVerified } : {}),
        ...(stale !== undefined ? { staleTolerance: stale } : {}),
        ...(delta !== undefined ? { delta: { crl: delta.crl, crlDer: delta.der, ...(deltaVerified !== undefined ? { signatureVerified: deltaVerified } : {}) } } : {}),
        limits: ctx.opts.limits,
        onDiagnostic: parseOptions(ctx).onDiagnostic,
    }));
    const valid = reasons.length === 0;
    emitReport(ctx, { valid, reasons, signatureVerified: signatureVerified ?? null }, () => renderVerdict(ctx.color, valid, 'revocation (CRL)', reasons));
    if (!valid) throw new CliError(`Revocation check failed: ${reasons.map((r) => r.code).join(', ')}.`, 1, ErrorCode.CHECK_FAILED, { reasons });
}

export async function crl(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'crl inspect': return inspect(ctx);
        case 'crl find': return find(ctx);
        case 'crl verify-signature': return verifySignature(ctx);
        default: return check(ctx);
    }
}
