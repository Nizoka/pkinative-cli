// `pkinative tsp request|inspect|verify` — RFC 3161 time-stamping, offline:
// the CLI writes the request and judges the response; posting it to a TSA is
// the caller's (curl --data-binary @req.tsq -H 'Content-Type: application/timestamp-query').

import { webcrypto } from 'node:crypto';
import {
    computeFingerprint,
    createTimeStampRequest,
    getOidName,
    parseTimeStampResponse,
    parseTimeStampToken,
    parseTstInfo,
    verifyTimeStampToken,
    type TimeStampHashAlgorithm,
    type TimeStampToken,
    type TstInfo,
    type VerifyTimeStampTokenReport,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getStringFlag, getStringFlagAll, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { emitArtifact, emitReport } from '../utils/output.js';
import { guard, guardAsync, mapPkiError } from '../utils/pkierr.js';
import { LABELS, readContentBytes, readPkiBundle, readPkiBytes } from '../utils/pki-input.js';
import { dn, generalName, renderVerdict } from '../utils/render.js';
import { formatInstant, parseInstant } from '../utils/time.js';
import { fromHex, toHex } from '../utils/wire.js';
import { readCertificates } from './cert.js';

const HASHES: readonly TimeStampHashAlgorithm[] = ['SHA-256', 'SHA-384', 'SHA-512'];

function nonce(ctx: Ctx): bigint | undefined {
    const raw = getStringFlag(ctx.args.flags, 'nonce');
    if (raw === undefined) return undefined;
    if (raw === 'random') {
        const bytes = webcrypto.getRandomValues(new Uint8Array(8));
        bytes[0] = (bytes[0] as number) & 0x7f;
        return BigInt(`0x${toHex(bytes)}`);
    }
    if (/^(\d+|0x[0-9a-f]+)$/i.test(raw)) return BigInt(raw);
    throw usageError(`--nonce expects "random", a decimal or 0x-hex integer, got "${raw}".`);
}

/** The message imprint: --digest <hex>, or the hash of --data <file>. */
async function imprint(ctx: Ctx, hash: TimeStampHashAlgorithm | undefined): Promise<{ digest?: Uint8Array; data?: Uint8Array }> {
    const dataPath = getStringFlag(ctx.args.flags, 'data');
    const digestHex = getStringFlag(ctx.args.flags, 'digest');
    if (dataPath !== undefined && digestHex !== undefined) throw usageError('Give --data or --digest, not both.');
    if (digestHex !== undefined) {
        const digest = fromHex(digestHex);
        if (digest === undefined || digest.length === 0) throw usageError(`--digest expects hexadecimal, got "${digestHex}".`);
        return { digest };
    }
    if (dataPath !== undefined) {
        const data = await readContentBytes(ctx, dataPath, 'data');
        // verify hands the data to pkinative, which hashes it with the token's own algorithm.
        return hash === undefined ? { data } : { data, digest: guard('Cannot hash the data', () => computeFingerprint(data, hash)) };
    }
    return {};
}

async function request(ctx: Ctx): Promise<void> {
    const hash = getChoiceFlag(ctx.args.flags, 'hash', HASHES, 'SHA-256');
    const { digest } = await imprint(ctx, hash);
    if (digest === undefined) throw usageError('tsp request needs --data <file> or --digest <hex>.');
    const n = nonce(ctx);
    const policy = getStringFlag(ctx.args.flags, 'policy');
    const der = guard('Cannot create the time-stamp request', () => createTimeStampRequest(digest, {
        hashAlgorithm: hash,
        ...(n !== undefined ? { nonce: n } : {}),
        ...(policy !== undefined ? { policy } : {}),
        certReq: !hasFlag(ctx.args.flags, 'no-cert-req'),
    }));
    if (n !== undefined) ctx.status['nonce'] = n.toString();
    await emitArtifact(ctx, der, { label: undefined, defaultEncoding: 'der' });
}

export function renderTstInfo(info: TstInfo): string[] {
    const accuracy = info.accuracy === undefined ? '' : ` ±${info.accuracy.seconds}s${info.accuracy.millis}ms${info.accuracy.micros}µs`;
    return [
        `  Gen time:   ${formatInstant(info.genTime.epochMilliseconds)}${accuracy}`,
        `  Policy:     ${info.policy}`,
        `  Serial:     ${info.serialNumber.hex}`,
        `  Imprint:    ${getOidName(info.messageImprint.hashAlgorithm.oid) ?? info.messageImprint.hashAlgorithm.oid} ${toHex(info.messageImprint.hashedMessage)}`,
        `  Nonce:      ${info.nonce?.toString() ?? '(none)'}`,
        `  TSA:        ${info.tsa === undefined ? '(not named)' : generalName(info.tsa)}`,
    ];
}

type Inspected =
    | { readonly as: 'response'; readonly status: string; readonly failInfo: readonly string[]; readonly token: TimeStampToken | undefined }
    | { readonly as: 'token'; readonly token: TimeStampToken }
    | { readonly as: 'tstinfo'; readonly tstInfo: TstInfo };

function parseAs(ctx: Ctx, der: Uint8Array, as: 'response' | 'token' | 'tstinfo'): Inspected {
    const opts = parseOptions(ctx);
    switch (as) {
        case 'response': {
            const r = parseTimeStampResponse(der, opts);
            return { as, status: r.status, failInfo: r.failInfo, token: r.token };
        }
        case 'token': return { as, token: parseTimeStampToken(der, opts) };
        default: return { as, tstInfo: parseTstInfo(der, opts) };
    }
}

async function inspect(ctx: Ctx): Promise<void> {
    const der = await readPkiBytes(ctx, getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0], 'time-stamp object');
    const forced = getChoiceFlag(ctx.args.flags, 'as', ['response', 'token', 'tstinfo'] as const);
    let result: Inspected | undefined;
    if (forced !== undefined) {
        result = guard(`Cannot read the input as a ${forced}`, () => parseAs(ctx, der, forced));
    } else {
        // A response, a token and a bare TSTInfo are tried in that order.
        let first: unknown;
        for (const as of ['response', 'token', 'tstinfo'] as const) {
            try {
                result = parseAs(ctx, der, as);
                break;
            } catch (e) {
                first ??= e;
            }
        }
        if (result === undefined) throw mapPkiError(first, 'The input is not a TimeStampResp, a TimeStampToken or a TSTInfo');
    }
    const shown = result;
    const info = shown.as === 'tstinfo' ? shown.tstInfo : shown.token?.tstInfo;
    emitReport(ctx, shown, () => [
        shown.as === 'response' ? `TimeStampResp: ${shown.status}${shown.failInfo.length > 0 ? ` (${shown.failInfo.join(', ')})` : ''}` : shown.as === 'token' ? 'TimeStampToken' : 'TSTInfo',
        ...(info === undefined ? [] : renderTstInfo(info)),
    ].join('\n'), () => ({ as: shown.as, ...(info !== undefined ? { genTime: info.genTime.epochMilliseconds, serialNumber: info.serialNumber.hex } : {}) }));
}

export function renderVerify(ctx: Ctx, report: VerifyTimeStampTokenReport): string {
    return [
        renderVerdict(ctx.color, report.valid, 'time-stamp', report.reasons),
        ...(report.genTime !== undefined ? [`  Gen time:   ${formatInstant(report.genTime.epochMilliseconds)}`] : []),
        ...(report.tsaCertificate !== undefined ? [`  TSA:        ${dn(report.tsaCertificate.subject)}`] : []),
    ].join('\n');
}

async function verify(ctx: Ctx): Promise<void> {
    const tokenPath = getStringFlag(ctx.args.flags, 'token');
    const responsePath = getStringFlag(ctx.args.flags, 'response') ?? (tokenPath === undefined ? ctx.args.positionals[0] : undefined);
    if ((tokenPath === undefined) === (responsePath === undefined)) throw usageError('tsp verify takes --token <file> or --response <file> (or a response as positional).');
    const trustPaths = getStringFlagAll(ctx.args.flags, 'trust');
    if (trustPaths.length === 0) throw usageError('tsp verify needs --trust <file> (repeatable): the trust anchors.');
    const bytes = await readPkiBytes(ctx, tokenPath ?? responsePath, 'time-stamp');
    const requestPath = getStringFlag(ctx.args.flags, 'request');
    const requestDer = requestPath === undefined ? undefined : await readPkiBytes(ctx, requestPath, 'time-stamp request');
    const { data, digest } = await imprint(ctx, undefined);
    // A token verified without what it stamps proves only that some hash existed at some time.
    if (requestDer === undefined && data === undefined && digest === undefined) {
        throw usageError('tsp verify needs what was stamped: --request <tsq>, --data <file> or --digest <hex>.');
    }
    const at = getStringFlag(ctx.args.flags, 'at');
    const report = await guardAsync('Cannot verify the time-stamp', async () => verifyTimeStampToken({
        ...(tokenPath !== undefined ? { token: bytes } : { response: bytes }),
        ...(requestDer !== undefined ? { request: requestDer } : {}),
        ...(data !== undefined ? { data } : digest !== undefined ? { imprint: digest } : {}),
        certificates: await readCertificates(ctx, getStringFlagAll(ctx.args.flags, 'untrusted'), 'untrusted certificate'),
        trustAnchors: await readCertificates(ctx, trustPaths, 'trust anchor'),
        crls: (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'crl'), 'CRL', LABELS.crl)).map((o) => o.der),
        ocspResponses: (await readPkiBundle(ctx, getStringFlagAll(ctx.args.flags, 'ocsp'), 'OCSP response', LABELS.any)).map((o) => o.der),
        requireRevocation: hasFlag(ctx.args.flags, 'require-revocation'),
        ...(at !== undefined ? { at: parseInstant(at, 'at') } : {}),
        allowSha1: ctx.opts.allowSha1,
        allowNonCriticalTimeStampingEku: hasFlag(ctx.args.flags, 'allow-noncritical-eku'),
        limits: ctx.opts.limits,
        onDiagnostic: parseOptions(ctx).onDiagnostic,
    }));
    ctx.status['valid'] = report.valid;
    emitReport(ctx, report, () => renderVerify(ctx, report), () => ({
        valid: report.valid,
        genTime: report.genTime?.epochMilliseconds,
        reasons: report.reasons.map((r) => r.code),
    }));
    if (!report.valid) throw new CliError(`The time-stamp does not verify: ${report.reasons.map((r) => r.code).join(', ')}.`, 1, ErrorCode.VERIFY_FAILED, { reasons: report.reasons });
}

export async function tsp(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'tsp request': return request(ctx);
        case 'tsp inspect': return inspect(ctx);
        default: return verify(ctx);
    }
}
