// `pkinative p12 inspect|verify-mac|bags|open` — PKCS#12 (RFC 7292), PBES2
// and PBMAC1 (RFC 9579) only: the legacy RC2/3DES ciphers and the RFC 7292
// Appendix B MAC are refused by pkinative's doctrine (its ADR 0002).
// Reports are curated views: no key or secret byte is ever printed.

import {
    encodePem,
    openPkcs12,
    openSafeContents,
    parsePkcs12,
    verifyPkcs12Mac,
    type OpenPkcs12Report,
    type Pkcs12,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getStringFlag, hasFlag } from '../utils/args.js';
import { CliError, ErrorCode, usageError } from '../utils/error.js';
import { writeOutput } from '../utils/io.js';
import { bagView, encryptionView, macView, signingKeyView, type BagView, type SigningKeyView } from '../utils/key-views.js';
import { emitReport } from '../utils/output.js';
import { UNVERIFIED_INTEGRITY_REMEDY, guard, guardAsync, pkcs12Failure } from '../utils/pkierr.js';
import { readPkiBytes } from '../utils/pki-input.js';
import { dn, renderVerdict } from '../utils/render.js';
import { readPassword } from '../utils/secrets.js';

function p12Path(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0];
}

async function read(ctx: Ctx): Promise<{ der: Uint8Array; pkcs12: Pkcs12 }> {
    const der = await readPkiBytes(ctx, p12Path(ctx), 'PKCS#12 file');
    return { der, pkcs12: guard('Cannot read the PKCS#12 file', () => parsePkcs12(der, parseOptions(ctx))) };
}

async function password(ctx: Ctx): Promise<string> {
    const path = p12Path(ctx);
    const value = await readPassword(ctx.io, ctx.args, path === undefined || path === '-');
    if (value === undefined) throw usageError(`${ctx.command} needs the password.`, '--password-file <file> | --password-stdin | PKINATIVE_PASSWORD');
    return value;
}

async function inspect(ctx: Ctx): Promise<void> {
    const { pkcs12 } = await read(ctx);
    const view = {
        version: pkcs12.version,
        mac: macView(pkcs12.mac),
        contents: pkcs12.contents.map((c) => ({
            path: c.path,
            encrypted: c.encrypted,
            ...(c.encryption !== undefined ? { encryption: encryptionView(c.encryption) } : {}),
            bags: c.bags.map((b) => bagView(b, parseOptions(ctx))),
        })),
    };
    emitReport(ctx, view, () => [
        `PKCS#12 v${view.version}, MAC: ${view.mac === null ? 'none' : `${view.mac.kind}, ${view.mac.iterations} iterations`}`,
        ...view.contents.map((c) => `  ${c.path}: ${c.encrypted ? `encrypted (${String(c.encryption?.scheme)})` : `${c.bags.length} bag(s): ${c.bags.map((b) => b.kind).join(', ')}`}`),
    ].join('\n'));
}

async function verifyMac(ctx: Ctx): Promise<void> {
    const { pkcs12 } = await read(ctx);
    const pw = await password(ctx);
    // A file without a MAC is a property of the input, not a misuse of the
    // command: a verdict (exit 1), never a usage error (audit A-03).
    if (pkcs12.mac === undefined) {
        emitReport(ctx, { valid: false, mac: null }, () => renderVerdict(ctx.color, false, 'MAC (none present)', []));
        throw new CliError('The PKCS#12 file carries no MAC: its integrity cannot be verified.', 1, ErrorCode.VERIFY_FAILED, { remedy: UNVERIFIED_INTEGRITY_REMEDY });
    }
    const valid = await guardAsync('Cannot verify the MAC', () => verifyPkcs12Mac(pkcs12, pw));
    emitReport(ctx, { valid }, () => renderVerdict(ctx.color, valid, 'MAC', []));
    // One class for a wrong password across every p12 subcommand (audit A-05).
    if (!valid) throw new CliError('The PKCS#12 MAC does not match: the password is wrong, or the file was altered.', 1, ErrorCode.PASSWORD);
}

async function bags(ctx: Ctx): Promise<void> {
    const { pkcs12 } = await read(ctx);
    const pw = await password(ctx);
    const opened: { path: string; encrypted: boolean; bags: BagView[] }[] = [];
    for (const contents of pkcs12.contents) {
        const list = contents.encrypted ? await guardAsync(`Cannot open ${contents.path}`, () => openSafeContents(contents, pw, parseOptions(ctx))) : contents.bags;
        opened.push({ path: contents.path, encrypted: contents.encrypted, bags: list.map((b) => bagView(b, parseOptions(ctx))) });
    }
    emitReport(ctx, { contents: opened }, () => opened.flatMap((c) => c.bags.map((b) => {
        const subject = b.certificate !== undefined && 'subject' in b.certificate ? ` ${b.certificate.subject}` : '';
        return `${b.path}: ${b.kind}${subject}${b.friendlyName !== undefined ? ` "${b.friendlyName}"` : ''}`;
    })).join('\n'));
}

/** Certificates then CRLs, as one PEM text. */
export function pemBundle(certificates: readonly Uint8Array[], crls: readonly Uint8Array[]): string {
    return [...certificates.map((c) => encodePem('CERTIFICATE', c)), ...crls.map((c) => encodePem('X509 CRL', c))].join('');
}

export interface OpenView {
    readonly valid: boolean;
    readonly integrity: OpenPkcs12Report['integrity'];
    readonly keys: readonly {
        readonly path: string;
        readonly friendlyName?: string;
        readonly certificate?: string;
        readonly signingKey: SigningKeyView | null;
    }[];
    readonly certificates: readonly { readonly subject: string; readonly serialNumber: string }[];
    readonly crls: number;
    readonly reasons: OpenPkcs12Report['reasons'];
}

function openView(report: OpenPkcs12Report): OpenView {
    return {
        valid: report.valid,
        integrity: report.integrity,
        keys: report.keys.map((k) => ({
            path: k.path,
            ...(k.friendlyName !== undefined ? { friendlyName: k.friendlyName } : {}),
            ...(k.certificate !== undefined ? { certificate: dn(k.certificate.subject) } : {}),
            ...(k.signingKey !== undefined ? { signingKey: signingKeyView(k.signingKey) } : { signingKey: null }),
        })),
        certificates: report.certificates.map((c) => ({ subject: dn(c.subject), serialNumber: c.serialNumber.hex })),
        crls: report.crls.length,
        reasons: report.reasons,
    };
}

async function open(ctx: Ctx): Promise<void> {
    const der = await readPkiBytes(ctx, p12Path(ctx), 'PKCS#12 file');
    const pw = await password(ctx);
    const scheme = getChoiceFlag(ctx.args.flags, 'rsa-scheme', ['pkcs1', 'pss'] as const);
    const hash = getChoiceFlag(ctx.args.flags, 'hash', ['SHA-256', 'SHA-384', 'SHA-512'] as const, 'SHA-256');
    const report = await guardAsync('Cannot open the PKCS#12 file', () => openPkcs12(der, {
        ...parseOptions(ctx),
        password: pw,
        allowUnverifiedIntegrity: hasFlag(ctx.args.flags, 'allow-unverified-integrity'),
        ...(scheme !== undefined ? { rsaAlgorithm: scheme === 'pkcs1' ? { name: 'RSASSA-PKCS1-v1_5', hash } : { name: 'RSA-PSS', hash } } : {}),
    }));
    const view = openView(report);
    emitReport(ctx, view, () => [
        renderVerdict(ctx.color, report.valid, `PKCS#12 (integrity ${report.integrity})`, report.reasons),
        ...report.keys.map((k) => `  key ${k.path}${k.certificate !== undefined ? ` — ${dn(k.certificate.subject)}` : ''}${k.signingKey === undefined ? ' (not imported)' : ''}`),
        ...report.certificates.map((c) => `  certificate ${dn(c.subject)}`),
    ].join('\n'));
    // Nothing is written from a file that did not open: neither an
    // unauthenticated certificate nor an empty bundle that a retry would then
    // refuse to overwrite (audit A-02).
    if (!report.valid) throw pkcs12Failure(report);
    const out = getStringFlag(ctx.args.flags, 'certs-out');
    if (out !== undefined && !ctx.opts.dryRun) {
        const pem = pemBundle(report.certificates.map((c) => c.der), report.crls);
        await writeOutput(ctx.io, out, pem, { overwrite: ctx.opts.overwrite });
        ctx.status['certsOut'] = out;
    }
}

export async function p12(ctx: Ctx): Promise<void> {
    switch (ctx.command) {
        case 'p12 inspect': return inspect(ctx);
        case 'p12 verify-mac': return verifyMac(ctx);
        case 'p12 bags': return bags(ctx);
        default: return open(ctx);
    }
}
