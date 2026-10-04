// Reading PKI objects from files or stdin. pkinative does no I/O and has no
// PEM-to-object shortcut by design, so the CLI owns the sniffing: an input
// whose first non-blank bytes are `-----BEGIN ` is PEM text (decoded with
// decodePem in the --pem-mode), anything else is DER. The read itself is
// capped by maxInputBytes before a byte is buffered.

import { decodePem, DEFAULT_PKI_LIMITS, type PemBlock } from '../core-bridge/index.js';
import { maxInputBytes, parseOptions, type Ctx } from '../context.js';
import { CliError, ErrorCode } from './error.js';
import { readInput } from './io.js';
import { guard } from './pkierr.js';

const BEGIN = new TextEncoder().encode('-----BEGIN ');

/** True when the bytes are PEM text: optional UTF-8 BOM and whitespace, then `-----BEGIN `. */
export function looksLikePem(bytes: Uint8Array): boolean {
    let i = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
    while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
    if (bytes.length - i < BEGIN.length) return false;
    return BEGIN.every((b, k) => bytes[i + k] === b);
}

/** Read raw bytes of a PKI input, capped by --max-input-bytes. */
export function readPkiBytes(ctx: Ctx, path: string | undefined, what: string): Promise<Uint8Array> {
    return readInput(ctx.io, path, { what, maxBytes: maxInputBytes(ctx, DEFAULT_PKI_LIMITS.maxInputBytes), limitFlag: 'max-input-bytes' });
}

/** Read a non-PKI payload (content to sign, data to time-stamp), capped by --max-content-size. */
export function readContentBytes(ctx: Ctx, path: string | undefined, what: string): Promise<Uint8Array> {
    return readInput(ctx.io, path, { what, maxBytes: ctx.opts.maxContentSize, limitFlag: 'max-content-size' });
}

/** Decode every PEM block of a text, under the global PEM mode and limits. */
export function decodePemBlocks(ctx: Ctx, bytes: Uint8Array, what: string): readonly PemBlock[] {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    return guard(`Cannot decode ${what} as PEM`, () => decodePem(text, { ...parseOptions(ctx), mode: ctx.opts.pemMode }));
}

export interface PkiObject {
    readonly der: Uint8Array;
    /** The PEM label, or undefined for a DER input. */
    readonly label: string | undefined;
    /** The source, for messages. */
    readonly source: string;
}

/**
 * The DER objects of an input: the matching PEM blocks, or the DER bytes as
 * one object. `labels` lists the acceptable PEM labels; an empty list accepts
 * every block.
 */
export async function readPkiObjects(ctx: Ctx, path: string | undefined, what: string, labels: readonly string[]): Promise<readonly PkiObject[]> {
    const source = path === undefined || path === '-' ? 'stdin' : path;
    const bytes = await readPkiBytes(ctx, path, what);
    if (!looksLikePem(bytes)) return [{ der: bytes, label: undefined, source }];
    const blocks = decodePemBlocks(ctx, bytes, what);
    const matching = labels.length === 0 ? blocks : blocks.filter((b) => labels.includes(b.label));
    if (matching.length === 0) {
        const present = [...new Set(blocks.map((b) => b.label))].join(', ');
        throw new CliError(
            `${source} holds no ${labels.join(' or ')} PEM block (labels present: ${present}).`,
            1,
            ErrorCode.INPUT,
            { pkiCode: 'PKI_PEM_UNEXPECTED_LABEL', remedy: 'pkinative pem decode <file> (lists the labels present)' },
        );
    }
    return matching.map((b) => ({ der: b.bytes, label: b.label, source }));
}

/**
 * Exactly one DER object. A PEM file holding several matching blocks is
 * refused rather than silently reduced to its first block.
 */
export async function readPkiObject(ctx: Ctx, path: string | undefined, what: string, labels: readonly string[]): Promise<PkiObject> {
    const objects = await readPkiObjects(ctx, path, what, labels);
    // readPkiObjects returns at least one object or throws.
    const first = objects[0] as PkiObject;
    if (objects.length > 1) {
        throw new CliError(
            `${first.source} holds ${objects.length} ${labels.join('/')} blocks where one ${what} is expected.`,
            1,
            ErrorCode.INPUT,
            { remedy: 'pkinative pem decode <file> --index <n> --encoding der -o <one.der>' },
        );
    }
    return first;
}

/** Every object of every file in a repeatable flag (trust anchors, candidates, CRLs). */
export async function readPkiBundle(ctx: Ctx, paths: readonly string[], what: string, labels: readonly string[]): Promise<readonly PkiObject[]> {
    const out: PkiObject[] = [];
    for (const p of paths) out.push(...await readPkiObjects(ctx, p, what, labels));
    return out;
}

/** PEM labels by object kind (RFC 7468 §5–§13, plus the common legacy forms). */
export const LABELS = {
    certificate: ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'],
    csr: ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'],
    crl: ['X509 CRL'],
    cms: ['CMS', 'PKCS7'],
    privateKey: ['PRIVATE KEY'],
    encryptedPrivateKey: ['ENCRYPTED PRIVATE KEY'],
    publicKey: ['PUBLIC KEY'],
    any: [] as readonly string[],
} as const;
