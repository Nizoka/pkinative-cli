// The signer of `cert create`, `csr create` and `cms sign`: a PKCS#8 key
// (plain or PBES2-encrypted, PEM or DER) or a PKCS#12 file, imported through
// pkinative into a non-extractable Web Crypto key.
//
// The signature algorithm is chosen from the key, never guessed:
//   EC       ECDSA on the key's curve; hash SHA-256/384/512 for P-256/384/521
//            unless --hash says otherwise
//   Ed25519 / Ed448   no hash (--hash is refused)
//   RSA      --rsa-scheme pkcs1|pss is REQUIRED: pkinative has no default RSA
//            scheme (its ADR 0015), and neither does the CLI; hash SHA-256
//            unless --hash
// An encrypted key reveals its type only once decrypted, and pkinative
// decrypts into a key for one algorithm, so the type comes from the matching
// certificate or public key the command already has, or from --key-type.
// SHA-1 signatures are produced only under --allow-sha1.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import {
    decryptPrivateKey,
    importPrivateKey,
    openPkcs12,
    parseEncryptedPrivateKeyInfo,
    parsePrivateKeyInfo,
    type Certificate,
    type EcCurve,
    type SignatureAlgorithm,
    type SignatureHash,
    type SigningKey,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getChoiceFlag, getIntFlag, getStringFlag } from './args.js';
import { CliError, ErrorCode, usageError } from './error.js';
import { guard, guardAsync, mapPkiError } from './pkierr.js';
import { LABELS, readPkiBytes, readPkiObject } from './pki-input.js';
import { readPassword } from './secrets.js';
import type { KeyKind, KeyType } from './spki.js';

export const KEY_TYPES = ['ec-p256', 'ec-p384', 'ec-p521', 'ed25519', 'ed448', 'rsa', 'rsa-pss'] as const;
const KEY_TYPE_MAP: Readonly<Record<(typeof KEY_TYPES)[number], KeyType>> = {
    'ec-p256': { kind: 'ec', curve: 'P-256' },
    'ec-p384': { kind: 'ec', curve: 'P-384' },
    'ec-p521': { kind: 'ec', curve: 'P-521' },
    ed25519: { kind: 'ed25519' },
    ed448: { kind: 'ed448' },
    rsa: { kind: 'rsa' },
    'rsa-pss': { kind: 'rsa-pss' },
};

const CURVE_HASH: Readonly<Record<EcCurve, SignatureHash>> = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' };
const HASHES: readonly SignatureHash[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
const PASSWORD_REMEDY = '--password-file <file> | --password-stdin | PKINATIVE_PASSWORD';

function hashFlag(ctx: Ctx): SignatureHash | undefined {
    const hash = getChoiceFlag(ctx.args.flags, 'hash', HASHES);
    if (hash === 'SHA-1' && !ctx.opts.allowSha1) {
        throw usageError('--hash SHA-1 produces a signature every current verifier refuses; pass --allow-sha1 to make one anyway.');
    }
    return hash;
}

/** The signature algorithm for a key of `kind` (and `curve`), under the command's flags. */
export function signatureAlgorithm(ctx: Ctx, kind: KeyKind, curve: EcCurve | undefined): SignatureAlgorithm {
    const hash = hashFlag(ctx);
    const scheme = getChoiceFlag(ctx.args.flags, 'rsa-scheme', ['pkcs1', 'pss'] as const);
    const salt = getIntFlag(ctx.args.flags, 'salt-length', 0, 512);
    if (kind !== 'rsa' && kind !== 'rsa-pss' && (scheme !== undefined || salt !== undefined)) {
        throw usageError('--rsa-scheme and --salt-length apply to RSA keys only.');
    }
    switch (kind) {
        case 'ec':
            if (curve === undefined) throw new CliError('The EC key is on a curve Web Crypto does not sign with (P-256, P-384, P-521 only).', 1, ErrorCode.UNSUPPORTED);
            return { name: 'ECDSA', hash: hash ?? CURVE_HASH[curve], namedCurve: curve };
        case 'ed25519':
        case 'ed448':
            if (hash !== undefined) throw usageError(`--hash does not apply to ${kind === 'ed25519' ? 'Ed25519' : 'Ed448'}, which hashes internally.`);
            return { name: kind === 'ed25519' ? 'Ed25519' : 'Ed448' };
        default: {
            const effective = scheme ?? (kind === 'rsa-pss' ? 'pss' : undefined);
            if (effective === undefined) {
                throw usageError('An RSA key needs --rsa-scheme pkcs1|pss: pkinative has no default RSA signature scheme.', '--rsa-scheme pkcs1|pss');
            }
            if (kind === 'rsa-pss' && effective === 'pkcs1') throw usageError('An id-RSASSA-PSS key signs with RSA-PSS only.');
            if (effective === 'pkcs1' && salt !== undefined) throw usageError('--salt-length applies to --rsa-scheme pss only.');
            return effective === 'pkcs1'
                ? { name: 'RSASSA-PKCS1-v1_5', hash: hash ?? 'SHA-256' }
                : { name: 'RSA-PSS', hash: hash ?? 'SHA-256', ...(salt !== undefined ? { saltLength: salt } : {}) };
        }
    }
}

export interface LoadedSigner {
    readonly signer: SigningKey;
    /** The certificate that came with the key (a PKCS#12 bag). */
    readonly certificate: Certificate | undefined;
    /** Other certificates of a PKCS#12 file. */
    readonly chain: readonly Certificate[];
    /** The SPKI DER of the key, when it can be derived (plain PKCS#8 or a PKCS#12 certificate). */
    readonly publicKey: Uint8Array | undefined;
}

export interface SignerContext {
    /** The public key of the signing key, when the command has it (issuer certificate, --cert, --public-key). */
    readonly hint?: KeyType | undefined;
    /** stdin already carries another input, so --password-stdin is refused. */
    readonly stdinTaken: boolean;
}

/** Load --key or --p12 into a signer. Exactly one of the two is required. */
export async function loadSigner(ctx: Ctx, sc: SignerContext): Promise<LoadedSigner> {
    const keyPath = getStringFlag(ctx.args.flags, 'key');
    const p12Path = getStringFlag(ctx.args.flags, 'p12');
    if ((keyPath === undefined) === (p12Path === undefined)) throw usageError(`${ctx.command} needs a signing key: --key <pkcs8> or --p12 <file>.`);
    const password = await readPassword(ctx.io, ctx.args, sc.stdinTaken);
    if (p12Path !== undefined) return loadPkcs12(ctx, p12Path, password);
    const key = await importKeyFile(ctx, keyPath, password, sc.hint);
    return { signer: key.signer, certificate: undefined, chain: [], publicKey: key.publicKey };
}

export interface ImportedKey {
    readonly signer: SigningKey;
    readonly encrypted: boolean;
    /** The SPKI DER, derived for an unencrypted key. */
    readonly publicKey: Uint8Array | undefined;
}

/** Import a PKCS#8 file (plain, or PBES2-encrypted with `password`) into a signing key. */
export async function importKeyFile(ctx: Ctx, path: string | undefined, password: string | undefined, hint: KeyType | undefined): Promise<ImportedKey> {
    const obj = await readPkiObject(ctx, path, 'private key', [...LABELS.privateKey, ...LABELS.encryptedPrivateKey]);
    const encrypted = obj.label === undefined ? isEncryptedPkcs8(ctx, obj.der) : (LABELS.encryptedPrivateKey as readonly string[]).includes(obj.label);
    if (!encrypted) {
        const info = guard('Cannot read the private key', () => parsePrivateKeyInfo(obj.der, parseOptions(ctx)));
        if (info.kind === 'unknown') throw new CliError(`The private key algorithm ${info.algorithm.oid} cannot sign through Web Crypto.`, 1, ErrorCode.UNSUPPORTED);
        const algorithm = signatureAlgorithm(ctx, info.kind, info.curve);
        const signer = await guardAsync('Cannot import the private key', () => importPrivateKey(obj.der, { ...parseOptions(ctx), algorithm }));
        return { signer, encrypted, publicKey: derivePublicKey(obj.der) };
    }
    if (password === undefined) {
        throw usageError('The key is encrypted: give its password.', PASSWORD_REMEDY);
    }
    const typeFlag = getChoiceFlag(ctx.args.flags, 'key-type', KEY_TYPES);
    const type = typeFlag !== undefined ? KEY_TYPE_MAP[typeFlag] : hint;
    if (type === undefined) {
        throw usageError('An encrypted key needs its type before it can be decrypted: pass --key-type, or the matching certificate or public key.', `--key-type ${KEY_TYPES.join('|')}`);
    }
    const algorithm = signatureAlgorithm(ctx, type.kind, type.curve);
    const signer = await guardAsync('Cannot decrypt the private key', () => decryptPrivateKey(obj.der, { ...parseOptions(ctx), password, algorithm }));
    return { signer, encrypted, publicKey: undefined };
}

/** A DER key is encrypted when parseEncryptedPrivateKeyInfo reads it; one neither reader reads is refused with the PKCS#8 cause. */
export function isEncryptedPkcs8(ctx: Ctx, der: Uint8Array): boolean {
    try {
        parsePrivateKeyInfo(der, parseOptions(ctx));
        return false;
    } catch (plainError) {
        try {
            parseEncryptedPrivateKeyInfo(der, parseOptions(ctx));
            return true;
        } catch {
            throw mapPkiError(plainError, 'Cannot read the private key (PKCS#8 expected; convert a SEC1 or PKCS#1 key with openssl pkcs8 -topk8)');
        }
    }
}

/** The SPKI of a plain PKCS#8 key, derived by Node's own crypto (pkinative never exports a key). */
export function derivePublicKey(pkcs8: Uint8Array): Uint8Array {
    return guard('Cannot derive the public key', () => {
        const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
        return new Uint8Array(createPublicKey(privateKey).export({ type: 'spki', format: 'der' }));
    });
}

async function loadPkcs12(ctx: Ctx, path: string, password: string | undefined): Promise<LoadedSigner> {
    if (password === undefined) {
        throw usageError('A PKCS#12 file needs its password.', PASSWORD_REMEDY);
    }
    const der = await readPkiBytes(ctx, path, 'PKCS#12 file');
    const scheme = getChoiceFlag(ctx.args.flags, 'rsa-scheme', ['pkcs1', 'pss'] as const);
    const hash = hashFlag(ctx);
    const rsaAlgorithm = scheme === undefined ? undefined : scheme === 'pkcs1'
        ? { name: 'RSASSA-PKCS1-v1_5' as const, hash: hash ?? 'SHA-256' }
        : { name: 'RSA-PSS' as const, hash: hash ?? 'SHA-256' };
    const report = await guardAsync('Cannot open the PKCS#12 file', () => openPkcs12(der, {
        ...parseOptions(ctx),
        password,
        ...(rsaAlgorithm !== undefined ? { rsaAlgorithm } : {}),
    }));
    if (!report.valid) {
        const scheme_ = report.reasons.some((r) => r.code === 'PKI_REASON_PKCS12_RSA_SCHEME_UNSPECIFIED');
        throw new CliError(
            scheme_ ? 'The PKCS#12 key is RSA: pass --rsa-scheme pkcs1|pss.' : `The PKCS#12 file did not open: ${report.reasons.map((r) => r.code).join(', ')}.`,
            scheme_ ? 2 : 1,
            scheme_ ? ErrorCode.USAGE : report.integrity === 'mismatch' ? ErrorCode.PASSWORD : ErrorCode.VERIFY_FAILED,
            { reasons: report.reasons },
        );
    }
    const keys = report.keys.filter((k) => k.signingKey !== undefined);
    const [first] = keys;
    if (first === undefined || keys.length > 1) {
        throw new CliError(`The PKCS#12 file holds ${keys.length} usable keys; one is needed.`, 1, ErrorCode.INPUT);
    }
    let signer = first.signingKey as SigningKey;
    // ECDSA keys are not bound to a hash in Web Crypto: --hash re-targets them.
    if (signer.algorithm.name === 'ECDSA' && hash !== undefined) signer = { key: signer.key, algorithm: { ...signer.algorithm, hash } };
    const chain = report.certificates.filter((c) => c !== first.certificate);
    return { signer, certificate: first.certificate, chain, publicKey: first.certificate?.subjectPublicKeyInfo.der };
}
