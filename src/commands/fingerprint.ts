// `pkinative fingerprint` — the digest of an object's DER, the key identifier
// of its public key (RFC 5280 §4.2.1.2), or SHAKE256 output of any length.

import { computeFingerprint, computeFingerprintAsync, computeKeyIdentifier, formatFingerprint, shake256, type FingerprintAlgorithm } from '../core-bridge/index.js';
import type { Ctx } from '../context.js';
import { getChoiceFlag, getIntFlag, getStringFlag, hasFlag } from '../utils/args.js';
import { usageError } from '../utils/error.js';
import { emitReport } from '../utils/output.js';
import { guard, guardAsync } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { publicKeyOf } from '../utils/spki.js';
import { toHex } from '../utils/wire.js';

const ALGORITHMS: readonly FingerprintAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
const MAX_SHAKE_OUTPUT = 1024 * 1024;

export async function fingerprint(ctx: Ctx): Promise<void> {
    const path = getStringFlag(ctx.args.flags, 'input') ?? ctx.args.positionals[0];
    const separator = getStringFlag(ctx.args.flags, 'separator') ?? ':';
    const letterCase = getChoiceFlag(ctx.args.flags, 'case', ['upper', 'lower'] as const, 'upper');
    const keyId = hasFlag(ctx.args.flags, 'key-id');
    const shake = getIntFlag(ctx.args.flags, 'shake256', 1, MAX_SHAKE_OUTPUT);
    const webcrypto = hasFlag(ctx.args.flags, 'webcrypto');
    if (keyId && shake !== undefined) throw usageError('--key-id and --shake256 are separate modes; pass one.');
    if (webcrypto && (keyId || shake !== undefined)) throw usageError('--webcrypto applies to the fingerprint mode only.');
    const obj = await readPkiObject(ctx, path, 'object', LABELS.any);

    if (shake !== undefined) {
        const out = guard('Cannot compute SHAKE256', () => shake256(obj.der, shake));
        const report = { algorithm: 'SHAKE256', outputLength: shake, hex: toHex(out) };
        emitReport(ctx, report, () => report.hex);
        return;
    }

    if (keyId) {
        const alg = getChoiceFlag(ctx.args.flags, 'alg', ['SHA-1', 'SHA-256'] as const, 'SHA-1');
        const key = publicKeyOf(ctx, obj);
        const id = guard('Cannot compute the key identifier', () => computeKeyIdentifier(key.bits, alg));
        const formatted = guard('Cannot format the key identifier', () => formatFingerprint(id, { separator, letterCase }));
        const report = { algorithm: alg, from: key.from, keyIdentifier: formatted, hex: toHex(id) };
        emitReport(ctx, report, () => `${alg} key identifier (${key.from}): ${formatted}`);
        return;
    }

    const alg = getChoiceFlag(ctx.args.flags, 'alg', ALGORITHMS, 'SHA-256');
    const digest = webcrypto
        ? await guardAsync('Cannot compute the fingerprint', () => computeFingerprintAsync(obj.der, alg))
        : guard('Cannot compute the fingerprint', () => computeFingerprint(obj.der, alg));
    const formatted = guard('Cannot format the fingerprint', () => formatFingerprint(digest, { separator, letterCase }));
    const report = { algorithm: alg, fingerprint: formatted, hex: toHex(digest), ...(obj.label !== undefined ? { label: obj.label } : {}) };
    emitReport(ctx, report, () => `${alg} Fingerprint=${formatted}`);
}
