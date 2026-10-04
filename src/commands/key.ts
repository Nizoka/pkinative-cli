// `pkinative key inspect|check` — PKCS#8 private keys (RFC 5958), plain or
// PBES2-encrypted (RFC 8018). Reports never carry a key byte (utils/key-views.ts).

import { parseEncryptedPrivateKeyInfo, parsePrivateKeyInfo } from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { getStringFlag } from '../utils/args.js';
import { encryptedKeyView, privateKeyView, signingKeyView } from '../utils/key-views.js';
import { emitReport } from '../utils/output.js';
import { guard } from '../utils/pkierr.js';
import { LABELS, readPkiObject } from '../utils/pki-input.js';
import { readPassword } from '../utils/secrets.js';
import { importKeyFile, isEncryptedPkcs8 } from '../utils/signer.js';

function keyPath(ctx: Ctx): string | undefined {
    return getStringFlag(ctx.args.flags, 'input', 'i') ?? ctx.args.positionals[0];
}

async function inspect(ctx: Ctx): Promise<void> {
    const obj = await readPkiObject(ctx, keyPath(ctx), 'private key', [...LABELS.privateKey, ...LABELS.encryptedPrivateKey]);
    const encrypted = obj.label === undefined ? isEncryptedPkcs8(ctx, obj.der) : (LABELS.encryptedPrivateKey as readonly string[]).includes(obj.label);
    const view = encrypted
        ? encryptedKeyView(guard('Cannot read the encrypted key', () => parseEncryptedPrivateKeyInfo(obj.der, parseOptions(ctx))))
        : privateKeyView(guard('Cannot read the private key', () => parsePrivateKeyInfo(obj.der, parseOptions(ctx))));
    emitReport(ctx, view, () => Object.entries(view).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join('\n'));
}

async function check(ctx: Ctx): Promise<void> {
    const path = keyPath(ctx);
    const password = await readPassword(ctx.io, ctx.args, path === undefined || path === '-');
    const imported = await importKeyFile(ctx, path, password, undefined);
    const report = { imported: true, encrypted: imported.encrypted, ...signingKeyView(imported.signer) };
    emitReport(ctx, report, () => `key imported${imported.encrypted ? ' (decrypted)' : ''}: ${JSON.stringify(imported.signer.algorithm)} (${imported.signer.key.type}, non-extractable)`);
}

export async function key(ctx: Ctx): Promise<void> {
    if (ctx.command === 'key inspect') return inspect(ctx);
    return check(ctx);
}
