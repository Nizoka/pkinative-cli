// The JSON spec of `cert create`, `csr create` and `cert encode`, turned into
// pkinative's descriptions through its structural encoders.
//
//   {
//     "serialNumber": "0x1001" | "4097" | 4097 | "random",     default random (127 bits)
//     "subject": { "C": "FR", "O": "Acme", "CN": "example.test" },   or explicit RDNs
//     "issuer":  { ... },              default: --issuer's subject DER, else the subject
//     "notBefore": "2027-01-01T00:00:00Z",  default now (whole seconds)
//     "notAfter":  "...",  or  "validityDays": 365
//     "extensions": {
//       "basicConstraints": { "ca": true, "pathLen": 0, "critical": true },
//       "keyUsage": ["digitalSignature"]  |  { "usages": [...], "critical": true },
//       "extendedKeyUsage": ["serverAuth", "1.3.6.1.5.5.7.3.2"]  |  { "purposes": [...], "critical": false },
//       "subjectAltName" | "issuerAltName": { "dns": [], "email": [], "uri": [], "ip": [],
//                                             "registeredId": [], "directoryName": [ <name> ], "critical": false },
//       "subjectKeyIdentifier": true | false | "hex",
//       "authorityKeyIdentifier": true | false | "hex",
//       "raw": [ { "oid": "1.2.3", "critical": false, "value": "hex of the extnValue content" } ]
//     }
//   }

import { webcrypto } from 'node:crypto';
import {
    ANY_EXTENDED_KEY_USAGE,
    KEY_PURPOSES,
    KEY_USAGE_BITS,
    computeKeyIdentifier,
    encodeAuthorityKeyIdentifier,
    encodeBasicConstraints,
    encodeDistinguishedName,
    encodeExtendedKeyUsage,
    encodeKeyUsage,
    encodeSubjectAltName,
    encodeSubjectKeyIdentifier,
    type ExtensionDescription,
    type GeneralNameDescription,
    type NameDescription,
} from '../core-bridge/index.js';
import type { Ctx } from '../context.js';
import { CliError, ErrorCode } from './error.js';
import { parseIp, parseNameSpec } from './names.js';
import { guard } from './pkierr.js';
import { readContentBytes } from './pki-input.js';
import { parseInstant } from './time.js';
import { fromHex } from './wire.js';

export type Spec = Readonly<Record<string, unknown>>;

export const EXTENSION_OIDS = {
    basicConstraints: '2.5.29.19',
    keyUsage: '2.5.29.15',
    extendedKeyUsage: '2.5.29.37',
    subjectAltName: '2.5.29.17',
    issuerAltName: '2.5.29.18',
    subjectKeyIdentifier: '2.5.29.14',
    authorityKeyIdentifier: '2.5.29.35',
} as const;

const KNOWN_EXTENSION_KEYS = [...Object.keys(EXTENSION_OIDS), 'raw'];

export function specError(path: string, message: string): CliError {
    return new CliError(`spec ${path}: ${message}`, 1, ErrorCode.INPUT);
}

export function isSpec(value: unknown): value is Spec {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringArray(value: unknown, path: string): string[] {
    if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) throw specError(path, 'expected an array of strings');
    return value;
}

function critical(spec: Spec, path: string, fallback: boolean): boolean {
    const c = spec['critical'];
    if (c === undefined) return fallback;
    if (typeof c !== 'boolean') throw specError(`${path}.critical`, 'expected a boolean');
    return c;
}

/** Array shorthand or `{ <key>: [...], critical }`. */
function listForm(value: unknown, path: string, key: string, criticalDefault: boolean): { items: string[]; critical: boolean } {
    if (Array.isArray(value)) return { items: stringArray(value, path), critical: criticalDefault };
    if (!isSpec(value)) throw specError(path, `expected an array, or { "${key}": [...], "critical": ... }`);
    return { items: stringArray(value[key], `${path}.${key}`), critical: critical(value, path, criticalDefault) };
}

/** `serverAuth`, `any`, or a dotted OID → the purpose OID. */
export function purposeOid(name: string, path: string): string {
    if (name === 'any') return ANY_EXTENDED_KEY_USAGE;
    if (Object.hasOwn(KEY_PURPOSES, name)) return KEY_PURPOSES[name as keyof typeof KEY_PURPOSES];
    if (/^\d+(\.\d+)+$/.test(name)) return name;
    throw specError(path, `unknown purpose "${name}" (${Object.keys(KEY_PURPOSES).join(', ')}, any, or a dotted OID)`);
}

export function keyUsages(names: readonly string[], path: string): string[] {
    for (const n of names) {
        if (!KEY_USAGE_BITS.has(n)) throw specError(path, `unknown key usage "${n}" (${[...KEY_USAGE_BITS.keys()].join(', ')})`);
    }
    return [...names];
}

export function generalNames(spec: unknown, path: string): GeneralNameDescription[] {
    if (!isSpec(spec)) throw specError(path, 'expected { "dns": [...], "ip": [...], ... }');
    const out: GeneralNameDescription[] = [];
    const list = (key: string): string[] => (spec[key] === undefined ? [] : stringArray(spec[key], `${path}.${key}`));
    for (const v of list('dns')) out.push({ kind: 'dNSName', value: v });
    for (const v of list('email')) out.push({ kind: 'rfc822Name', value: v });
    for (const v of list('uri')) out.push({ kind: 'uniformResourceIdentifier', value: v });
    for (const v of list('ip')) out.push({ kind: 'iPAddress', value: parseIp(v, `${path}.ip`) });
    for (const v of list('registeredId')) out.push({ kind: 'registeredID', value: v });
    const dirs = spec['directoryName'];
    if (dirs !== undefined) {
        if (!Array.isArray(dirs)) throw specError(`${path}.directoryName`, 'expected an array of names');
        dirs.forEach((d: unknown, i) => {
            const name = parseNameSpec(d, `spec ${path}.directoryName[${i}]`);
            out.push({ kind: 'directoryNameDer', value: guard(`spec ${path}.directoryName[${i}]`, () => encodeDistinguishedName(name)) });
        });
    }
    return out;
}

export function hexValue(value: unknown, path: string): Uint8Array {
    const bytes = typeof value === 'string' ? fromHex(value) : undefined;
    if (bytes === undefined) throw specError(path, 'expected a hexadecimal string');
    return bytes;
}

export interface KeyIdentifiers {
    /** The subject's public key bits (for an automatic subjectKeyIdentifier). */
    readonly subjectKeyBits: Uint8Array;
    /** The issuer's key identifier (for an automatic authorityKeyIdentifier). */
    readonly issuerKeyId: Uint8Array | undefined;
    /** Whether SKI / AKI are added when the spec does not mention them. */
    readonly defaults: { readonly ski: boolean; readonly aki: boolean };
}

function keyIdentifier(value: unknown, path: string, auto: () => Uint8Array | undefined): Uint8Array | undefined {
    if (value === false) return undefined;
    if (value === true) {
        const id = auto();
        if (id === undefined) throw specError(path, 'cannot be computed here: give it as hex');
        return id;
    }
    return hexValue(value, path);
}

/** Build the extension descriptions of a spec, in a stable order. */
export function buildExtensions(spec: unknown, ids: KeyIdentifiers): ExtensionDescription[] {
    if (spec !== undefined && !isSpec(spec)) throw specError('extensions', 'expected an object');
    const ext: Spec = spec ?? {};
    for (const key of Object.keys(ext)) {
        if (!KNOWN_EXTENSION_KEYS.includes(key)) throw specError(`extensions.${key}`, `unknown extension (${KNOWN_EXTENSION_KEYS.join(', ')})`);
    }
    const out: ExtensionDescription[] = [];
    const push = (oid: string, isCritical: boolean, value: Uint8Array): void => {
        out.push({ oid, critical: isCritical, value });
    };
    const bc = ext['basicConstraints'];
    if (bc !== undefined) {
        if (!isSpec(bc) || typeof bc['ca'] !== 'boolean') throw specError('extensions.basicConstraints', 'expected { "ca": boolean, "pathLen"?: n }');
        const pathLen = bc['pathLen'];
        if (pathLen !== undefined && typeof pathLen !== 'number') throw specError('extensions.basicConstraints.pathLen', 'expected a number');
        push(EXTENSION_OIDS.basicConstraints, critical(bc, 'extensions.basicConstraints', true),
            guard('spec extensions.basicConstraints', () => encodeBasicConstraints({ cA: bc['ca'] as boolean, ...(pathLen !== undefined ? { pathLenConstraint: pathLen } : {}) })));
    }
    if (ext['keyUsage'] !== undefined) {
        const ku = listForm(ext['keyUsage'], 'extensions.keyUsage', 'usages', true);
        push(EXTENSION_OIDS.keyUsage, ku.critical, guard('spec extensions.keyUsage', () => encodeKeyUsage(keyUsages(ku.items, 'extensions.keyUsage'))));
    }
    if (ext['extendedKeyUsage'] !== undefined) {
        const eku = listForm(ext['extendedKeyUsage'], 'extensions.extendedKeyUsage', 'purposes', false);
        const oids = eku.items.map((p) => purposeOid(p, 'extensions.extendedKeyUsage'));
        push(EXTENSION_OIDS.extendedKeyUsage, eku.critical, guard('spec extensions.extendedKeyUsage', () => encodeExtendedKeyUsage(oids)));
    }
    for (const key of ['subjectAltName', 'issuerAltName'] as const) {
        const san = ext[key];
        if (san === undefined) continue;
        const names = generalNames(san, `extensions.${key}`);
        push(EXTENSION_OIDS[key], critical(san as Spec, `extensions.${key}`, false), guard(`spec extensions.${key}`, () => encodeSubjectAltName(names)));
    }
    const ski = keyIdentifier(ext['subjectKeyIdentifier'] ?? ids.defaults.ski, 'extensions.subjectKeyIdentifier', () => computeKeyIdentifier(ids.subjectKeyBits));
    if (ski !== undefined) push(EXTENSION_OIDS.subjectKeyIdentifier, false, encodeSubjectKeyIdentifier(ski));
    const aki = keyIdentifier(ext['authorityKeyIdentifier'] ?? ids.defaults.aki, 'extensions.authorityKeyIdentifier', () => ids.issuerKeyId);
    if (aki !== undefined) push(EXTENSION_OIDS.authorityKeyIdentifier, false, encodeAuthorityKeyIdentifier(aki));
    const raw = ext['raw'];
    if (raw !== undefined) {
        if (!Array.isArray(raw)) throw specError('extensions.raw', 'expected an array');
        raw.forEach((r: unknown, i) => {
            const path = `extensions.raw[${i}]`;
            if (!isSpec(r) || typeof r['oid'] !== 'string') throw specError(path, 'expected { "oid", "critical"?, "value": hex }');
            push(r['oid'], critical(r, path, false), hexValue(r['value'], `${path}.value`));
        });
    }
    return out;
}

/** A serial number: "random" (default), a decimal or 0x-hex string, or a safe integer. */
export function serialNumber(value: unknown): bigint {
    if (value === undefined || value === 'random') {
        const bytes = webcrypto.getRandomValues(new Uint8Array(16));
        bytes[0] = ((bytes[0] as number) & 0x7f) | 0x01;
        return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
    }
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === 'string' && /^(\d+|0x[0-9a-f]+)$/i.test(value)) return BigInt(value);
    throw specError('serialNumber', 'expected "random", a decimal or 0x-hex string, or an integer');
}

/** notBefore / notAfter from the spec, in whole seconds. */
export function validity(spec: Spec, now: () => number = Date.now): { notBefore: number; notAfter: number } {
    const instant = (key: string, fallback: number): number => {
        const v = spec[key];
        if (v === undefined) return fallback;
        if (typeof v === 'number' && Number.isSafeInteger(v)) return v;
        if (typeof v === 'string') return parseInstant(v, key);
        throw specError(key, 'expected an instant (ISO 8601 or epoch milliseconds)');
    };
    const notBefore = instant('notBefore', Math.floor(now() / 1000) * 1000);
    const days = spec['validityDays'] ?? 365;
    if (typeof days !== 'number' || !Number.isSafeInteger(days) || days < 1) throw specError('validityDays', 'expected a positive integer');
    if (spec['notAfter'] !== undefined && spec['validityDays'] !== undefined) throw specError('notAfter', 'give notAfter or validityDays, not both');
    const notAfter = instant('notAfter', notBefore + days * 86_400_000);
    return { notBefore, notAfter };
}

/** Read and parse any JSON document (or "-"), bounded by --max-content-size. */
export async function readJsonValue(ctx: Ctx, path: string): Promise<unknown> {
    const bytes = await readContentBytes(ctx, path, 'spec');
    try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch {
        throw new CliError(`spec ${path}: not valid UTF-8 JSON.`, 1, ErrorCode.PARSE);
    }
}

/** Read a JSON object spec. */
export async function readJsonSpec(ctx: Ctx, path: string): Promise<Spec> {
    const parsed = await readJsonValue(ctx, path);
    if (!isSpec(parsed)) throw specError('$', 'expected a JSON object');
    return parsed;
}

/** A name from a spec member, required or optional. */
export function nameOf(spec: Spec, key: string): NameDescription | undefined {
    return spec[key] === undefined ? undefined : parseNameSpec(spec[key], `spec ${key}`);
}
