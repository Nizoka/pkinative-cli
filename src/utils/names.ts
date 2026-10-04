// Names and addresses as a user writes them, turned into what pkinative
// takes: a NameDescription (RDNs of attribute OIDs), and an IP address as
// the 4 or 16 octets a GeneralName iPAddress carries.

import { isIPv4, isIPv6 } from 'node:net';
import { OID_REGISTRY, type NameAttribute, type NameDescription } from '../core-bridge/index.js';
import { CliError, ErrorCode } from './error.js';

/** RFC 4514 §3 short names and the usual extras, to attribute type OIDs. */
export const NAME_ALIASES: Readonly<Record<string, string>> = {
    CN: '2.5.4.3', SN: '2.5.4.4', SERIALNUMBER: '2.5.4.5', C: '2.5.4.6', L: '2.5.4.7', ST: '2.5.4.8',
    STREET: '2.5.4.9', O: '2.5.4.10', OU: '2.5.4.11', T: '2.5.4.12', TITLE: '2.5.4.12', GN: '2.5.4.42',
    DC: '0.9.2342.19200300.100.1.25', UID: '0.9.2342.19200300.100.1.1', E: '1.2.840.113549.1.9.1',
    EMAILADDRESS: '1.2.840.113549.1.9.1', ORGANIZATIONIDENTIFIER: '2.5.4.97',
};

const DOTTED = /^\d+(\.\d+)+$/;

/** The attribute type OID for a short name, a registry name or a dotted OID. */
export function attributeType(name: string, path: string): string {
    if (DOTTED.test(name)) return name;
    const alias = NAME_ALIASES[name.toUpperCase()];
    if (alias !== undefined) return alias;
    const entry = OID_REGISTRY.find((e) => e.name.toLowerCase() === name.toLowerCase());
    if (entry !== undefined) return entry.oid;
    throw new CliError(`${path}: unknown attribute type "${name}" (use CN, O, OU, C, ..., a registered name, or a dotted OID).`, 1, ErrorCode.INPUT);
}

const STRING_TYPES = ['utf8', 'printable', 'ia5', 'numeric'] as const;

/** One { type, value, stringType? } attribute of a name spec. */
export function parseNameAttribute(raw: unknown, path: string): NameAttribute {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new CliError(`${path}: expected { "type", "value", "stringType"? }.`, 1, ErrorCode.INPUT);
    }
    const { type, value, stringType } = raw as Record<string, unknown>;
    if (typeof type !== 'string' || typeof value !== 'string') {
        throw new CliError(`${path}: "type" and "value" must be strings.`, 1, ErrorCode.INPUT);
    }
    if (stringType !== undefined && !(STRING_TYPES as readonly unknown[]).includes(stringType)) {
        throw new CliError(`${path}.stringType: expected one of ${STRING_TYPES.join('|')}.`, 1, ErrorCode.INPUT);
    }
    return { type: attributeType(type, `${path}.type`), value, ...(stringType !== undefined ? { stringType: stringType as NameAttribute['stringType'] } : {}) };
}

/**
 * A name spec, most significant RDN first, in either form:
 *   { "C": "FR", "O": "Acme", "CN": "example.test" }       one attribute per RDN
 *   [ [ { "type": "C", "value": "FR" } ], [ ... ], ... ]    explicit RDNs
 */
export function parseNameSpec(spec: unknown, path: string): NameDescription {
    if (Array.isArray(spec)) {
        if (spec.length === 0) throw new CliError(`${path}: a name needs at least one RDN.`, 1, ErrorCode.INPUT);
        return spec.map((rdn: unknown, i) => {
            if (!Array.isArray(rdn) || rdn.length === 0) throw new CliError(`${path}[${i}]: an RDN is a non-empty array of attributes.`, 1, ErrorCode.INPUT);
            return rdn.map((a: unknown, j) => parseNameAttribute(a, `${path}[${i}][${j}]`));
        });
    }
    if (spec !== null && typeof spec === 'object') {
        const entries = Object.entries(spec as Record<string, unknown>);
        if (entries.length === 0) throw new CliError(`${path}: a name needs at least one RDN.`, 1, ErrorCode.INPUT);
        return entries.map(([type, value]) => {
            if (typeof value !== 'string') throw new CliError(`${path}.${type}: expected a string.`, 1, ErrorCode.INPUT);
            return [{ type: attributeType(type, `${path}.${type}`), value }];
        });
    }
    throw new CliError(`${path}: expected an object such as { "CN": "example.test" } or an array of RDNs.`, 1, ErrorCode.INPUT);
}

/** The octets of an IPv4 or IPv6 address (RFC 5280 §4.2.1.6 iPAddress). */
export function parseIp(text: string, what: string): Uint8Array {
    if (isIPv4(text)) return Uint8Array.from(text.split('.').map(Number));
    if (isIPv6(text)) {
        // An embedded IPv4 suffix (::ffff:192.0.2.1) is rewritten as its two groups.
        const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
        const s = v4 === null ? text : `${text.slice(0, v4.index)}${((Number(v4[1]) << 8) | Number(v4[2])).toString(16)}:${((Number(v4[3]) << 8) | Number(v4[4])).toString(16)}`;
        const [left = '', right] = s.split('::');
        const groups = (g: string): number[] => (g === '' ? [] : g.split(':').map((w) => parseInt(w, 16)));
        const l = groups(left);
        const r = right === undefined ? [] : groups(right);
        const words = [...l, ...Array<number>(8 - l.length - r.length).fill(0), ...r];
        const out = new Uint8Array(16);
        words.forEach((w, i) => {
            out[i * 2] = w >> 8;
            out[i * 2 + 1] = w & 0xff;
        });
        return out;
    }
    throw new CliError(`${what}: "${text}" is not an IPv4 or IPv6 address.`, 1, ErrorCode.INPUT);
}

