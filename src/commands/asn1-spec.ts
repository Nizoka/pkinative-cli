// The JSON node spec of `asn1 encode`. Every node is an object with a `type`:
//
//   { "type": "boolean", "value": true }
//   { "type": "integer" | "enumerated", "value": "12345" | 42 | "0x7f" }
//   { "type": "null" }
//   { "type": "bit-string", "hex": "0a0b", "unusedBits": 0 }
//   { "type": "named-bits", "bits": [0, 5] }
//   { "type": "octet-string", "hex": "00ff" }
//   { "type": "oid" | "relative-oid", "value": "1.2.840.113549" }
//   { "type": "string", "stringType": "utf8", "value": "text" }
//   { "type": "time", "value": "2027-01-01T00:00:00Z", "timeType": "rfc5280" }
//   { "type": "sequence" | "set" | "set-of", "children": [ … ] }
//   { "type": "explicit" | "implicit", "tag": 0, "class": "context", "inner": { … } }
//   { "type": "tlv", "class": "universal", "tag": 4, "constructed": false, "hex": "…" }
//   { "type": "der", "hex": "…" }        pre-encoded bytes, checked to be one DER object
//
// Each node runs through the engine's own encoder; a malformed spec is
// E_INPUT naming the JSON path of the faulty node. Nesting is bounded by the
// engine's maxDepth limit.

import {
    DEFAULT_PKI_LIMITS,
    decodeAsn1,
    encodeBitString,
    encodeBoolean,
    encodeEnumerated,
    encodeExplicit,
    encodeImplicit,
    encodeInteger,
    encodeNamedBits,
    encodeNull,
    encodeObjectIdentifier,
    encodeOctetString,
    encodeRelativeOid,
    encodeSequence,
    encodeSet,
    encodeSetOf,
    encodeString,
    encodeTime,
    encodeTlv,
    type Asn1StringType,
    type TagClass,
} from '../core-bridge/index.js';
import { parseOptions, type Ctx } from '../context.js';
import { CliError, ErrorCode } from '../utils/error.js';
import { guard } from '../utils/pkierr.js';
import { readPkiBytes } from '../utils/pki-input.js';
import { parseInstant } from '../utils/time.js';
import { fromHex } from '../utils/wire.js';

type Spec = Readonly<Record<string, unknown>>;

const TAG_CLASSES: readonly TagClass[] = ['universal', 'application', 'context', 'private'];
const STRING_TYPES: readonly Asn1StringType[] = ['utf8', 'numeric', 'printable', 'teletex', 'ia5', 'visible', 'universal', 'bmp'];
const TIME_TYPES = ['UTCTime', 'GeneralizedTime', 'rfc5280'] as const;

function specError(path: string, message: string): CliError {
    return new CliError(`asn1 spec ${path}: ${message}`, 1, ErrorCode.INPUT);
}

function isSpec(value: unknown): value is Spec {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function field<T>(spec: Spec, path: string, key: string, check: (v: unknown) => v is T, what: string): T {
    const value = spec[key];
    if (!check(value)) throw specError(`${path}.${key}`, `expected ${what}`);
    return value;
}

const isString = (v: unknown): v is string => typeof v === 'string';
const isBoolean = (v: unknown): v is boolean => typeof v === 'boolean';
const isTagNumber = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const isArray = (v: unknown): v is readonly unknown[] => Array.isArray(v);

function hexField(spec: Spec, path: string, key = 'hex'): Uint8Array {
    const bytes = fromHex(field(spec, path, key, isString, 'a hexadecimal string'));
    if (bytes === undefined) throw specError(`${path}.${key}`, 'expected a hexadecimal string');
    return bytes;
}

function integerField(spec: Spec, path: string): bigint {
    const value = spec['value'];
    if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value);
    if (typeof value === 'string' && /^-?(\d+|0x[0-9a-f]+)$/i.test(value.trim())) {
        const v = value.trim();
        return v.startsWith('-') ? -BigInt(v.slice(1)) : BigInt(v);
    }
    throw specError(`${path}.value`, 'expected a safe integer, or a decimal or 0x-hex string');
}

function choiceField<T extends string>(spec: Spec, path: string, key: string, choices: readonly T[], fallback?: T): T {
    const value = spec[key];
    if (value === undefined && fallback !== undefined) return fallback;
    if (typeof value === 'string' && (choices as readonly string[]).includes(value)) return value as T;
    throw specError(`${path}.${key}`, `expected one of ${choices.join('|')}`);
}

/** Encode one spec node (recursively) through the engine's encoders. */
export function encodeSpec(ctx: Ctx, root: unknown): Uint8Array {
    const maxDepth = ctx.opts.limits?.maxDepth ?? DEFAULT_PKI_LIMITS.maxDepth;
    const visit = (spec: unknown, path: string, depth: number): Uint8Array => {
        if (depth > maxDepth) {
            throw new CliError(`asn1 spec ${path}: nesting exceeds maxDepth (${maxDepth}).`, 1, ErrorCode.LIMIT, {
                detail: { limit: 'maxDepth', flag: '--max-depth', configured: maxDepth, observed: depth },
                remedy: '--max-depth <n> (trusted input only)',
            });
        }
        if (!isSpec(spec)) throw specError(path, 'expected an object with a "type"');
        const type = field(spec, path, 'type', isString, 'a string');
        const children = (): Uint8Array[] => field(spec, path, 'children', isArray, 'an array').map((c, i) => visit(c, `${path}.children[${i}]`, depth + 1));
        const tagOptions = (): { tagClass: TagClass } => ({ tagClass: choiceField(spec, path, 'class', TAG_CLASSES, 'context') });
        return guard(`asn1 spec ${path}`, () => {
            switch (type) {
                case 'boolean': return encodeBoolean(field(spec, path, 'value', isBoolean, 'a boolean'));
                case 'integer': return encodeInteger(integerField(spec, path));
                case 'enumerated': return encodeEnumerated(integerField(spec, path));
                case 'null': return encodeNull();
                case 'bit-string': {
                    const unused = spec['unusedBits'] ?? 0;
                    if (!isTagNumber(unused)) throw specError(`${path}.unusedBits`, 'expected an integer from 0 to 7');
                    return encodeBitString(hexField(spec, path), unused);
                }
                case 'named-bits': {
                    const bits = field(spec, path, 'bits', isArray, 'an array of bit numbers');
                    if (!bits.every(isTagNumber)) throw specError(`${path}.bits`, 'expected an array of bit numbers');
                    return encodeNamedBits(bits);
                }
                case 'octet-string': return encodeOctetString(hexField(spec, path));
                case 'oid': return encodeObjectIdentifier(field(spec, path, 'value', isString, 'a dotted OID'));
                case 'relative-oid': return encodeRelativeOid(field(spec, path, 'value', isString, 'a dotted relative OID'));
                case 'string': return encodeString(choiceField(spec, path, 'stringType', STRING_TYPES), field(spec, path, 'value', isString, 'a string'));
                case 'time': {
                    const value = spec['value'];
                    const ms = typeof value === 'number' ? value : parseInstant(field(spec, path, 'value', isString, 'an instant'), 'value');
                    return encodeTime(ms, choiceField(spec, path, 'timeType', TIME_TYPES, 'rfc5280'));
                }
                case 'sequence': return encodeSequence(children());
                case 'set': return encodeSet(children());
                case 'set-of': return encodeSetOf(children());
                case 'explicit': return encodeExplicit(field(spec, path, 'tag', isTagNumber, 'a tag number'), visit(spec['inner'], `${path}.inner`, depth + 1), tagOptions());
                case 'implicit': return encodeImplicit(field(spec, path, 'tag', isTagNumber, 'a tag number'), visit(spec['inner'], `${path}.inner`, depth + 1), tagOptions());
                case 'tlv': return encodeTlv(
                    choiceField(spec, path, 'class', TAG_CLASSES),
                    field(spec, path, 'tag', isTagNumber, 'a tag number'),
                    field(spec, path, 'constructed', isBoolean, 'a boolean'),
                    hexField(spec, path),
                );
                case 'der': {
                    const bytes = hexField(spec, path);
                    decodeAsn1(bytes, parseOptions(ctx));
                    return bytes;
                }
                default: throw specError(`${path}.type`, `unknown type "${type}"`);
            }
        });
    };
    return visit(root, '$', 0);
}

/** Read and parse a spec document (file or "-"), bounded by --max-input-bytes. */
export async function readSpec(ctx: Ctx, path: string): Promise<unknown> {
    const bytes = await readPkiBytes(ctx, path, 'asn1 spec');
    try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch {
        throw new CliError(`asn1 spec ${path}: not valid UTF-8 JSON.`, 1, ErrorCode.PARSE);
    }
}
