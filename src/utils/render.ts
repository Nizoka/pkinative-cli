// Human renderings of engine results. JSON output never goes through here:
// it is the ADR 0018 wire form of the result itself.

import {
    computeFingerprint,
    formatDistinguishedName,
    formatFingerprint,
    getOidName,
    type Certificate,
    type CertificationRequest,
    type DistinguishedName,
    type Extension,
    type GeneralName,
    type PkiReason,
    type SubjectPublicKeyInfo,
} from '../core-bridge/index.js';
import type { Palette } from './colors.js';
import { formatInstant } from './time.js';

export function oidLabel(oid: string): string {
    const name = getOidName(oid);
    return name === undefined ? oid : `${name} (${oid})`;
}

/** RFC 4514 text, or `(empty)` for an empty name. */
export function dn(name: DistinguishedName): string {
    const text = formatDistinguishedName(name);
    return text === '' ? '(empty)' : text;
}

export function colonHex(bytes: Uint8Array): string {
    return formatFingerprint(bytes, { separator: ':', letterCase: 'upper' });
}

export function generalName(n: GeneralName): string {
    switch (n.kind) {
        case 'dNSName': return `DNS:${n.value}`;
        case 'rfc822Name': return `email:${n.value}`;
        case 'uniformResourceIdentifier': return `URI:${n.value}`;
        case 'iPAddress': return `IP:${n.address}${n.mask !== undefined ? `/${n.mask}` : ''}`;
        case 'directoryName': return `DirName:${dn(n.name)}`;
        case 'registeredID': return `RID:${n.oid}`;
        case 'otherName': return `othername:${n.typeId}`;
        default: return n.kind;
    }
}

function names(list: readonly GeneralName[]): string {
    return list.map(generalName).join(', ');
}

/** One line for an extension: its name, criticality and decoded essentials. */
export function extensionLine(e: Extension): string {
    const head = `${getOidName(e.oid) ?? e.oid}${e.critical ? ' (critical)' : ''}`;
    let body: string;
    switch (e.kind) {
        case 'basicConstraints':
            body = `CA=${e.cA}${e.pathLenConstraint !== undefined ? `, pathLen=${e.pathLenConstraint}` : ''}`;
            break;
        case 'keyUsage': body = e.usages.join(', '); break;
        case 'extendedKeyUsage': body = e.purposes.map((p) => getOidName(p) ?? p).join(', '); break;
        case 'subjectAltName':
        case 'issuerAltName': body = names(e.names); break;
        case 'subjectKeyIdentifier': body = colonHex(e.keyIdentifier); break;
        case 'authorityKeyIdentifier':
            body = e.keyIdentifier !== undefined ? `keyid:${colonHex(e.keyIdentifier)}` : 'issuer and serial';
            break;
        case 'crlDistributionPoints':
        case 'freshestCRL': body = e.points.map((p) => names(p.fullName ?? [])).join('; '); break;
        case 'authorityInfoAccess':
        case 'subjectInfoAccess':
            body = e.descriptions.map((d) => `${getOidName(d.accessMethod) ?? d.accessMethod} ${generalName(d.accessLocation)}`).join(', ');
            break;
        case 'certificatePolicies': body = e.policies.map((p) => getOidName(p.policyIdentifier) ?? p.policyIdentifier).join(', '); break;
        default: body = `${e.valueDer.length} bytes`;
    }
    return `${head}: ${body}`;
}

export function publicKeyLine(spki: SubjectPublicKeyInfo): string {
    switch (spki.kind) {
        case 'rsa':
        case 'rsa-pss': return `${spki.kind} ${spki.modulus.length * 8 - Math.clz32(spki.modulus[0] ?? 0) + 24} bits`;
        case 'ec': return `ec ${spki.curve ?? spki.namedCurve ?? 'explicit curve'} (${spki.pointFormat})`;
        case 'unknown': return `unknown ${oidLabel(spki.algorithm.oid)}`;
        default: return spki.kind;
    }
}

function rows(entries: readonly (readonly [string, string])[]): string[] {
    const width = Math.max(...entries.map(([k]) => k.length)) + 2;
    return entries.map(([k, v]) => `  ${`${k}:`.padEnd(width)}${v}`);
}

export function renderCertificate(cert: Certificate): string {
    const extensions = cert.extensions.map((e) => `    ${extensionLine(e)}`);
    return [
        'Certificate',
        ...rows([
            ['Version', String(cert.version)],
            ['Serial', `${cert.serialNumber.hex} (${cert.serialNumber.value.toString()})`],
            ['Signature', oidLabel(cert.signatureAlgorithm.oid)],
            ['Issuer', dn(cert.issuer)],
            ['Not before', formatInstant(cert.validity.notBefore.epochMilliseconds)],
            ['Not after', formatInstant(cert.validity.notAfter.epochMilliseconds)],
            ['Subject', dn(cert.subject)],
            ['Public key', publicKeyLine(cert.subjectPublicKeyInfo)],
            ['SHA-256', colonHex(computeFingerprint(cert.der, 'SHA-256'))],
        ]),
        `  Extensions (${cert.extensions.length}):`,
        ...extensions,
    ].join('\n');
}

export function renderRequest(csr: CertificationRequest): string {
    const extensions = (csr.extensions ?? []).map((e) => `    ${extensionLine(e)}`);
    return [
        'Certificate request',
        ...rows([
            ['Subject', dn(csr.subject)],
            ['Public key', publicKeyLine(csr.subjectPublicKeyInfo)],
            ['Signature', oidLabel(csr.signatureAlgorithm.oid)],
            ['Attributes', csr.attributes.map((a) => getOidName(a.oid) ?? a.oid).join(', ') || '(none)'],
        ]),
        `  Requested extensions (${extensions.length}):`,
        ...extensions,
    ].join('\n');
}

/** A verdict line followed by one line per reason. */
export function renderVerdict(color: Palette, valid: boolean, what: string, reasons: readonly PkiReason[]): string {
    const head = valid ? color.ok(`${what}: valid`) : color.bad(`${what}: INVALID`);
    return [head, ...reasons.map(reasonLine)].join('\n');
}

export function reasonLine(r: PkiReason): string {
    const where = r.path !== '' ? ` at ${r.path}` : '';
    const cause = r.errorCode !== undefined ? ` [${r.errorCode}]` : '';
    return `  ${r.code}${where}${cause}: ${r.message} (${r.standard})`;
}
