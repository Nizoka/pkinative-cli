// What the built bundle (dist/cli.cjs) must and must not contain — the gate
// step `bundle-check`, ported from pdfnative-cli's scripts/lib/bundle-probe.ts.
// The byte budget would catch the engine inlined whole; this catches it
// inlined in part, a stray key or certificate, a debug print, an attribution
// trailer, or a dependency package.json does not declare. Pure, so tests feed
// it synthetic bundles.

import { isBuiltin } from 'node:module';

/** The only modules the bundle may require besides Node built-ins. */
export const ALLOWED_EXTERNALS: ReadonlySet<string> = new Set(['pkinative', 'pkinative/package.json']);

/** The engine stays external, never inlined. */
export const REQUIRED_EXTERNALS: readonly string[] = ['pkinative'];

/**
 * Definitions that only exist inside the engine's own build: one per layer
 * (ASN.1, X.509, path validation, CMS, PKCS#12). The CLI calls these
 * functions and never defines them, so any of them in the bundle means engine
 * code was inlined.
 */
export const ENGINE_MARKERS: readonly string[] = [
    'function decodeAsn1(',
    'function parseCertificate(',
    'function verifyCertificateChain(',
    'function createSignedData(',
    'function openPkcs12(',
];

const REQUIRE_RE = /require\((['"])([^'"]+)\1\)/g;
const BASE64_RUN = /[A-Za-z0-9+/]{2048,}/;
// A real PEM block: header, at least 64 base64 / whitespace characters (or the
// `\n` escapes of a string literal), footer. The PEM regexes in src/ never match.
const PEM_BLOCK = /-----BEGIN [A-Z0-9 ]+-----(?:[A-Za-z0-9+/=\s]|\\[nr]){64,}-----END [A-Z0-9 ]+-----/;

export function externalRequires(code: string): string[] {
    const out = new Set<string>();
    for (const m of code.matchAll(REQUIRE_RE)) {
        const spec = m[2] ?? '';
        if (spec.startsWith('.') || spec.startsWith('/')) continue;
        out.add(spec);
    }
    return [...out].sort();
}

/** The failure lines for `code`; empty when the bundle is what it should be. */
export function probeBundle(code: string): string[] {
    const failures: string[] = [];
    const lines = code.split('\n');
    if (!(lines[0] ?? '').startsWith('#!/usr/bin/env node')) failures.push('the first line is not the node shebang');
    lines.forEach((line, i) => {
        if (i > 0 && line.startsWith('#!')) failures.push(`line ${i + 1} is a second shebang`);
    });
    for (const marker of ENGINE_MARKERS) {
        if (code.includes(marker)) failures.push(`engine marker ${JSON.stringify(marker)} found — engine code is inlined`);
    }
    if (BASE64_RUN.test(code)) failures.push('a base64 run of 2048+ characters found — embedded binary data');
    if (code.includes('Co-Authored-By')) failures.push('"Co-Authored-By" found — attribution trailers never ship');
    if (PEM_BLOCK.test(code)) failures.push('a PEM block found — key material or a certificate is embedded');
    if (code.includes('console.log(')) failures.push('console.log( found — stdout is reserved for the artefact');
    const externals = externalRequires(code);
    for (const spec of externals) {
        if (!ALLOWED_EXTERNALS.has(spec) && !isBuiltin(spec)) failures.push(`external require("${spec}") is not a Node built-in and not on the allow list`);
    }
    for (const required of REQUIRED_EXTERNALS) {
        if (!externals.includes(required)) failures.push(`require("${required}") is missing — the engine must stay external`);
    }
    return failures;
}
