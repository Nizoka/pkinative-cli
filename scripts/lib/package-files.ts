// What `npm pack` may put in the tarball, shared by scripts/package-files.ts
// (which compares `npm pack --dry-run --json` with docs/data/package-files.json)
// and the package-files rule of scripts/verify-docs.ts. Adapted from
// pkinative's scripts/lib/package-files.ts.
//
// Pinned per file: the path, the role derived from the path, and the sha256 of
// the legal texts only. The bundle is held by its byte budget
// (docs/data/budgets.json) and bundle-check, the documents by verify-docs, and
// package.json changes with every bump. The executable bit is not pinned: a
// Windows checkout never reports one, and npm sets it on the bin at install,
// which scripts/smoke-install.ts proves by running the installed bin.

import { createHash } from 'node:crypto';

export const PACKAGE_FILES_MANIFEST = 'docs/data/package-files.json';
export const PACKAGE_FILES_COMMAND = 'npx tsx scripts/package-files.ts --update';
export const BUDGETS = 'docs/data/budgets.json';

export type PackageFileRole = 'build' | 'legal' | 'doc' | 'data' | 'manifest';

export interface PackageFile {
    readonly path: string;
    readonly role: PackageFileRole;
    readonly sha256?: string;
}

export interface PackageFilesManifest {
    readonly $comment?: string;
    readonly generatedBy?: string;
    readonly files: readonly PackageFile[];
}

/** The texts a redistributor ships verbatim: a change to either is a decision. */
export const LEGAL_FILES: readonly string[] = ['LICENSE', 'THIRD-PARTY-NOTICES.md'];

/** Files npm packs whatever `files` says. */
export const ALWAYS_PACKED: readonly string[] = ['package.json', 'README.md', 'LICENSE'];

/** Never in the tarball, whatever the manifest says, so regenerating it cannot bless a leak. */
export const FORBIDDEN: ReadonlyArray<{ readonly pattern: RegExp; readonly why: string }> = [
    { pattern: /^(src|tests?|scripts|samples|examples|fuzz)\//, why: 'a source, test, sample or tooling directory' },
    { pattern: /^docs\/(?!data\/errors\.json$|AGENT_CONTRACT\.md$)/, why: 'a document other than the shipped error catalogue and agent contract' },
    { pattern: /(^|\/)\./, why: 'a dotfile (.env, .npmrc, .github, .claude, an editor config)' },
    { pattern: /(^|\/)(node_modules|coverage|test-output|fixtures)\//, why: 'a dependency, report or fixture directory' },
    { pattern: /\.(der|pem|crt|cer|p7b|p7c|p7s|p12|pfx|key|p8|csr|crl|tsq|tsr|ocsp|tgz|zip|log)$/i, why: 'key material, a certificate, a PKI message, an archive or a log' },
    { pattern: /\.(test|spec|bench)\.[cm]?[jt]s$/, why: 'a test or benchmark file' },
    { pattern: /\.(ts|map|tsbuildinfo)$/, why: 'a TypeScript source, a source map or a build cache (the CLI ships no types)' },
];

export function roleOf(path: string): PackageFileRole {
    if (path.startsWith('dist/')) return 'build';
    if (LEGAL_FILES.includes(path)) return 'legal';
    if (path === 'package.json') return 'manifest';
    if (path.startsWith('docs/data/')) return 'data';
    return 'doc';
}

export function sha256(bytes: Uint8Array | string): string {
    return createHash('sha256').update(bytes).digest('hex');
}

export function forbiddenReason(path: string): string | null {
    return FORBIDDEN.find((f) => f.pattern.test(path))?.why ?? null;
}

/** Manifest entries for a packed list, sorted by path; `readBytes` supplies each legal file. */
export function manifestEntries(
    packed: ReadonlyArray<{ readonly path: string }>,
    readBytes: (path: string) => Uint8Array | string | null,
): PackageFile[] {
    return packed
        .map(({ path }) => path)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((path) => {
            const role = roleOf(path);
            if (role !== 'legal') return { path, role };
            const bytes = readBytes(path);
            return bytes === null ? { path, role } : { path, role, sha256: sha256(bytes) };
        });
}

/**
 * The rules a file list must meet on its own: nothing forbidden, every dist/
 * file budgeted and every budget shipped, every other file declared by
 * package.json `files` (or packed unconditionally), every `files` entry
 * shipping something, and every bin target shipped.
 */
export function listFindings(
    paths: readonly string[],
    packageJsonFiles: readonly string[],
    budgeted: readonly string[],
    bin: readonly string[],
): string[] {
    const out: string[] = [];
    for (const path of paths) {
        const why = forbiddenReason(path);
        if (why !== null) out.push(`${path} must never ship (${why})`);
    }
    const dist = paths.filter((p) => p.startsWith('dist/'));
    for (const path of dist) if (!budgeted.includes(path)) out.push(`${path} ships without a byte budget in ${BUDGETS}`);
    for (const path of budgeted) if (!dist.includes(path)) out.push(`${BUDGETS} budgets ${path}, which does not ship`);
    const under = (p: string, entry: string): boolean => p === entry || p.startsWith(`${entry.replace(/\/+$/, '')}/`);
    for (const path of paths) {
        if (!packageJsonFiles.some((f) => under(path, f)) && !ALWAYS_PACKED.includes(path)) out.push(`${path} ships but package.json "files" does not declare it`);
    }
    for (const entry of packageJsonFiles) {
        if (!paths.some((p) => under(p, entry))) out.push(`package.json "files" declares ${entry}, which ships nothing`);
    }
    for (const target of bin) {
        if (!paths.includes(target.replace(/^\.\//, ''))) out.push(`the bin ${target} does not ship`);
    }
    return out;
}

/** The differences between the pinned list and the packed one. */
export function compareEntries(pinned: readonly PackageFile[], actual: readonly PackageFile[]): string[] {
    const out: string[] = [];
    const byPath = new Map(pinned.map((f) => [f.path, f]));
    const actualPaths = new Set(actual.map((f) => f.path));
    for (const file of actual) {
        const pin = byPath.get(file.path);
        if (pin === undefined) {
            out.push(`added: ${file.path}`);
            continue;
        }
        if (pin.role !== file.role) out.push(`role changed: ${file.path} ${pin.role} → ${file.role}`);
        if (pin.sha256 !== file.sha256) out.push(`content changed: ${file.path} sha256 ${pin.sha256 ?? 'none'} → ${file.sha256 ?? 'none'}`);
    }
    for (const pin of pinned) if (!actualPaths.has(pin.path)) out.push(`removed: ${pin.path}`);
    return out;
}

/** The manifest's own shape: sorted, unique, roles derived, a hash exactly on the legal files. */
export function manifestShapeFindings(files: readonly PackageFile[]): string[] {
    const out: string[] = [];
    const paths = files.map((f) => f.path);
    if (new Set(paths).size !== paths.length) out.push('a path is listed twice');
    if (paths.some((p, i) => i > 0 && (paths[i - 1] ?? '') >= p)) out.push('the files are not sorted by path');
    for (const f of files) {
        if (f.role !== roleOf(f.path)) out.push(`${f.path} has role ${f.role}, derived role is ${roleOf(f.path)}`);
        else if ((f.role === 'legal') !== (typeof f.sha256 === 'string' && /^[0-9a-f]{64}$/.test(f.sha256))) {
            out.push(`${f.path}: a sha256 is pinned for the legal files and for them only`);
        }
    }
    return out;
}
