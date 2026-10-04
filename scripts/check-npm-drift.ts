// The npm registry against package.json. Not a verify-docs rule on purpose:
// those are offline and deterministic, and this answer changes without a
// commit. Run weekly by the npm-drift job of .github/workflows/docs.yml
// (anonymous: `npm view` needs no token). Adapted from pkinative's
// scripts/check-npm-drift.ts.
//
// The registry must hold: the name (an unreserved name can be taken); no 0.x
// version but the hand-published 0.0.1 name reservation, under any dist-tag;
// and `latest` equal to package.json's version. Behind it: the release is
// tagged but not published (in flight, or forgotten). Ahead of it: something
// was published that main does not describe.
//   npx tsx scripts/check-npm-drift.ts [--json]
// Exit: 0 in agreement; 1 drift; 2 the registry or package.json could not be read.

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { npm } from './lib/npm.ts';

export const PACKAGE = 'pkinative-cli';
/** The name reservation, published by hand so Trusted Publishing could be configured. */
export const PLACEHOLDER = '0.0.1';

export type RegistryState =
    | { readonly found: false }
    | { readonly found: true; readonly distTags: Readonly<Record<string, string>>; readonly versions: readonly string[] };

const parts = (v: string): number[] => v.split(/[.-]/).slice(0, 3).map(Number);
function compare(a: string, b: string): number {
    const [pa, pb] = [parts(a), parts(b)];
    for (let i = 0; i < 3; i++) {
        const d = (pa[i] ?? 0) - (pb[i] ?? 0);
        if (d !== 0) return d;
    }
    return 0;
}

/** Every problem with the registry for package.json at `version`; empty when they agree. */
export function decideNpmDrift(version: string, registry: RegistryState): string[] {
    if (!registry.found) return [`${PACKAGE} is not on the registry at all — the name is unreserved and can be taken`];
    const out: string[] = [];
    const latest = registry.distTags['latest'] ?? null;
    const preOne = registry.versions.filter((v) => parts(v)[0] === 0 && v !== PLACEHOLDER);
    if (preOne.length > 0) out.push(`pre-1.0 version(s) ${preOne.join(', ')} reached npm — publish.yml refuses every 0.x version; deprecate them and find how they were published`);
    for (const [tag, v] of Object.entries(registry.distTags)) {
        if (!registry.versions.includes(v)) out.push(`dist-tag ${tag} points at ${v}, which the registry does not list`);
    }
    if (latest === null) out.push(`${PACKAGE} has no latest dist-tag; package.json says ${version}`);
    else if (compare(latest, version) < 0) out.push(`latest is ${latest} and package.json says ${version} — ${version} is not published yet (re-run once publish.yml has finished)`);
    else if (compare(latest, version) > 0) out.push(`latest is ${latest}, ahead of package.json's ${version} — something was published that main does not describe`);
    else if (latest !== version) out.push(`latest is ${latest}; package.json says ${version}`);
    return out;
}

/** The state from `npm view --json`; throws when the answer is neither a package nor a 404. */
export function parseNpmView(stdout: string, stderr: string, status: number | null): RegistryState {
    if (status !== 0) {
        if (/\bE404\b/.test(stdout) || /\bE404\b/.test(stderr)) return { found: false };
        throw new Error(`npm view exited ${String(status)}: ${(stderr || stdout).trim().split('\n').slice(-3).join(' ')}`);
    }
    const value = JSON.parse(stdout) as { 'dist-tags'?: unknown; versions?: unknown };
    const tags = value['dist-tags'];
    if (typeof tags !== 'object' || tags === null) throw new Error('npm view returned no dist-tags');
    // npm prints a single version as a string, several as an array.
    const versions = typeof value.versions === 'string' ? [value.versions] : Array.isArray(value.versions) ? value.versions.filter((v): v is string => typeof v === 'string') : [];
    const distTags: Record<string, string> = {};
    for (const [k, v] of Object.entries(tags)) if (typeof v === 'string') distTags[k] = v;
    return { found: true, distTags, versions };
}

function main(argv: readonly string[]): number {
    if (argv.some((a) => a !== '--json')) {
        process.stderr.write('usage: npx tsx scripts/check-npm-drift.ts [--json]\n');
        return 2;
    }
    const root = resolve(import.meta.dirname, '..');
    let version: string;
    let registry: RegistryState;
    try {
        version = (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string }).version;
        const r = npm(['view', PACKAGE, 'dist-tags', 'versions', '--json'], root);
        registry = parseNpmView(r.stdout, r.stderr, r.status);
    } catch (err) {
        process.stderr.write(`check-npm-drift: ${(err as Error).message}\n`);
        return 2;
    }
    const problems = decideNpmDrift(version, registry);
    if (argv.includes('--json')) {
        process.stdout.write(`${JSON.stringify({ ok: problems.length === 0, version, registry, problems }, null, 2)}\n`);
    } else {
        for (const p of problems) process.stdout.write(`drift: ${p}\n`);
        const seen = registry.found ? `latest ${registry.distTags['latest'] ?? '—'}, ${registry.versions.length} version(s)` : 'absent';
        process.stdout.write(`check-npm-drift: package.json ${version}, registry ${seen} — ${problems.length === 0 ? 'in agreement' : `${problems.length} problem(s)`}\n`);
    }
    return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    process.exitCode = main(process.argv.slice(2));
}
