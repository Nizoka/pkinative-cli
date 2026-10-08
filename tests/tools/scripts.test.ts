import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { probeBundle, externalRequires } from '../../scripts/lib/bundle-probe.ts';
import { compareEntries, listFindings, manifestEntries, manifestShapeFindings, roleOf } from '../../scripts/lib/package-files.ts';
import { decideNpmDrift, parseNpmView } from '../../scripts/check-npm-drift.ts';
import { planRelease, parseArgs as releaseArgs } from '../../scripts/release-prepare.ts';
import { parseArgs, selectSteps, STEPS } from '../../scripts/gate.ts';
import { crlfTextFiles, parseLsFilesEol } from '../../scripts/lib/agent-config.ts';
import { anchorsOf, FIGURES, RULES } from '../../scripts/verify-docs.ts';

// The release tooling is code the release depends on: each script's pure core
// is held here, with synthetic inputs, so a defect cannot hide until release day.

describe('gate', () => {
    it('parses profiles and selects steps', () => {
        expect(parseArgs([])).toMatchObject({ profile: 'ci', requireAll: false });
        expect(parseArgs(['--fast', '--publish'])).toEqual({ error: '--fast and --publish are mutually exclusive' });
        expect(parseArgs(['--only'])).toEqual({ error: '--only needs a step id' });
        expect(parseArgs(['--only', 'nope'])).toEqual({ error: 'unknown step "nope"' });
        expect(parseArgs(['--bogus'])).toEqual({ error: 'unknown argument "--bogus"' });
        const publish = parseArgs(['--publish', '--require-all', '--json']);
        if ('error' in publish) throw new Error(publish.error);
        expect(selectSteps(publish).map((s) => s.id)).toEqual(STEPS.map((s) => s.id).filter((id) => id !== 'test'));
        const fast = parseArgs(['--fast']);
        if ('error' in fast) throw new Error(fast.error);
        expect(selectSteps(fast).map((s) => s.id)).toEqual(['typecheck:all', 'lint', 'test', 'verify:docs']);
        const from = parseArgs(['--from', 'verify:docs']);
        if ('error' in from) throw new Error(from.error);
        expect(selectSteps(from)[0]?.id).toBe('verify:docs');
    });

    it('names only npm scripts that exist', () => {
        const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as { scripts: Record<string, string> }).scripts;
        for (const s of STEPS.filter((x) => x.npmScript !== undefined)) expect(scripts, s.id).toHaveProperty([s.npmScript as string]);
        // The fast and CI profiles build before the suites that need dist/.
        const ids = STEPS.map((s) => s.id);
        expect(ids.indexOf('build')).toBeLessThan(ids.indexOf('test:coverage'));
        expect(STEPS.find((s) => s.id === 'test:coverage')?.env).toMatchObject({ GATE_REQUIRE_ARTIFACTS: '1' });
    });
});

describe('bundle-probe', () => {
    const ok = "#!/usr/bin/env node\nconst p = require('pkinative'); require('node:fs'); require('./x');\n";
    it('accepts a clean bundle', () => {
        expect(probeBundle(ok)).toEqual([]);
        expect(externalRequires(ok)).toEqual(['node:fs', 'pkinative']);
    });
    it('names every defect', () => {
        const pem = `-----BEGIN PRIVATE KEY-----\\n${'A'.repeat(70)}\\n-----END PRIVATE KEY-----`;
        const bad = `// no shebang\n#!/x\nfunction decodeAsn1(a) {}\n${'Q'.repeat(2100)}\nCo-Authored-By\n${pem}\nconsole.log(1)\nrequire('left-pad')`;
        const failures = probeBundle(bad).join('\n');
        for (const what of ['first line', 'second shebang', 'engine marker', 'base64 run', 'Co-Authored-By', 'PEM block', 'console.log', 'left-pad', 'must stay external']) {
            expect(failures).toContain(what);
        }
    });
});

describe('package-files', () => {
    const packed = [{ path: 'package.json', mode: 0o644 }, { path: 'LICENSE', mode: 0o644 }, { path: 'dist/cli.cjs', mode: 0o755 }, { path: 'README.md', mode: 0o644 }];
    const entries = manifestEntries(packed, (p) => (p === 'LICENSE' ? 'MIT' : null));

    it('derives roles and pins only the legal texts', () => {
        expect(entries.map((e) => e.path)).toEqual(['LICENSE', 'README.md', 'dist/cli.cjs', 'package.json']);
        expect(entries.filter((e) => e.sha256 !== undefined).map((e) => e.path)).toEqual(['LICENSE']);
        expect(roleOf('docs/data/errors.json')).toBe('data');
        expect(manifestShapeFindings(entries)).toEqual([]);
        expect(manifestShapeFindings([...entries].reverse())).toContain('the files are not sorted by path');
        expect(manifestShapeFindings([{ path: 'README.md', role: 'legal' }])).toHaveLength(1);
        expect(manifestShapeFindings([{ path: 'README.md', role: 'doc', sha256: 'a'.repeat(64) }])).toHaveLength(1);
    });

    it('refuses leaks, unbudgeted builds and undeclared files', () => {
        const findings = listFindings(['dist/cli.cjs', 'dist/cli.js.map', 'src/cli.ts', 'tests/fixtures/pki/root.key.pem', '.npmrc', 'docs/KNOWLEDGE_BASE.md', 'docs/data/errors.json', 'extra.md'], ['dist', 'docs/data/errors.json', 'gone.md'], ['dist/cli.cjs', 'dist/old.cjs'], ['./dist/cli.cjs', './dist/bin.cjs']).join('\n');
        for (const what of ['dist/cli.js.map must never ship', 'src/cli.ts must never ship', 'root.key.pem must never ship', '.npmrc must never ship', 'KNOWLEDGE_BASE.md must never ship', 'dist/cli.js.map ships without a byte budget', 'budgets dist/old.cjs', 'extra.md ships but', 'declares gone.md', 'the bin ./dist/bin.cjs does not ship']) {
            expect(findings).toContain(what);
        }
        expect(findings).not.toContain('errors.json must never ship');
    });

    it('compares a pinned list with the packed one', () => {
        const changed = [{ path: 'LICENSE', role: 'legal' as const, sha256: 'b'.repeat(64) }, { path: 'new.md', role: 'doc' as const }, { path: 'README.md', role: 'data' as const }];
        expect(compareEntries(entries, changed)).toEqual([
            expect.stringContaining('content changed: LICENSE'),
            'added: new.md',
            'role changed: README.md doc → data',
            'removed: dist/cli.cjs',
            'removed: package.json',
        ]);
    });
});

describe('check-npm-drift', () => {
    it('reads npm view answers', () => {
        expect(parseNpmView('', 'npm error code E404', 1)).toEqual({ found: false });
        expect(() => parseNpmView('', 'ETIMEDOUT', 1)).toThrow(/exited 1/);
        expect(() => parseNpmView('{}', '', 0)).toThrow(/no dist-tags/);
        expect(parseNpmView('{"dist-tags":{"latest":"0.0.1"},"versions":"0.0.1"}', '', 0)).toEqual({ found: true, distTags: { latest: '0.0.1' }, versions: ['0.0.1'] });
    });

    it('decides drift', () => {
        expect(decideNpmDrift('1.0.0', { found: false })[0]).toMatch(/unreserved/);
        expect(decideNpmDrift('1.0.0', { found: true, distTags: { latest: '1.0.0' }, versions: ['0.0.1', '1.0.0'] })).toEqual([]);
        expect(decideNpmDrift('1.0.0', { found: true, distTags: { latest: '0.0.1' }, versions: ['0.0.1'] })[0]).toMatch(/not published yet/);
        expect(decideNpmDrift('1.0.0', { found: true, distTags: { latest: '1.1.0' }, versions: ['1.1.0'] })[0]).toMatch(/ahead/);
        expect(decideNpmDrift('1.0.0', { found: true, distTags: {}, versions: ['1.0.0'] })[0]).toMatch(/no latest/);
        const bad = decideNpmDrift('1.0.0', { found: true, distTags: { latest: '1.0.0', next: '2.0.0' }, versions: ['0.2.0', '1.0.0'] });
        expect(bad.join('\n')).toMatch(/pre-1.0 version\(s\) 0.2.0/);
        expect(bad.join('\n')).toMatch(/dist-tag next points at 2.0.0/);
    });
});

describe('release-prepare', () => {
    const tree: Record<string, string> = {
        'package.json': '{\n  "name": "pkinative-cli",\n  "version": "1.0.0",\n}',
        'package-lock.json': '{\n  "name": "pkinative-cli",\n  "version": "1.0.0",\n  "packages": {\n    "": {\n      "name": "pkinative-cli",\n      "version": "1.0.0",\n',
        'CITATION.cff': 'version: 1.0.0\ndate-released: 2026-10-04\n',
        'CHANGELOG.md': '## [Unreleased]\n\n## [1.0.0] – 2026-10-04\n\n[Unreleased]: https://github.com/Nizoka/pkinative-cli/compare/v1.0.0...HEAD\n',
        'llms.txt': 'Version 1.0.0, on pkinative',
        'SECURITY.md': '| 1.0.x | ✅ |\nnpm view pkinative-cli@1.0.0 x\ngh attestation verify pkinative-cli-1.0.0.tgz\n',
        'release-notes/TEMPLATE.md': '```markdown\n# pkinative-cli vX.Y.Z\n_Released YYYY-MM-DD_\n```\n',
        'release-notes/PR_TEMPLATE.md': '```markdown\n# release: vX.Y.Z\n```\n',
    };
    const read = (p: string): string | null => tree[p] ?? null;

    it('plans the whole bump', () => {
        const plan = planRelease(read, '1.1.0', '2026-11-01');
        expect(plan.failures).toBe(0);
        expect(plan.texts.get('package.json')).toContain('"version": "1.1.0"');
        expect(plan.texts.get('package-lock.json')?.match(/1\.1\.0/g)).toHaveLength(2);
        expect(plan.texts.get('CITATION.cff')).toBe('version: 1.1.0\ndate-released: 2026-11-01\n');
        expect(plan.texts.get('CHANGELOG.md')).toContain('## [Unreleased]\n\n## [1.1.0] – 2026-11-01');
        expect(plan.texts.get('CHANGELOG.md')).toContain('[1.1.0]: https://github.com/Nizoka/pkinative-cli/compare/v1.0.0...v1.1.0');
        expect(plan.texts.get('SECURITY.md')).toBe('| 1.1.x | ✅ |\nnpm view pkinative-cli@1.1.0 x\ngh attestation verify pkinative-cli-1.1.0.tgz\n');
        expect(plan.texts.get('release-notes/v1.1.0.md')).toBe('# pkinative-cli v1.1.0\n_Released 2026-11-01_\n');
        expect(plan.texts.get('release-notes/draft/PR-v1.1.0.md')).toBe('# release: v1.1.0\n');
    });

    it('writes nothing it cannot complete', () => {
        const plan = planRelease((p) => (p === 'llms.txt' || p.startsWith('release-notes/') ? null : read(p)), '1.1.0', '2026-11-01');
        expect(plan.failures).toBe(3);
        expect(plan.lines.filter((l) => l.level === 'FAIL').map((l) => l.text)).toContain('llms.txt: Version not found');
        expect(releaseArgs(['--version', '1.1'])).toBeNull();
        expect(releaseArgs(['--version', '1.1.0', '--date', '2026-11-01', '--dry-run'])).toEqual({ version: '1.1.0', date: '2026-11-01', dryRun: true });
    });
});

describe('verify-docs', () => {
    it('computes GitHub heading anchors', () => {
        const anchors = anchorsOf('# Title\n## 8. pkinative API mapping\n## Paths & revocation\n```\n# not a heading\n```\n## Title\n');
        expect([...anchors]).toEqual(['title', '8-pkinative-api-mapping', 'paths--revocation', 'title-1']);
    });

    it('quotes figures the docs actually use', () => {
        const readme = readFileSync('README.md', 'utf8');
        for (const what of ['commands', 'engine exports', 'PKI_* codes', 'reasons', 'diagnostics', 'limits', 'E_* classes']) {
            const fig = FIGURES.find((f) => f.what === what);
            expect(fig?.phrases.some((p) => new RegExp(p.source).test(readme)), what).toBe(true);
        }
        expect(RULES.map((r) => r.id)).toContain('links');
        expect(RULES.map((r) => r.id)).toContain('eol-lf');
    });

    it('reads the ls-files --eol table and keeps only CRLF or mixed text blobs', () => {
        const table = [
            'i/lf    w/lf    attr/text=auto eol=lf     	src/cli.ts',
            'i/crlf  w/crlf  attr/text=auto eol=lf     	CHANGELOG.md',
            'i/mixed w/mixed attr/text=auto eol=lf     	docs/x.md',
            'i/crlf  w/crlf  attr/-text linguist-vendored=true	scripts/data/Blocks.txt',
            'i/-text w/-text attr/-text -diff -merge   	tests/fixtures/pki/leaf.crt.der',
            'i/crlf  w/crlf  attr/binary                	weird.bin',
            'i/none  w/none  attr/text=auto eol=lf     	empty.txt',
        ].join('\n');
        expect(parseLsFilesEol(table)).toHaveLength(7);
        expect(crlfTextFiles(parseLsFilesEol(table)).map((e) => e.path)).toEqual(['CHANGELOG.md', 'docs/x.md']);
        expect(parseLsFilesEol(table.replace(/\n/g, '\r\n'))).toHaveLength(7);
    });
});
