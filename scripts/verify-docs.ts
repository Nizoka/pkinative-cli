// Holds the documentation to the source, offline and deterministically: every
// figure, version, command, link and generated file a reader can see is
// derived or checked here, so a doc cannot drift from what ships. Ported in
// spirit from pdfnative-cli's and pkinative's verify-docs.
//   npx tsx scripts/verify-docs.ts            every rule
//   npx tsx scripts/verify-docs.ts --list     the rules and what they hold
// Exit: 0 clean; 1 a finding; 2 usage.

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, normalize, relative, resolve } from 'node:path';
import { COMMANDS } from '../src/commands/registry.ts';
import { ERROR_CODES } from '../src/utils/error.ts';
import { LIMIT_FLAG_NAMES } from '../src/utils/limits.ts';
import { expectedRules, RULES_DIR } from './build-claude-rules.ts';
import { generatedDocs } from './lib/docs.ts';
import { BUDGETS, LEGAL_FILES, listFindings, manifestShapeFindings, PACKAGE_FILES_MANIFEST, sha256, type PackageFilesManifest } from './lib/package-files.ts';
import { SAMPLES } from './lib/sample-plan.ts';
import { ps1Script, samplePath, shScript } from './lib/samples.ts';
import { surfaceDocument } from './lib/surface.ts';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8').replace(/\r\n/g, '\n');
const readJson = <T>(path: string): T => JSON.parse(read(path)) as T;

interface Rule {
    readonly id: string;
    readonly holds: string;
    readonly check: () => string[];
}

// ── The files the rules read ────────────────────────────────────────

const SKIP_DIRS = new Set(['node_modules', 'dist', 'coverage', 'test-output', '.git', '.audit', 'samples', 'tests']);

/** Every Markdown file of the repository a reader sees, repository-relative with `/`. */
function markdownFiles(): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(join(ROOT, dir))) {
            const path = dir === '' ? entry : `${dir}/${entry}`;
            if (SKIP_DIRS.has(entry) || path === 'docs/data/pkinative') continue;
            if (statSync(join(ROOT, path)).isDirectory()) walk(path);
            else if (entry.endsWith('.md')) out.push(path);
        }
    };
    walk('');
    return out.sort();
}

const pkg = readJson<{ version: string; engines: { node: string }; dependencies: Record<string, string>; files: string[]; bin: Record<string, string> }>('package.json');

// ── Figures ─────────────────────────────────────────────────────────

const surface = readJson<{ exports: Array<{ kind: string }> }>('docs/data/core-exports.json');
const countOf = (path: string, key: string): number => {
    const doc = readJson<Record<string, unknown>>(path);
    const value = doc[key];
    return Array.isArray(value) ? value.length : Object.keys(value as object).filter((k) => !k.startsWith('$')).length;
};

/** Each figure the docs quote, with the phrases that quote it. */
export const FIGURES: ReadonlyArray<{ readonly what: string; readonly value: number; readonly phrases: readonly RegExp[] }> = [
    { what: 'commands', value: COMMANDS.length, phrases: [/\b(\d+) commands\b/g] },
    { what: 'subcommands', value: COMMANDS.reduce((n, c) => n + c.subcommands.length, 0), phrases: [/\b(\d+) subcommands\b/g] },
    { what: 'engine exports', value: surface.exports.length, phrases: [/\b(\d+) exports\b/g] },
    { what: 'runtime exports', value: surface.exports.filter((e) => e.kind !== 'type').length, phrases: [/\b(\d+) runtime exports\b/g] },
    { what: 'types', value: surface.exports.filter((e) => e.kind === 'type').length, phrases: [/\b(\d+) types\b/g] },
    { what: 'E_* classes', value: ERROR_CODES.length, phrases: [/\b(\d+) `?E_\*`? classes\b/g, /\b(\d+) (?:stable )?CLI classes\b/g, /\b(\d+) classes\b/g] },
    { what: 'PKI_* codes', value: countOf('docs/data/pkinative/errors.json', 'errors'), phrases: [/\b(\d+) `?PKI_\*`? (?:errors|codes)\b/g, /\b(\d+) codes\b/g] },
    { what: 'reasons', value: countOf('docs/data/pkinative/reasons.json', 'reasons'), phrases: [/\b(\d+) (?:`?PKI_REASON_\*`? )?reasons\b/g] },
    { what: 'diagnostics', value: countOf('docs/data/pkinative/diagnostics.json', 'diagnostics'), phrases: [/\b(\d+) (?:`?PKI_DIAG_\*`? )?diagnostics\b/g] },
    { what: 'limits', value: LIMIT_FLAG_NAMES.length, phrases: [/\b(\d+) (?:pkinative )?(?:security )?bounds\b/g, /\b(\d+) limits\b/g] },
    { what: 'engine CHANGELOG bullets', value: readJson<{ items: unknown[] }>('tests/regression/engine-surface.json').items.length, phrases: [/\b(\d+) bullets\b/g] },
    { what: 'samples', value: SAMPLES.length, phrases: [/\b(\d+) samples\b/g] },
];

/** Files whose figures describe the current release (history is left alone). */
function figureFiles(): string[] {
    const current = `release-notes/v${pkg.version}.md`;
    return [...markdownFiles().filter((f) => !f.startsWith('release-notes/') && f !== 'CHANGELOG.md'), current, 'llms.txt'].filter((f) => existsSync(join(ROOT, f)));
}

function figures(): string[] {
    const out: string[] = [];
    for (const file of figureFiles()) {
        const lines = read(file).split('\n');
        lines.forEach((line, i) => {
            const claimed = new Set<number>();
            for (const fig of FIGURES) {
                for (const phrase of fig.phrases) {
                    for (const m of line.matchAll(phrase)) {
                        if (m.index === undefined || claimed.has(m.index)) continue;
                        claimed.add(m.index);
                        const n = Number(m[1]);
                        if (n !== fig.value) out.push(`${file}:${i + 1}: "${m[0]}" — the source says ${fig.value} ${fig.what}`);
                    }
                }
            }
        });
    }
    return out;
}

// ── Generated files ─────────────────────────────────────────────────

function generated(): string[] {
    const out: string[] = [];
    const expected: Record<string, string> = {
        ...generatedDocs(),
        'docs/data/core-exports.json': JSON.stringify(surfaceDocument(), null, 2) + '\n',
    };
    for (const [path, text] of Object.entries(expected)) {
        if (!existsSync(join(ROOT, path)) || read(path) !== text) out.push(`${path} is stale: run npm run docs:build / npm run surface:build`);
    }
    const engine = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/build-engine-surface.ts', '--check'], { cwd: ROOT, encoding: 'utf8', windowsHide: true });
    if (engine.status !== 0) out.push(engine.stderr.trim() || 'scripts/build-engine-surface.ts --check failed');
    for (const [name, text] of Object.entries(expectedRules(ROOT))) {
        const path = `${RULES_DIR}/${name}`;
        if (!existsSync(join(ROOT, path)) || read(path) !== text) out.push(`${path} is out of sync with .github/instructions: run npm run agents:rules`);
    }
    const present = existsSync(join(ROOT, RULES_DIR)) ? readdirSync(join(ROOT, RULES_DIR)) : [];
    for (const name of present) if (!(name in expectedRules(ROOT))) out.push(`${RULES_DIR}/${name} has no source in .github/instructions`);
    return out;
}

// ── Commands ────────────────────────────────────────────────────────

function commands(): string[] {
    const out: string[] = [];
    const readme = read('README.md');
    const kb = read('docs/KNOWLEDGE_BASE.md');
    const usage = read('src/commands/usage.ts');
    const headings = [...readme.matchAll(/^### `pkinative ([a-z0-9-]+)`$/gm)].map((m) => m[1]);
    if (headings.join() !== COMMANDS.map((c) => c.name).join()) out.push(`README.md: the command headings (${headings.join(', ')}) are not the registry's, in order`);
    for (const c of COMMANDS) {
        const row = new RegExp(String.raw`^\| ${c.group.replace(/[&]/g, '\\&')} \|.*\`${c.name}\``, 'm');
        if (!row.test(readme)) out.push(`README.md: the Commands table does not list ${c.name} under ${c.group}`);
        if (!new RegExp(String.raw`^\|.*\`${c.name}[\` ]`, 'm').test(kb)) out.push(`docs/KNOWLEDGE_BASE.md §5: no row describes ${c.name}`);
        if (c.name !== 'doctor' && !existsSync(join(ROOT, 'samples', c.name))) out.push(`samples/${c.name}/ is missing`);
        for (const s of c.subcommands) {
            if (!SAMPLES.some((p) => p.argv[0] === c.name && p.argv[1] === s.name)) out.push(`${c.name} ${s.name} has no sample in scripts/lib/sample-plan.ts`);
            if (!usage.includes(` ${s.name} `) && !usage.includes(` ${s.name}\n`)) out.push(`src/commands/usage.ts does not describe ${c.name} ${s.name}`);
        }
    }
    return out;
}

function samples(): string[] {
    const out: string[] = [];
    const expected = new Map<string, string>();
    for (const s of SAMPLES) {
        expected.set(samplePath(s, 'sh'), shScript(s));
        expected.set(samplePath(s, 'ps1'), ps1Script(s));
    }
    for (const [path, text] of expected) {
        if (!existsSync(join(ROOT, path)) || read(path) !== text) out.push(`${path} is stale: run npm run samples:generate`);
    }
    for (const dir of readdirSync(join(ROOT, 'samples'))) {
        if (dir === 'inputs') continue;
        for (const file of readdirSync(join(ROOT, 'samples', dir))) {
            if (!expected.has(`samples/${dir}/${file}`)) out.push(`samples/${dir}/${file} is not in the sample plan`);
        }
    }
    return out;
}

// ── Versions ────────────────────────────────────────────────────────

function versions(): string[] {
    const out: string[] = [];
    const v = pkg.version;
    const minor = v.split('.').slice(0, 2).join('.');
    const citation = read('CITATION.cff');
    const changelog = read('CHANGELOG.md');
    const entry = new RegExp(String.raw`^## \[${v.replace(/\./g, '\\.')}\] – (\d{4}-\d{2}-\d{2})$`, 'm').exec(changelog);
    if (!new RegExp(String.raw`^version: ${v.replace(/\./g, '\\.')}$`, 'm').test(citation)) out.push(`CITATION.cff: version is not ${v}`);
    if (entry === null) out.push(`CHANGELOG.md: no "## [${v}] – YYYY-MM-DD" entry`);
    else if (!citation.includes(`date-released: ${entry[1] ?? ''}`)) out.push(`CITATION.cff: date-released is not the CHANGELOG date ${entry[1] ?? ''}`);
    if (!changelog.includes(`[${v}]: https://github.com/Nizoka/pkinative-cli/`)) out.push(`CHANGELOG.md: no link definition for [${v}]`);
    if (!existsSync(join(ROOT, `release-notes/v${v}.md`))) out.push(`release-notes/v${v}.md is missing`);
    if (!read('llms.txt').includes(`Version ${v}`)) out.push(`llms.txt does not say "Version ${v}"`);
    if (!read('SECURITY.md').includes(`| ${minor}.x |`)) out.push(`SECURITY.md: the supported-versions table has no ${minor}.x row`);
    for (const m of read('SECURITY.md').matchAll(/pkinative-cli[@-](\d+\.\d+\.\d+)/g)) {
        if (m[1] !== v) out.push(`SECURITY.md quotes pkinative-cli ${m[1] ?? ''}, the version is ${v}`);
    }
    const engine = pkg.dependencies['pkinative'] ?? '';
    if (Object.keys(pkg.dependencies).join() !== 'pkinative') out.push(`package.json: the runtime dependencies are ${Object.keys(pkg.dependencies).join(', ')}, not pkinative alone`);
    if (!read('llms.txt').includes(`pkinative ${engine}`)) out.push(`llms.txt does not name the engine range pkinative ${engine}`);
    for (const file of ['README.md', 'CONTRIBUTING.md', 'llms.txt']) {
        if (!read(file).includes(pkg.engines.node)) out.push(`${file} does not quote the Node.js range ${pkg.engines.node}`);
    }
    return out;
}

// ── Links ───────────────────────────────────────────────────────────

/** GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens, -N for repeats. */
export function anchorsOf(markdown: string): Set<string> {
    const seen = new Map<string, number>();
    const out = new Set<string>();
    let fenced = false;
    for (const line of markdown.split('\n')) {
        if (/^\s*```/.test(line)) fenced = !fenced;
        const m = fenced ? null : /^#{1,6} (.+?)\s*#*$/.exec(line);
        if (m === null) continue;
        const base = (m[1] ?? '').toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').replace(/ /g, '-');
        const n = seen.get(base) ?? 0;
        seen.set(base, n + 1);
        out.add(n === 0 ? base : `${base}-${n}`);
    }
    return out;
}

function links(): string[] {
    const out: string[] = [];
    for (const file of markdownFiles()) {
        const text = read(file).replace(/^\s*```[\s\S]*?^\s*```/gm, '');
        for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) {
            const target = m[1] ?? '';
            if (/^[a-z]+:/i.test(target)) continue;
            const [pathPart, anchor] = target.split('#') as [string, string | undefined];
            const resolved = pathPart === '' ? file : normalize(join(dirname(file), decodeURIComponent(pathPart))).replace(/\\/g, '/');
            if (relative(ROOT, join(ROOT, resolved)).startsWith('..')) {
                out.push(`${file}: link ${target} leaves the repository`);
                continue;
            }
            if (!existsSync(join(ROOT, resolved))) {
                out.push(`${file}: link ${target} — ${resolved} does not exist`);
                continue;
            }
            if (anchor !== undefined && anchor !== '' && resolved.endsWith('.md') && !anchorsOf(read(resolved)).has(anchor)) {
                out.push(`${file}: link ${target} — ${resolved} has no heading #${anchor}`);
            }
        }
    }
    return out;
}

// ── Contributor and agent surfaces ──────────────────────────────────

function checklist(markdown: string): string[] {
    return markdown.split('\n').filter((l) => l.startsWith('- [ ] ')).map((l) => l.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1'));
}

function prTemplate(): string[] {
    const contributing = read('CONTRIBUTING.md');
    const start = contributing.indexOf('## Pull Request Checklist');
    if (start === -1) return ['CONTRIBUTING.md has no "## Pull Request Checklist" section'];
    const section = contributing.slice(start, contributing.indexOf('\n## ', start + 1));
    const a = checklist(section);
    const b = checklist(read('.github/pull_request_template.md'));
    const out: string[] = [];
    for (const item of a) if (!b.includes(item)) out.push(`.github/pull_request_template.md lacks: ${item}`);
    for (const item of b) if (!a.includes(item)) out.push(`CONTRIBUTING.md §Pull Request Checklist lacks: ${item}`);
    return out;
}

function agents(): string[] {
    const out: string[] = [];
    if (!read('CLAUDE.md').startsWith('@AGENTS.md')) out.push('CLAUDE.md must start with @AGENTS.md');
    const settings = readJson<{ attribution?: { commit?: string; pr?: string }; permissions?: { deny?: string[] } }>('.claude/settings.json');
    if (settings.attribution?.commit !== '' || settings.attribution.pr !== '') out.push('.claude/settings.json: attribution.commit and attribution.pr must both be ""');
    for (const forbidden of ['Bash(npm publish*)', 'Bash(git push *)', 'Bash(gh pr create*)', 'Bash(gh release *)', 'PowerShell(npm publish*)', 'PowerShell(git push *)']) {
        if (!(settings.permissions?.deny ?? []).includes(forbidden)) out.push(`.claude/settings.json: deny lacks ${forbidden}`);
    }
    readJson<unknown>('.github/ai-governance.json');
    for (const file of markdownFiles()) {
        if (file === '.github/AGENT_RULES.md') continue;
        for (const line of read(file).split('\n')) {
            if (/^Co-Authored-By:/i.test(line.trim())) out.push(`${file}: an attribution trailer line`);
        }
    }
    return out;
}

function packageFiles(): string[] {
    const manifest = readJson<PackageFilesManifest>(PACKAGE_FILES_MANIFEST);
    const budgets = Object.keys(readJson<Record<string, unknown>>(BUDGETS)).filter((k) => !k.startsWith('$'));
    const out = [...manifestShapeFindings(manifest.files), ...listFindings(manifest.files.map((f) => f.path), pkg.files, budgets, Object.values(pkg.bin))];
    for (const legal of LEGAL_FILES) {
        const pinned = manifest.files.find((f) => f.path === legal)?.sha256;
        if (pinned !== sha256(readFileSync(join(ROOT, legal)))) out.push(`${legal} changed since ${PACKAGE_FILES_MANIFEST} pinned it: run npx tsx scripts/package-files.ts --update and review`);
    }
    return out;
}

function adrs(): string[] {
    const out: string[] = [];
    const files = readdirSync(join(ROOT, 'docs/adr')).filter((f) => /^\d{4}-/.test(f)).sort();
    files.forEach((f, i) => {
        if (!f.startsWith(String(i + 1).padStart(4, '0'))) out.push(`docs/adr/${f}: ADR numbers must run 0001.. without gaps`);
        if (!/^---\nstatus: (proposed|accepted|superseded|deprecated)\n/.test(read(`docs/adr/${f}`))) out.push(`docs/adr/${f}: frontmatter must open with a status`);
    });
    return out;
}

export const RULES: readonly Rule[] = [
    { id: 'generated', holds: 'errors.json, the knowledge-base tables, core-exports.json, engine-surface.json and .claude/rules equal their generators', check: generated },
    { id: 'commands', holds: 'README headings and table, knowledge base, usage text and samples cover every registry command and subcommand', check: commands },
    { id: 'samples', holds: 'samples/ equals the rendering of the sample plan, with nothing extra', check: samples },
    { id: 'figures', holds: 'every count quoted in the docs equals its source', check: figures },
    { id: 'versions', holds: 'package.json version, CHANGELOG, CITATION, llms.txt, SECURITY.md, the release note and the Node.js and engine ranges agree', check: versions },
    { id: 'links', holds: 'every relative Markdown link and heading anchor resolves', check: links },
    { id: 'pr-template', holds: 'the PR template and CONTRIBUTING.md carry the same checklist', check: prTemplate },
    { id: 'agents', holds: 'CLAUDE.md imports AGENTS.md; attribution is off; the agent deny list holds; no attribution trailer', check: agents },
    { id: 'package-files', holds: 'the pinned tarball list obeys the packing rules and the legal texts are unchanged', check: packageFiles },
    { id: 'adr', holds: 'ADRs are numbered without gaps and carry a status', check: adrs },
];

function main(argv: readonly string[]): number {
    if (argv.some((a) => a !== '--list')) {
        process.stderr.write('usage: npx tsx scripts/verify-docs.ts [--list]\n');
        return 2;
    }
    if (argv.includes('--list')) {
        for (const r of RULES) process.stdout.write(`${r.id.padEnd(14)}${r.holds}\n`);
        return 0;
    }
    let findings = 0;
    for (const rule of RULES) {
        const found = rule.check();
        findings += found.length;
        process.stdout.write(`${found.length === 0 ? 'ok  ' : 'FAIL'}  ${rule.id}\n`);
        for (const f of found) process.stdout.write(`      ${f}\n`);
    }
    process.stdout.write(`verify-docs: ${RULES.length} rules, ${findings} finding(s)\n`);
    return findings === 0 ? 0 : 1;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    process.exitCode = main(process.argv.slice(2));
}
