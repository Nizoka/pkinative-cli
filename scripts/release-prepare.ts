// The mechanical part of a version bump, in one pass, so the release commit
// reads as the bump and nothing else and verify-docs has nothing left to
// catch. Adapted from pkinative's scripts/release-prepare.ts.
//
// It edits, each with a targeted regex on the one field it owns (formatting
// and key order survive): package.json and package-lock.json `version`;
// CITATION.cff `version` and `date-released`; CHANGELOG.md `## [Unreleased]`
// into `## [X.Y.Z] – date` with a fresh `[Unreleased]` above and the link
// definitions; llms.txt `Version`; SECURITY.md's supported-versions row and
// the versioned verification commands. It scaffolds release-notes/vX.Y.Z.md
// and release-notes/draft/PR-vX.Y.Z.md from their templates when absent.
// Nothing is written while any row fails. It never tags, commits, pushes or
// publishes (.github/AGENT_RULES.md §5).
//   npx tsx scripts/release-prepare.ts --version X.Y.Z [--date YYYY-MM-DD] [--dry-run]
// Exit: 0 done (or dry run reported); 1 a file or field is missing; 2 usage.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const REPO = 'https://github.com/Nizoka/pkinative-cli';

interface Edit {
    readonly file: string;
    readonly what: string;
    readonly pattern: RegExp;
    readonly replace: (version: string, date: string, from: string) => string;
}

const minor = (v: string): string => v.split('.').slice(0, 2).join('.');

export const EDITS: readonly Edit[] = [
    { file: 'package.json', what: 'version', pattern: /("name": "pkinative-cli",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'package-lock.json', what: 'root version', pattern: /("name": "pkinative-cli",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'package-lock.json', what: 'root package version', pattern: /("packages": \{\s*\n\s*"": \{\s*\n\s*"name": "pkinative-cli",\s*\n\s*"version": ")[^"]+(")/, replace: (v) => `$1${v}$2` },
    { file: 'CITATION.cff', what: 'version', pattern: /^(version: ).+$/m, replace: (v) => `$1${v}` },
    { file: 'CITATION.cff', what: 'date-released', pattern: /^(date-released: ).+$/m, replace: (_v, d) => `$1${d}` },
    { file: 'CHANGELOG.md', what: 'Unreleased heading', pattern: /^## \[Unreleased\]$/m, replace: (v, d) => `## [Unreleased]\n\n## [${v}] – ${d}` },
    {
        file: 'CHANGELOG.md', what: 'link definitions', pattern: /^\[Unreleased\]: .+$/m,
        replace: (v, _d, from) => `[Unreleased]: ${REPO}/compare/v${v}...HEAD\n[${v}]: ${REPO}/compare/v${from}...v${v}`,
    },
    { file: 'llms.txt', what: 'Version', pattern: /(Version )\d+\.\d+\.\d+/, replace: (v) => `$1${v}` },
    { file: 'SECURITY.md', what: 'supported-versions row', pattern: /^\| \d+\.\d+\.x \| ✅ \|$/m, replace: (v) => `| ${minor(v)}.x | ✅ |` },
    { file: 'SECURITY.md', what: 'versioned verification commands', pattern: /pkinative-cli([@-])\d+\.\d+\.\d+/g, replace: (v) => `pkinative-cli$1${v}` },
];

export interface ReleasePlan {
    readonly texts: ReadonlyMap<string, string>;
    readonly lines: ReadonlyArray<{ readonly level: 'edit' | 'new' | 'FAIL'; readonly text: string }>;
    readonly failures: number;
}

export type TreeReader = (path: string) => string | null;

/** The whole bump, planned against `read` and written nowhere. */
export function planRelease(read: TreeReader, version: string, date: string): ReleasePlan {
    const texts = new Map<string, string>();
    const lines: Array<{ level: 'edit' | 'new' | 'FAIL'; text: string }> = [];
    let failures = 0;
    const current = (path: string): string | null => texts.get(path) ?? read(path);
    const from = /"version": "(\d+\.\d+\.\d+)"/.exec(read('package.json') ?? '')?.[1] ?? '0.0.0';
    for (const edit of EDITS) {
        const before = current(edit.file);
        edit.pattern.lastIndex = 0;
        if (before === null || !edit.pattern.test(before)) {
            const again = before?.includes(version) === true ? ` (the file already mentions ${version}: has this bump already run?)` : '';
            lines.push({ level: 'FAIL', text: `${edit.file}: ${edit.what} not found${again}` });
            failures++;
            continue;
        }
        edit.pattern.lastIndex = 0;
        texts.set(edit.file, before.replace(edit.pattern, edit.replace(version, date, from)));
        lines.push({ level: 'edit', text: `${edit.file}: ${edit.what}` });
    }
    const scaffolds: ReadonlyArray<readonly [string, string]> = [
        [`release-notes/v${version}.md`, 'release-notes/TEMPLATE.md'],
        [`release-notes/draft/PR-v${version}.md`, 'release-notes/PR_TEMPLATE.md'],
    ];
    for (const [target, template] of scaffolds) {
        if (read(target) !== null) continue;
        const body = /```markdown\n([\s\S]*?)\n```\n/.exec(read(template) ?? '')?.[1] ?? '';
        if (body === '') {
            lines.push({ level: 'FAIL', text: `${template}: no fenced markdown block to scaffold from` });
            failures++;
            continue;
        }
        texts.set(target, `${body.replace(/X\.Y\.Z/g, version).replace(/YYYY-MM-DD/g, date).replace(/\\`\\`\\`/g, '```')}\n`);
        lines.push({ level: 'new', text: `${target} (from ${template} — fill it in)` });
    }
    return { texts, lines, failures };
}

export function parseArgs(argv: readonly string[]): { version: string; date: string; dryRun: boolean } | null {
    const value = (flag: string): string | undefined => {
        const at = argv.indexOf(flag);
        return at >= 0 ? argv[at + 1] : undefined;
    };
    const version = value('--version') ?? '';
    const date = value('--date') ?? new Date().toISOString().slice(0, 10);
    if (!/^\d+\.\d+\.\d+$/.test(version) || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
    return { version, date, dryRun: argv.includes('--dry-run') };
}

function main(argv: readonly string[]): number {
    const args = parseArgs(argv);
    if (args === null) {
        process.stderr.write('usage: npx tsx scripts/release-prepare.ts --version X.Y.Z [--date YYYY-MM-DD] [--dry-run]\n');
        return 2;
    }
    const read: TreeReader = (path) => (existsSync(join(ROOT, path)) ? readFileSync(join(ROOT, path), 'utf8').replace(/\r\n/g, '\n') : null);
    const plan = planRelease(read, args.version, args.date);
    for (const line of plan.lines) (line.level === 'FAIL' ? process.stderr : process.stdout).write(`${line.level.padEnd(6)}${line.text}\n`);
    if (plan.failures > 0) return 1;
    if (!args.dryRun) {
        for (const [file, text] of plan.texts) {
            mkdirSync(dirname(join(ROOT, file)), { recursive: true });
            writeFileSync(join(ROOT, file), text);
        }
    }
    process.stdout.write(`${args.dryRun ? 'dry run: ' : ''}${plan.texts.size} file(s) ${args.dryRun ? 'would change' : 'changed'} for v${args.version} (${args.date}). Next: write the release note and CHANGELOG entry, then npx tsx scripts/gate.ts --publish --require-all.\n`);
    return 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    process.exitCode = main(process.argv.slice(2));
}
