// Generates .claude/rules/<name>.md from .github/instructions/<name>.instructions.md:
// the instruction's `applyTo` globs become the rule's `paths:` scope.
//   npx tsx scripts/build-claude-rules.ts           write
//   npx tsx scripts/build-claude-rules.ts --check   exit 1 on drift

import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const INSTRUCTIONS_DIR = '.github/instructions';
export const RULES_DIR = '.claude/rules';

/** The rule text for one instruction file. */
export function compileRule(sourceName: string, text: string): string {
    const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text.replace(/\r\n/g, '\n'));
    if (m === null) throw new Error(`${sourceName}: no frontmatter`);
    const apply = /^applyTo:\s*"([^"]+)"\s*$/m.exec(m[1] as string);
    if (apply === null) throw new Error(`${sourceName}: frontmatter has no applyTo`);
    const paths = (apply[1] as string).split(',').map((g) => `  - ${JSON.stringify(g.trim())}`).join('\n');
    const banner = `<!-- GENERATED from ${INSTRUCTIONS_DIR}/${sourceName} by scripts/build-claude-rules.ts — do not edit -->`;
    return `---\npaths:\n${paths}\n---\n${banner}\n\n${(m[2] as string).trim()}\n`;
}

/** Every expected rule, by file name. */
export function expectedRules(root: string): Record<string, string> {
    const dir = join(root, INSTRUCTIONS_DIR);
    const out: Record<string, string> = {};
    for (const name of readdirSync(dir).filter((f) => f.endsWith('.instructions.md')).sort()) {
        out[name.replace(/\.instructions\.md$/, '.md')] = compileRule(name, readFileSync(join(dir, name), 'utf8'));
    }
    return out;
}

function main(): number {
    const root = resolve(import.meta.dirname, '..');
    const expected = expectedRules(root);
    const dir = join(root, RULES_DIR);
    const present = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.md')) : [];
    const drift = [
        ...Object.entries(expected).filter(([n, t]) => !existsSync(join(dir, n)) || readFileSync(join(dir, n), 'utf8') !== t).map(([n]) => n),
        ...present.filter((n) => !(n in expected)),
    ];
    if (process.argv.includes('--check')) {
        for (const n of drift) process.stderr.write(`build-claude-rules: ${RULES_DIR}/${n} is out of sync; run npm run agents:rules\n`);
        return drift.length > 0 ? 1 : 0;
    }
    mkdirSync(dir, { recursive: true });
    for (const [n, t] of Object.entries(expected)) writeFileSync(join(dir, n), t);
    for (const n of present.filter((x) => !(x in expected))) unlinkSync(join(dir, n));
    process.stdout.write(`build-claude-rules: ${Object.keys(expected).length} rules written\n`);
    return 0;
}

// Run only when invoked directly: scripts/verify-docs.ts imports expectedRules.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    process.exitCode = main();
}
