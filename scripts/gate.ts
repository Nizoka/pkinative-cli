// The single definition of what "green" means. CI, the release workflow, the
// contributor docs and the agent instructions point here instead of each
// carrying a list of commands. Ported from pdfnative-cli's scripts/gate.ts.
//
// Each step is an npm script or an inline check; its full output goes to
// test-output/.gate/<id>.log and the gate prints one line per step. On the
// first failure it prints the tail of that log and stops.
//
//   npm run gate                                    --ci (default)
//   npm run gate:fast                               typecheck:all, lint, test, verify:docs
//   npx tsx scripts/gate.ts --publish --require-all what publish.yml runs
//   npx tsx scripts/gate.ts --only smoke | --from build | --json
//
// Profiles: --fast (no build), --ci (everything but the install smoke test),
// --publish (everything). --require-all turns every SKIP into a FAIL: a runner
// without OpenSSL, or on a Node.js below the security floor, goes red instead
// of quietly skipping a check.
// Exit: 0 every step passed or skipped with a reason; 1 a step failed; 2 usage.

import { spawnSync, type SpawnSyncOptions } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { COMMANDS } from '../src/commands/registry.ts';
import { NODE_RANGE } from '../src/commands/doctor.ts';
import { satisfies } from '../src/utils/engines.ts';
import { probeBundle, REQUIRED_EXTERNALS } from './lib/bundle-probe.ts';
import { BUDGETS } from './lib/package-files.ts';
import { SAMPLES } from './lib/sample-plan.ts';

const ROOT = resolve(import.meta.dirname, '..');
const LOG_DIR = join(ROOT, 'test-output', '.gate');
const VITEST_JSON = join(LOG_DIR, 'vitest.json');
const COVERAGE_SUMMARY = join(ROOT, 'coverage', 'coverage-summary.json');
const CLI = join(ROOT, 'dist', 'cli.cjs');

export type Profile = 'fast' | 'ci' | 'publish';

export interface Step {
    readonly id: string;
    readonly npmScript?: string;
    readonly profiles: readonly Profile[];
    /** A reason to skip the step, or null to run it. */
    readonly skipWhen?: () => string | null;
    readonly env?: Readonly<Record<string, string>>;
    /** In-process check: the failure lines, empty when it passes. */
    readonly inline?: () => readonly string[];
    /** A figure shown next to PASS. */
    readonly note?: () => string | null;
}

// ── Skip conditions and notes ───────────────────────────────────────

function opensslMissing(): string | null {
    const r = spawnSync('openssl', ['version'], { encoding: 'utf8', windowsHide: true });
    return r.status === 0 ? null : 'openssl not on PATH';
}

function belowNodeFloor(): string | null {
    return satisfies(process.versions.node, NODE_RANGE) ? null : `Node.js ${process.versions.node} is below the security floor ${NODE_RANGE}`;
}

function testCount(): string | null {
    if (!existsSync(VITEST_JSON)) return null;
    const report = JSON.parse(readFileSync(VITEST_JSON, 'utf8')) as { numTotalTests?: number; numPendingTests?: number; numTotalTestSuites?: number };
    if (typeof report.numTotalTests !== 'number') return null;
    const pending = report.numPendingTests ?? 0;
    return pending > 0 ? `${report.numTotalTests} tests, ${pending} skipped` : `${report.numTotalTests} tests`;
}

function coverageFigure(): string | null {
    if (!existsSync(COVERAGE_SUMMARY)) return null;
    const total = (JSON.parse(readFileSync(COVERAGE_SUMMARY, 'utf8')) as { total?: Record<string, { pct?: number }> }).total ?? {};
    const pct = ['statements', 'branches', 'functions', 'lines'].map((k) => total[k]?.pct);
    return pct.every((p) => typeof p === 'number') ? `${pct.join('/')} % s/b/f/l` : null;
}

const joinNotes = (...parts: Array<string | null>): string | null => parts.filter((p): p is string => p !== null).join(', ') || null;

// ── Inline checks ───────────────────────────────────────────────────

function distCheck(): readonly string[] {
    if (!existsSync(CLI)) return ['dist/cli.cjs is missing'];
    const first = readFileSync(CLI, 'utf8').split('\n', 1)[0] ?? '';
    return first.startsWith('#!/usr/bin/env node') ? [] : ['dist/cli.cjs does not start with the node shebang'];
}

/** Drive the BUILT binary the way a user would: tsup flattens src/, so a path that resolves in source can fail in dist/. */
function smoke(): readonly string[] {
    if (!existsSync(CLI)) return ['dist/cli.cjs is missing (run build first)'];
    const failures: string[] = [];
    const run = (args: readonly string[]): { status: number; stdout: string; stderr: string } => {
        const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, encoding: 'utf8', windowsHide: true, env: { ...process.env, NO_COLOR: '1', PKINATIVE_JSON: '' } });
        return { status: r.status ?? 1, stdout: r.stdout, stderr: r.stderr };
    };
    const help = run(['--help']);
    if (help.status !== 0) failures.push(`--help exited ${help.status}`);
    for (const c of COMMANDS) if (!help.stdout.includes(c.name)) failures.push(`--help does not list ${c.name}`);

    const version = (JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string }).version;
    const v = run(['--version']);
    if (v.stdout.trim() !== version) failures.push(`--version printed "${v.stdout.trim()}", package.json says ${version}`);

    const doctor = run(['doctor', '--json']);
    try {
        const report = JSON.parse(doctor.stdout) as { commands?: number; checks?: Array<{ name: string; ok: boolean; detail: string }> };
        // The Node.js floor is its own step (node-floor), so a contributor on an old Node still gets a smoke verdict.
        for (const check of (report.checks ?? []).filter((c) => !c.ok && c.name !== 'node')) failures.push(`doctor: ${check.name}: ${check.detail}`);
        if (report.commands !== COMMANDS.length) failures.push(`doctor reports ${String(report.commands)} commands, the registry has ${COMMANDS.length}`);
    } catch {
        failures.push(`doctor --json is not JSON:\n${doctor.stdout}${doctor.stderr}`);
    }

    const manifest = run(['schema', 'manifest']);
    try {
        const doc = JSON.parse(manifest.stdout) as { commands?: unknown[] };
        if (doc.commands?.length !== COMMANDS.length) failures.push(`schema manifest lists ${String(doc.commands?.length)} commands, the registry has ${COMMANDS.length}`);
    } catch {
        failures.push(`schema manifest is not JSON:\n${manifest.stdout}${manifest.stderr}`);
    }

    const refused = run(['key', 'check', 'x.key', '--password', 'secret']);
    if (refused.status !== 2) failures.push(`--password on argv exited ${refused.status}, expected the usage refusal (2)`);
    return failures;
}

function bundleBudget(): readonly string[] {
    if (!existsSync(CLI)) return ['dist/cli.cjs is missing (run build first)'];
    const budget = (JSON.parse(readFileSync(join(ROOT, BUDGETS), 'utf8')) as Record<string, unknown>)['dist/cli.cjs'];
    if (typeof budget !== 'number') return [`${BUDGETS} has no budget for dist/cli.cjs`];
    const size = statSync(CLI).size;
    return size <= budget ? [] : [`dist/cli.cjs is ${size} bytes, over its ${budget}-byte budget (${BUDGETS})`];
}

function bundleSize(): string | null {
    return existsSync(CLI) ? `${(statSync(CLI).size / 1024).toFixed(0)} KiB` : null;
}

function bundleCheck(): readonly string[] {
    return existsSync(CLI) ? probeBundle(readFileSync(CLI, 'utf8')) : ['dist/cli.cjs is missing (run build first)'];
}

// ── The steps ───────────────────────────────────────────────────────

// Order matters: `build` runs before `test:coverage`, because the built-binary
// suite needs dist/ and GATE_REQUIRE_ARTIFACTS=1 makes it fail without it.
export const STEPS: readonly Step[] = [
    { id: 'typecheck:all', npmScript: 'typecheck:all', profiles: ['fast', 'ci', 'publish'] },
    { id: 'lint', npmScript: 'lint', profiles: ['fast', 'ci', 'publish'] },
    { id: 'test', npmScript: 'test', profiles: ['fast'], env: { GATE: '1' }, note: testCount },
    { id: 'build', npmScript: 'build', profiles: ['ci', 'publish'] },
    { id: 'dist-check', profiles: ['ci', 'publish'], inline: distCheck },
    { id: 'smoke', profiles: ['ci', 'publish'], inline: smoke, note: () => `${COMMANDS.length} commands` },
    { id: 'bundle-size', profiles: ['ci', 'publish'], inline: bundleBudget, note: bundleSize },
    { id: 'bundle-check', profiles: ['ci', 'publish'], inline: bundleCheck, note: () => `${REQUIRED_EXTERNALS.length} external` },
    { id: 'node-floor', profiles: ['ci', 'publish'], skipWhen: belowNodeFloor, inline: () => [], note: () => `Node.js ${process.versions.node}` },
    {
        id: 'test:coverage', npmScript: 'test:coverage', profiles: ['ci', 'publish'],
        env: { GATE: '1', GATE_REQUIRE_ARTIFACTS: '1' }, note: () => joinNotes(testCount(), coverageFigure()),
    },
    { id: 'interop', npmScript: 'test:interop', profiles: ['ci', 'publish'], skipWhen: opensslMissing, env: { REQUIRE_INTEROP: '1' } },
    { id: 'verify:docs', npmScript: 'verify:docs', profiles: ['fast', 'ci', 'publish'] },
    { id: 'verify:samples', npmScript: 'verify:samples', profiles: ['ci', 'publish'], note: () => `${SAMPLES.length} samples` },
    { id: 'check:package', npmScript: 'check:package', profiles: ['ci', 'publish'] },
    { id: 'smoke:install', npmScript: 'smoke:install', profiles: ['publish'] },
];

// ── Running ─────────────────────────────────────────────────────────

function runNpmScript(script: string, logPath: string, extraEnv: Readonly<Record<string, string>>): number {
    const env: NodeJS.ProcessEnv = { ...process.env, ...extraEnv, NO_COLOR: '1', FORCE_COLOR: '0' };
    const fd = openSync(logPath, 'w');
    try {
        const npmCli = process.env['npm_execpath'];
        const common: SpawnSyncOptions = { cwd: ROOT, env, stdio: ['ignore', fd, fd], windowsHide: true };
        const result = npmCli !== undefined && existsSync(npmCli)
            ? spawnSync(process.execPath, [npmCli, 'run', script], common)
            : spawnSync('npm', ['run', script], { ...common, shell: true });
        if (result.error) throw result.error;
        return result.status ?? 1;
    } finally {
        closeSync(fd);
    }
}

function runInline(check: () => readonly string[], logPath: string): number {
    const failures = check();
    const fd = openSync(logPath, 'w');
    try {
        writeSync(fd, failures.length === 0 ? 'ok\n' : `${failures.join('\n')}\n`);
    } finally {
        closeSync(fd);
    }
    return failures.length === 0 ? 0 : 1;
}

function tail(file: string, lines: number): string[] {
    if (!existsSync(file)) return [];
    return readFileSync(file, 'utf8').replace(/\r\n/g, '\n').trimEnd().split('\n').slice(-lines);
}

export interface Options {
    readonly profile: Profile;
    readonly only: string | null;
    readonly from: string | null;
    readonly json: boolean;
    readonly requireAll: boolean;
}

export function parseArgs(argv: readonly string[]): Options | { error: string } {
    let profile: Profile | null = null;
    let only: string | null = null;
    let from: string | null = null;
    let json = false;
    let requireAll = false;
    const ids = new Set(STEPS.map((s) => s.id));
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--fast' || a === '--ci' || a === '--publish') {
            const p = a.slice(2) as Profile;
            if (profile !== null && profile !== p) return { error: `--${profile} and ${a} are mutually exclusive` };
            profile = p;
        } else if (a === '--only' || a === '--from') {
            const id = argv[i + 1];
            if (id === undefined || id.startsWith('--')) return { error: `${a} needs a step id` };
            if (!ids.has(id)) return { error: `unknown step "${id}"` };
            if (a === '--only') only = id;
            else from = id;
            i++;
        } else if (a === '--json') {
            json = true;
        } else if (a === '--require-all') {
            requireAll = true;
        } else {
            return { error: `unknown argument "${String(a)}"` };
        }
    }
    return { profile: profile ?? 'ci', only, from, json, requireAll };
}

export function selectSteps(opts: Options): readonly Step[] {
    if (opts.only !== null) return STEPS.filter((s) => s.id === opts.only);
    let selected = STEPS.filter((s) => s.profiles.includes(opts.profile));
    if (opts.from !== null) {
        const full = STEPS.findIndex((s) => s.id === opts.from);
        selected = selected.filter((s) => STEPS.indexOf(s) >= full);
    }
    return selected;
}

interface Outcome {
    readonly id: string;
    readonly status: 'pass' | 'fail' | 'skip';
    readonly seconds: number;
    readonly note: string | null;
}

function main(): number {
    const parsed = parseArgs(process.argv.slice(2));
    if ('error' in parsed) {
        process.stderr.write(`gate: ${parsed.error}\nusage: npx tsx scripts/gate.ts [--fast | --ci | --publish] [--only <id>] [--from <id>] [--require-all] [--json]\nsteps: ${STEPS.map((s) => s.id).join(', ')}\n`);
        return 2;
    }
    const opts = parsed;
    const steps = selectSteps(opts);
    const width = Math.max(...STEPS.map((s) => s.id.length));
    const say = (line: string): void => {
        if (!opts.json) process.stdout.write(`${line}\n`);
    };
    mkdirSync(LOG_DIR, { recursive: true });
    const outcomes: Outcome[] = [];
    const startedAt = Date.now();
    say(`gate --${opts.profile}${opts.requireAll ? ' --require-all' : ''}: ${steps.length} step(s)`);

    let failedAt: string | null = null;
    for (const step of steps) {
        const reason = step.skipWhen?.() ?? null;
        if (reason !== null) {
            if (opts.requireAll) {
                const note = `required by --require-all: ${reason}`;
                outcomes.push({ id: step.id, status: 'fail', seconds: 0, note });
                say(`FAIL  ${step.id.padEnd(width)}           ${note}`);
                failedAt = step.id;
                break;
            }
            outcomes.push({ id: step.id, status: 'skip', seconds: 0, note: reason });
            say(`SKIP  ${step.id.padEnd(width)}           (${reason})`);
            continue;
        }
        const logPath = join(LOG_DIR, `${step.id.replace(/[^a-z0-9-]/gi, '-')}.log`);
        // A stale report from an earlier run must never be reported as this run's.
        if (step.env?.['GATE'] === '1') rmSync(VITEST_JSON, { force: true });
        if (step.id === 'test:coverage') rmSync(COVERAGE_SUMMARY, { force: true });
        const t0 = Date.now();
        const status = step.inline ? runInline(step.inline, logPath) : runNpmScript(step.npmScript ?? step.id, logPath, step.env ?? {});
        const seconds = (Date.now() - t0) / 1000;
        const clock = `${seconds.toFixed(1)}s`.padStart(8);
        if (status === 0) {
            const note = step.note?.() ?? null;
            outcomes.push({ id: step.id, status: 'pass', seconds, note });
            say(`PASS  ${step.id.padEnd(width)}  ${clock}${note !== null ? `  ${note}` : ''}`);
            continue;
        }
        const rel = relative(ROOT, logPath).replace(/\\/g, '/');
        outcomes.push({ id: step.id, status: 'fail', seconds, note: `exit ${status}; log: ${rel}` });
        say(`FAIL  ${step.id.padEnd(width)}  ${clock}  exit ${status}`);
        for (const line of tail(logPath, 15)) say(`      ${line}`);
        say(`      (full log: ${rel})`);
        failedAt = step.id;
        break;
    }

    const total = ((Date.now() - startedAt) / 1000).toFixed(1);
    if (opts.json) {
        process.stdout.write(`${JSON.stringify({ ok: failedAt === null, profile: opts.profile, requireAll: opts.requireAll, steps: outcomes }, null, 2)}\n`);
    } else if (failedAt !== null) {
        process.stdout.write(`gate: failed at ${failedAt}\n`);
    } else {
        const passed = outcomes.filter((o) => o.status === 'pass').length;
        const skipped = outcomes.filter((o) => o.status === 'skip').length;
        process.stdout.write(`gate: ${passed} passed, ${skipped} skipped in ${total} s\n`);
    }
    return failedAt === null ? 0 : 1;
}

// Only when run directly, so tests can import STEPS, parseArgs and selectSteps.
if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    process.exitCode = main();
}
