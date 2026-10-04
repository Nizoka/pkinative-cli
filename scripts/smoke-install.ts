// Installs the packed tarball into an empty project, exactly as a user would,
// and runs the INSTALLED bin through npm's own shim (`npm exec pkinative`):
// --version must equal package.json, `doctor --json` must answer, a fixture
// certificate must be inspected, and the only runtime dependency installed
// must be pkinative. The tarball is what a release ships; this is the proof
// that it works. Adapted from pkinative's scripts/smoke-install.ts.
//   npm run build && npx tsx scripts/smoke-install.ts
//   npx tsx scripts/smoke-install.ts pkinative-cli-1.0.0.tgz   an existing tarball
// Exit: 0 installed and ran; 1 otherwise.

import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { npm } from './lib/npm.ts';

const ROOT = resolve(import.meta.dirname, '..');

function main(): number {
    const work = mkdtempSync(join(tmpdir(), 'pkinative-cli-smoke-'));
    try {
        let tarball = process.argv[2] === undefined ? undefined : resolve(process.argv[2]);
        if (tarball === undefined) {
            if (!existsSync(join(ROOT, 'dist', 'cli.cjs'))) {
                process.stderr.write('smoke-install: dist/ is missing — run npm run build first\n');
                return 1;
            }
            const pack = npm(['pack', '--pack-destination', work, '--ignore-scripts', '--silent'], ROOT);
            if (pack.status !== 0) {
                process.stderr.write(`smoke-install: npm pack failed\n${pack.stderr}\n`);
                return 1;
            }
            tarball = join(work, readdirSync(work).find((f) => f.endsWith('.tgz')) ?? '');
        }
        const project = join(work, 'project');
        mkdirSync(project);
        writeFileSync(join(project, 'package.json'), '{ "name": "smoke", "private": true }\n');
        const install = npm(['install', tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', '--engine-strict=false'], project);
        if (install.status !== 0) {
            process.stderr.write(`smoke-install: npm install of the tarball failed\n${install.stderr}\n`);
            return 1;
        }

        const env = { ...process.env, NO_COLOR: '1', PKINATIVE_JSON: '' };
        const run = (args: readonly string[]): { status: number | null; stdout: string; stderr: string } =>
            npm(['exec', '--offline', '--no', '--', 'pkinative', ...args], project, env);
        const failures: string[] = [];
        const version = (JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string }).version;

        const v = run(['--version']);
        if (v.stdout.trim() !== version) failures.push(`--version printed "${v.stdout.trim()}", package.json says ${version}`);

        const doctor = run(['doctor', '--json']);
        try {
            const report = JSON.parse(doctor.stdout) as { checks?: unknown[] };
            if (!Array.isArray(report.checks)) failures.push('doctor --json has no checks');
        } catch {
            failures.push(`doctor --json is not JSON:\n${doctor.stdout}${doctor.stderr}`);
        }

        const fixture = join(ROOT, 'tests', 'fixtures', 'pki', 'root.crt.pem');
        const inspect = run(['cert', 'inspect', fixture, '--json', '--fields', 'serialNumber']);
        if (inspect.status !== 0 || !inspect.stdout.includes('serialNumber')) failures.push(`cert inspect failed (exit ${String(inspect.status)}): ${inspect.stderr.trim()}`);

        const modules = readdirSync(join(project, 'node_modules')).filter((d) => !d.startsWith('.'));
        const extra = modules.filter((d) => d !== 'pkinative' && d !== 'pkinative-cli');
        if (extra.length > 0) failures.push(`runtime dependencies beyond pkinative were installed: ${extra.join(', ')}`);

        for (const f of failures) process.stderr.write(`✗ ${f}\n`);
        const name = tarball.split(/[\\/]/).pop() ?? '';
        process.stdout.write(failures.length === 0
            ? `smoke-install: ${name} installs; the installed bin answers --version ${version}, doctor and cert inspect; node_modules holds ${modules.join(' and ')}\n`
            : 'smoke-install: the packed CLI does not run\n');
        return failures.length === 0 ? 0 : 1;
    } finally {
        rmSync(work, { recursive: true, force: true });
    }
}

process.exitCode = main();
