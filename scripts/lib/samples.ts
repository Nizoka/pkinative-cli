// Running the sample plan against the built CLI, and rendering its scripts.

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { SAMPLE_BINARY_INPUTS, SAMPLE_INPUTS, SAMPLES, type Sample } from './sample-plan.ts';

export const ROOT = resolve(import.meta.dirname, '..', '..');
export const BIN = join(ROOT, 'dist', 'cli.cjs');
export const FIXTURES = 'tests/fixtures/pki';
export const INPUTS = 'samples/inputs';
export const OUT = 'test-output/samples';
export const BASELINE = 'tests/regression/baselines/samples.sha256.json';

const sha256 = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');

function expand(arg: string): string {
    return arg.replace(/^\$F/, join(ROOT, FIXTURES)).replace(/^\$S/, join(ROOT, INPUTS)).replace(/^\$O/, join(ROOT, OUT));
}

/** The first element of a DER SEQUENCE (a TBS), by its length octets. */
function firstElement(der: Uint8Array): Uint8Array {
    const lengthOf = (at: number): [number, number] => {
        const first = der[at] as number;
        if (first < 0x80) return [first, 1];
        const n = first & 0x7f;
        let len = 0;
        for (let i = 1; i <= n; i++) len = len * 256 + (der[at + i] as number);
        return [len, 1 + n];
    };
    const [, outerLen] = lengthOf(1);
    const start = 1 + outerLen;
    const [innerLen, innerHeader] = lengthOf(start + 1);
    return der.subarray(start, start + 1 + innerHeader + innerLen);
}

/** Write the non-fixture inputs the samples read. */
export function writeInputs(): void {
    mkdirSync(join(ROOT, INPUTS), { recursive: true });
    for (const [name, text] of Object.entries(SAMPLE_INPUTS)) writeFileSync(join(ROOT, INPUTS, name), text + '\n');
    for (const [name, hex] of Object.entries(SAMPLE_BINARY_INPUTS)) writeFileSync(join(ROOT, INPUTS, name), Buffer.from(hex, 'hex'));
}

export interface SampleResult {
    readonly id: string;
    readonly fingerprint: string;
    readonly problem?: string;
}

/** Run every sample, in order (later samples read earlier outputs). */
export function runSamples(): SampleResult[] {
    rmSync(join(ROOT, OUT), { recursive: true, force: true });
    mkdirSync(join(ROOT, OUT), { recursive: true });
    return SAMPLES.map((s) => {
        const r = spawnSync(process.execPath, [BIN, ...s.argv.map(expand)], {
            cwd: ROOT,
            env: { ...process.env, TZ: 'UTC', NO_COLOR: '1', PKINATIVE_JSON: '', ...s.env },
            maxBuffer: 64 * 1024 * 1024,
        });
        const exit = r.status;
        const problem = exit !== s.exit ? `exit ${String(exit)}, expected ${s.exit}: ${r.stderr.toString().trim().split('\n').pop() ?? ''}` : undefined;
        let fingerprint = `exit:${String(exit)}`;
        if (s.mode === 'stdout') fingerprint = sha256(r.stdout);
        else if (s.mode !== 'exit') {
            const bytes = new Uint8Array(readFileSync(join(ROOT, OUT, s.output as string)));
            fingerprint = sha256(s.mode === 'tbs' ? firstElement(bytes) : bytes);
        }
        return { id: s.id, fingerprint, ...(problem !== undefined ? { problem } : {}) };
    });
}

const shQuote = (a: string): string => (/^[\w@%+=:,./$-]+$/.test(a) ? a.replace(/^\$([FSO])/, '"$$$1"') : `'${a.replace(/'/g, `'\\''`)}'`);
const psQuote = (a: string): string => (/^\$[FSO]/.test(a) ? `"${a}"` : /^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, "''")}'`);

export function shScript(s: Sample): string {
    const env = Object.entries(s.env ?? {}).map(([k, v]) => `${k}=${v} `).join('');
    return `#!/bin/sh
# ${s.summary}
# Run from the repository root after \`npm run build\`. Expected exit: ${s.exit}.
set -u
F=${FIXTURES} S=${INPUTS} O=${OUT}
mkdir -p "$O"
${env}\${PKINATIVE:-node dist/cli.cjs} ${s.argv.map(shQuote).join(' ')}
`;
}

export function ps1Script(s: Sample): string {
    const vars = Object.entries(s.env ?? {});
    const set = vars.map(([k, v]) => `$env:${k} = '${v}'\n`).join('');
    // A variable set for the sample is removed afterwards, so a test password
    // never stays in the caller's session.
    const unset = vars.map(([k]) => `Remove-Item Env:${k}\n`).join('');
    return `# ${s.summary}
# Run from the repository root after \`npm run build\`. Expected exit: ${s.exit}.
# $env:PKINATIVE names another pkinative (e.g. 'pkinative' when installed).
$F = '${FIXTURES}'; $S = '${INPUTS}'; $O = '${OUT}'
$Cli = if ($env:PKINATIVE) { $env:PKINATIVE -split ' ' } else { @('node', 'dist/cli.cjs') }
New-Item -ItemType Directory -Force $O | Out-Null
${set}& $Cli[0] @($Cli | Select-Object -Skip 1) ${s.argv.map(psQuote).join(' ')}
${unset}`;
}

export function samplePath(s: Sample, ext: 'sh' | 'ps1'): string {
    return `samples/${s.command}/${s.id}.${ext}`;
}
