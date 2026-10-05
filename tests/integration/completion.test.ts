// The generated completion scripts, run by the shells themselves (audit B-11):
// bash where it is the system shell, PowerShell wherever pwsh is installed.
// Each case is skipped when its shell is absent; CI runs Linux, macOS and
// Windows, which between them carry both.

import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { cli, emptyDir } from '../helpers/io.js';

const has = (cmd: string, args: string[]): boolean => spawnSync(cmd, args, { encoding: 'utf8', windowsHide: true }).status === 0;
const BASH = process.platform !== 'win32' && has('bash', ['-c', 'true']);
const PWSH = has('pwsh', ['-NoProfile', '-Command', '$true']);

/** The cases audit B-11 found broken, and the value completion of G-09. */
const CASES: ReadonlyArray<{ line: string; expect: readonly string[]; not?: readonly string[] }> = [
    { line: 'pkinative ', expect: ['cert', 'chain', 'schema'] },
    { line: 'pkinative cert ', expect: ['inspect', 'create', 'check-name'], not: ['chain'] },
    { line: 'pkinative --json cert ', expect: ['inspect', 'verify-signature'], not: ['chain'] },
    { line: 'pkinative --config x.json cert ', expect: ['inspect'], not: ['chain'] },
    { line: 'pkinative cert inspect --', expect: ['--extension', '--raw-extensions', '--json'] },
    { line: 'pkinative cert inspect --format ', expect: ['text', 'json'] },
    { line: 'pkinative fingerprint --alg ', expect: ['SHA-256', 'SHA-1'] },
    // An alias is its flag, a path flag completes files, and completion completes shells (audit A2-14).
    { line: 'pkinative cert inspect -f ', expect: ['text', 'json'] },
    { line: 'pkinative cert inspect -i ', expect: [], not: ['--json', '--extension', 'text'] },
    { line: 'pkinative cert inspect --input ', expect: [], not: ['--json', '--extension'] },
    { line: 'pkinative completion ', expect: ['bash', 'zsh', 'fish', 'powershell'], not: ['--json'] },
];

async function script(shell: string): Promise<string> {
    const dir = emptyDir();
    const path = join(dir, `pkinative.${shell === 'powershell' ? 'ps1' : 'sh'}`);
    writeFileSync(path, (await cli(['completion', shell])).stdout);
    return path;
}

describe.skipIf(!BASH)('bash completion', () => {
    it('completes commands, subcommands after global flags, flags and enumerated values', async () => {
        const path = await script('bash');
        for (const c of CASES) {
            const words = c.line.split(' ');
            const program = `source '${path}'; COMP_WORDS=(${words.map((w) => `'${w}'`).join(' ')}); COMP_CWORD=${words.length - 1}; _pkinative; printf '%s\\n' "\${COMPREPLY[@]}"`;
            const out = spawnSync('bash', ['-c', program], { encoding: 'utf8' }).stdout.split('\n');
            expect(out, c.line).toEqual(expect.arrayContaining([...c.expect]));
            for (const n of c.not ?? []) expect(out, c.line).not.toContain(n);
        }
    }, 120_000);
});

describe.skipIf(!PWSH)('PowerShell completion', () => {
    it('completes commands, subcommands after global flags, flags and enumerated values', async () => {
        const path = await script('powershell');
        // One pwsh process for every case: its start-up dominates the run.
        const program = [`. '${path}'`, ...CASES.map((c) => `'#CASE'; (TabExpansion2 -inputScript '${c.line}' -cursorColumn ${c.line.length}).CompletionMatches | ForEach-Object { $_.CompletionText }`)].join('; ');
        const blocks = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', program], { encoding: 'utf8', windowsHide: true }).stdout.split('#CASE').slice(1);
        expect(blocks).toHaveLength(CASES.length);
        CASES.forEach((c, i) => {
            const out = (blocks[i] ?? '').split(/\r?\n/);
            expect(out, c.line).toEqual(expect.arrayContaining([...c.expect]));
            for (const n of c.not ?? []) expect(out, c.line).not.toContain(n);
        });
    }, 120_000);
});
