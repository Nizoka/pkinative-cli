// Running npm from a script: the npm that started us when there is one (one
// toolchain for the whole gate), else the `npm` on PATH, through a shell on
// Windows where it is an `npm.cmd` shim Node refuses to spawn directly.

import { spawnSync, type SpawnSyncReturns } from 'node:child_process';

export function npm(args: readonly string[], cwd: string, env?: NodeJS.ProcessEnv): SpawnSyncReturns<string> {
    const cli = process.env['npm_execpath'];
    const options = { cwd, encoding: 'utf8' as const, windowsHide: true, maxBuffer: 64 * 1024 * 1024, ...(env !== undefined ? { env } : {}) };
    return cli !== undefined && cli.endsWith('.js')
        ? spawnSync(process.execPath, [cli, ...args], options)
        : spawnSync('npm', [...args], { ...options, shell: process.platform === 'win32' });
}
