// `pkinative doctor` — an offline preflight of the runtime the CLI depends on:
// the Node.js security floor, the installed pkinative, Web Crypto, the limits.

import pkg from '../../package.json' with { type: 'json' };
import { canDecrypt, canSign, canVerify } from '../core-bridge/index.js';
import type { Ctx } from '../context.js';
import { CliError, ErrorCode } from '../utils/error.js';
import { satisfies } from '../utils/engines.js';
import { effectiveLimits, LIMIT_FLAGS } from '../utils/limits.js';
import { emitReport } from '../utils/output.js';
import { CLI_VERSION, engineVersion, nodeVersion } from '../utils/version.js';
import { COMMANDS } from './registry.js';

export interface Check {
    readonly name: string;
    readonly ok: boolean;
    readonly detail: string;
}

export interface Probe {
    readonly node: string;
    readonly engine: string;
    readonly canVerify: boolean;
    readonly canSign: boolean;
    readonly canDecrypt: boolean;
}

export const NODE_RANGE: string = pkg.engines.node;
export const ENGINE_RANGE: string = pkg.dependencies.pkinative;

/** The checks for a probed runtime. Pure, so every outcome is testable on any host. */
export function runChecks(probe: Probe): Check[] {
    const nodeOk = satisfies(probe.node, NODE_RANGE);
    const engineOk = satisfies(probe.engine, ENGINE_RANGE);
    return [
        {
            name: 'node',
            ok: nodeOk,
            detail: nodeOk
                ? `Node.js ${probe.node} satisfies ${NODE_RANGE}`
                : `Node.js ${probe.node} is below the security floor ${NODE_RANGE} (CVE-2026-21713: variable-time PKCS#12 MAC comparison in Web Crypto); upgrade Node.js`,
        },
        {
            name: 'pkinative',
            ok: engineOk,
            detail: engineOk ? `pkinative ${probe.engine} satisfies ${ENGINE_RANGE}` : `pkinative ${probe.engine} does not satisfy ${ENGINE_RANGE}; reinstall pkinative-cli`,
        },
        { name: 'verify', ok: probe.canVerify, detail: probe.canVerify ? 'Web Crypto can verify signatures' : 'Web Crypto cannot verify: every signature check reports NOT_CHECKED' },
        { name: 'sign', ok: probe.canSign, detail: probe.canSign ? 'Web Crypto can sign' : 'Web Crypto cannot sign: cert create, csr create and cms sign are unavailable' },
        { name: 'decrypt', ok: probe.canDecrypt, detail: probe.canDecrypt ? 'Web Crypto can decrypt PBES2' : 'Web Crypto cannot decrypt: encrypted keys and PKCS#12 cannot be opened' },
    ];
}

export async function doctor(ctx: Ctx): Promise<void> {
    const checks = runChecks({ node: nodeVersion(), engine: engineVersion(), canVerify: canVerify(), canSign: canSign(), canDecrypt: canDecrypt() });
    const limits = effectiveLimits(ctx.opts.limits);
    const changed = LIMIT_FLAGS.filter((l) => ctx.opts.limits?.[l.key] !== undefined).map((l) => ({ limit: l.key, value: limits[l.key] }));
    const report = {
        ok: checks.every((c) => c.ok),
        cli: CLI_VERSION,
        pkinative: engineVersion(),
        node: nodeVersion(),
        platform: `${process.platform}-${process.arch}`,
        commands: COMMANDS.length,
        offline: true,
        checks,
        changedLimits: changed,
    };
    emitReport(ctx, report, () => [
        `pkinative-cli ${report.cli} (pkinative ${report.pkinative}, Node.js ${report.node}, ${report.platform})`,
        ...checks.map((c) => `  ${c.ok ? ctx.color.ok('ok  ') : ctx.color.bad('FAIL')}  ${c.name.padEnd(9)} ${c.detail}`),
        `  info  commands  ${report.commands} registered, offline: no command opens a socket`,
        ...changed.map((l) => `  info  limit     ${l.limit} = ${l.value} (raised or lowered by a --max-* flag)`),
    ].join('\n'), () => ({ ok: report.ok, failed: checks.filter((c) => !c.ok).map((c) => c.name) }));
    if (!report.ok) {
        throw new CliError(`Preflight failed: ${checks.filter((c) => !c.ok).map((c) => c.name).join(', ')}.`, 1, ErrorCode.CHECK_FAILED);
    }
}
