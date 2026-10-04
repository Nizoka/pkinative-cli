// `pkinative explain <code>` — every code the CLI can show, explained offline:
// pkinative's 57 PKI_* errors, 43 PKI_REASON_* reasons and 97 PKI_DIAG_*
// diagnostics (the registries of the pinned v1.0.0 tag, vendored under
// docs/data/pkinative/), and the CLI's own E_* classes.

import diagnosticsRegistry from '../../docs/data/pkinative/diagnostics.json' with { type: 'json' };
import errorsRegistry from '../../docs/data/pkinative/errors.json' with { type: 'json' };
import reasonsRegistry from '../../docs/data/pkinative/reasons.json' with { type: 'json' };
import type { Ctx } from '../context.js';
import { getChoiceFlag, hasFlag } from '../utils/args.js';
import { CliError, ERROR_CODES, ErrorCode, usageError, type ErrorCodeValue } from '../utils/error.js';
import { emitReport } from '../utils/output.js';
import { PKI_REMEDY, PKI_TO_CLI } from '../utils/pkierr.js';

/** What each CLI class means, for `explain E_*` and the manifest. */
export const CLI_CODE_MEANING: Readonly<Record<ErrorCodeValue, string>> = {
    [ErrorCode.USAGE]: 'A flag, argument or option value is missing or invalid (exit 2).',
    [ErrorCode.INPUT]: 'A value you supplied is not acceptable: a spec document, a label, a range, a key that does not match.',
    [ErrorCode.PARSE]: 'The bytes are not the DER, PEM or JSON structure they claim to be.',
    [ErrorCode.IO]: 'A filesystem or stream failure, including a refused overwrite.',
    [ErrorCode.SECURITY]: 'A security policy refused the input: SHA-1 without --allow-sha1, PBES1, a legacy PKCS#12 MAC.',
    [ErrorCode.LIMIT]: 'A named bound was exceeded: one of the 22 pkinative limits, or --max-content-size.',
    [ErrorCode.UNSUPPORTED]: 'The runtime or pkinative does not support the algorithm, key or structure.',
    [ErrorCode.CRYPTO]: 'Web Crypto could not run the operation the input requires.',
    [ErrorCode.PASSWORD]: 'A password is wrong, or a MAC does not match it.',
    [ErrorCode.NOT_FOUND]: 'A named item does not exist: an extension, a PEM block, a signer, a code.',
    [ErrorCode.VERIFY_FAILED]: 'A signature, chain, request, time-stamp or MAC verdict is negative; the report says why.',
    [ErrorCode.CHECK_FAILED]: 'A check returned reasons (revocation, OCSP, name, purpose) or --strict escalated a warning.',
    [ErrorCode.RUNTIME]: 'Anything else (exit 1); PKINATIVE_DEBUG=1 prints the stack.',
};

export type ExplainKind = 'error' | 'reason' | 'diagnostic' | 'cli';

export interface Explanation {
    readonly code: string;
    readonly kind: ExplainKind;
    readonly [key: string]: unknown;
}

/** Every explainable code with its entry, in registry order. */
export function catalogue(): Explanation[] {
    return [
        ...ERROR_CODES.map((code) => ({
            code,
            kind: 'cli' as const,
            meaning: CLI_CODE_MEANING[code],
            pkiCodes: Object.entries(PKI_TO_CLI).filter(([, [cli]]) => cli === code).map(([pki]) => pki),
        })),
        ...errorsRegistry.errors.map((e) => {
            const [cliCode, exitCode] = PKI_TO_CLI[e.code as keyof typeof PKI_TO_CLI];
            const cliRemedy = (PKI_REMEDY as Readonly<Record<string, string>>)[e.code];
            return { ...e, kind: 'error' as const, cliCode, exitCode, ...(cliRemedy !== undefined ? { cliRemedy } : {}) };
        }),
        ...reasonsRegistry.reasons.map((r) => ({ ...r, kind: 'reason' as const })),
        ...diagnosticsRegistry.diagnostics.map((d) => ({ ...d, kind: 'diagnostic' as const })),
    ];
}

function render(e: Explanation): string {
    return Object.entries(e).filter(([k]) => k !== 'code').map(([k, v]) => `  ${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`).join('\n');
}

export async function explain(ctx: Ctx): Promise<void> {
    const all = catalogue();
    if (hasFlag(ctx.args.flags, 'list')) {
        const kind = getChoiceFlag(ctx.args.flags, 'kind', ['error', 'reason', 'diagnostic', 'cli'] as const);
        const rows = kind === undefined ? all : all.filter((e) => e.kind === kind);
        ctx.status['count'] = rows.length;
        emitReport(ctx, { codes: rows }, () => rows.map((e) => `${e.code.padEnd(44)} ${e.kind}`).join('\n'), () => ({ codes: rows.map((e) => e.code) }));
        return;
    }
    const [code, ...extra] = ctx.args.positionals;
    if (code === undefined || extra.length > 0) throw usageError('explain takes one code, e.g. pkinative explain PKI_ASN1_TRUNCATED, or --list.');
    const entry = all.find((e) => e.code === code.toUpperCase());
    if (entry === undefined) throw new CliError(`Unknown code "${code}": run pkinative explain --list.`, 1, ErrorCode.NOT_FOUND);
    emitReport(ctx, entry, () => `${entry.code}\n${render(entry)}`);
}
