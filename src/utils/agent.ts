// The machine contract an autonomous caller drives the CLI through.
//   stdout  the artefact or the report — nothing else, ever.
//   stderr  diagnostics, and under --json exactly one envelope:
//           { ok: true,  command, diagnostics, ...status }            on success
//           { ok: false, command, error: { code, message, pkiCode?,
//             detail?, remedy?, reasons? }, diagnostics }             on failure
//   exit    0 success, 1 failure, 2 usage error, 130/143 interrupted.

import type { PkiDiagnostic } from '../core-bridge/index.js';
import { CliError, ErrorCode, type ErrorCodeValue } from './error.js';
import { remedyFor } from './pkierr.js';
import { toWire, type Wire } from './wire.js';

export interface ErrorEnvelope {
    readonly ok: false;
    readonly command: string | null;
    readonly error: {
        readonly code: ErrorCodeValue;
        readonly message: string;
        readonly pkiCode?: string;
        readonly detail?: Wire;
        readonly remedy?: string;
        readonly reasons?: Wire;
    };
    readonly diagnostics: Wire;
    /** The configuration file that supplied defaults to this invocation (ADR 0007). */
    readonly config?: string;
}

export function buildErrorEnvelope(command: string | null, err: unknown, diagnostics: readonly PkiDiagnostic[], configPath?: string): ErrorEnvelope {
    const diags = toWire(diagnostics);
    const config = configPath !== undefined ? { config: configPath } : {};
    if (err instanceof CliError) {
        const remedy = remedyFor(err);
        return {
            ok: false,
            command,
            error: {
                code: err.code,
                message: err.message,
                ...(err.pkiCode !== undefined ? { pkiCode: err.pkiCode } : {}),
                ...(err.detail !== undefined ? { detail: toWire(err.detail) } : {}),
                ...(remedy !== undefined ? { remedy } : {}),
                ...(err.reasons !== undefined ? { reasons: toWire(err.reasons) } : {}),
            },
            diagnostics: diags,
            ...config,
        };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, command, error: { code: ErrorCode.RUNTIME, message }, diagnostics: diags, ...config };
}

export function buildStatusEnvelope(command: string, status: Readonly<Record<string, unknown>>, diagnostics: readonly PkiDiagnostic[]): Wire {
    return toWire({ ok: true, command, ...status, diagnostics });
}

/** One human line per diagnostic: `warning PKI_DIAG_X at path: message (standard)`. */
export function formatDiagnostic(d: PkiDiagnostic): string {
    const where = d.path !== '' ? ` at ${d.path}` : '';
    return `${d.severity} ${d.code}${where}: ${d.message} (${d.standard})`;
}
