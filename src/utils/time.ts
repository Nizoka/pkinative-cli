import { usageError } from './error.js';

/**
 * Parse `--at` and the other instants: epoch milliseconds (digits), `now`, or
 * an ISO 8601 date-time. A date-time without a zone is read as UTC, so a
 * verdict never depends on the host's time zone.
 */
export function parseInstant(raw: string, flag: string, now: () => number = Date.now): number {
    const v = raw.trim();
    if (v === 'now') return now();
    if (/^\d+$/.test(v)) {
        const n = Number(v);
        if (Number.isSafeInteger(n)) return n;
    } else if (/^\d{4}-\d{2}-\d{2}/.test(v)) {
        const zoned = /(Z|[+-]\d{2}:?\d{2})$/i.test(v) || !v.includes('T') ? v : `${v}Z`;
        const iso = v.includes('T') ? zoned : `${v}T00:00:00Z`;
        const n = Date.parse(iso);
        if (Number.isFinite(n)) return n;
    }
    throw usageError(`--${flag} expects epoch milliseconds, "now" or an ISO 8601 date-time (UTC unless zoned), got "${raw}".`);
}

/** ISO 8601 rendering of an instant, for text output. */
export function formatInstant(ms: number): string {
    return new Date(ms).toISOString();
}
