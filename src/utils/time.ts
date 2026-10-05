import { usageError } from './error.js';

// YYYY-MM-DD, then optionally Thh:mm[:ss[.fraction]] and a zone (Z or ±hh[:]mm).
const ISO = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?)?$/i;

/** Whether the calendar fields name an instant that exists (no 02-31, no 24:00, no :60). */
function realFields(m: RegExpExecArray): boolean {
    const [year, month, day, hour, minute, second] = [m[1], m[2], m[3], m[4] ?? '0', m[5] ?? '0', m[6] ?? '0'].map(Number) as [number, number, number, number, number, number];
    const days = new Date(Date.UTC(year, month, 0)).getUTCDate();
    return month >= 1 && month <= 12 && day >= 1 && day <= days && hour <= 23 && minute <= 59 && second <= 59;
}

/**
 * Parse `--at` and the other instants: epoch milliseconds (digits), `now`, or
 * an ISO 8601 date or date-time. A date-time without a zone is read as UTC, so
 * a verdict never depends on the host's time zone. A date that does not exist
 * (2027-02-31) is refused, never rolled over to the next month (audit A-10).
 */
export function parseInstant(raw: string, flag: string, now: () => number = Date.now): number {
    const v = raw.trim();
    if (v === 'now') return now();
    if (/^\d+$/.test(v)) {
        const n = Number(v);
        if (Number.isSafeInteger(n)) return n;
    } else {
        const m = ISO.exec(v);
        if (m !== null && realFields(m)) {
            const iso = m[4] === undefined ? `${v}T00:00:00Z` : m[8] === undefined ? `${v}Z` : v;
            return Date.parse(iso);
        }
    }
    throw usageError(`--${flag} expects epoch milliseconds, "now" or an ISO 8601 date-time (UTC unless zoned), got "${raw}".`);
}

/** ISO 8601 rendering of an instant, for text output. */
export function formatInstant(ms: number): string {
    return new Date(ms).toISOString();
}
