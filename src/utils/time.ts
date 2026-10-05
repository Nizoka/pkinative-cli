import { usageError } from './error.js';

// YYYY-MM-DD, then optionally Thh:mm[:ss[.fraction]] and a zone (Z or ±hh[:]mm).
const ISO = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(\.\d{1,9})?)?(Z|([+-])(\d{2}):?(\d{2}))?)?$/i;

function daysIn(year: number, month: number): number {
    if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
    return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * The instant an ISO 8601 date or date-time names, computed from its fields —
 * never through Date.parse, whose leniency differs between engines — or
 * undefined when a field is out of range (02-31, 24:00, :60, a +25:00 zone).
 */
function fromFields(m: RegExpExecArray): number | undefined {
    const [year, month, day, hour, minute, second] = [1, 2, 3, 4, 5, 6].map((i) => Number(m[i] ?? '0')) as [number, number, number, number, number, number];
    const [zoneHours, zoneMinutes] = [Number(m[10] ?? '0'), Number(m[11] ?? '0')];
    if (month < 1 || month > 12 || day < 1 || day > daysIn(year, month) || hour > 23 || minute > 59 || second > 59 || zoneHours > 23 || zoneMinutes > 59) return undefined;
    const date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, Math.floor(Number(`0${m[7] ?? ''}`) * 1000));
    const offset = (m[9] === '-' ? -1 : 1) * (zoneHours * 60 + zoneMinutes) * 60_000;
    return date.getTime() - offset;
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
        const instant = m === null ? undefined : fromFields(m);
        if (instant !== undefined) return instant;
    }
    throw usageError(`--${flag} expects epoch milliseconds, "now" or an ISO 8601 date-time (UTC unless zoned), got "${raw}".`);
}

/** ISO 8601 rendering of an instant, for text output. */
export function formatInstant(ms: number): string {
    return new Date(ms).toISOString();
}
