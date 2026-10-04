// In-flight output tracking for signal cleanup. A file the CLI is writing is
// registered while it is open; on SIGINT / SIGTERM exactly those paths are
// removed — never a finished output — and the process exits 128 + signal.

import { rmSync } from 'node:fs';

const inFlight = new Set<string>();

export function markInFlight(path: string): void {
    inFlight.add(path);
}

export function clearInFlight(path: string): void {
    inFlight.delete(path);
}

export function inFlightPaths(): readonly string[] {
    return [...inFlight];
}

/** Remove every in-flight path (best effort, synchronous: runs inside a signal handler). */
export function removeInFlight(): string[] {
    const removed: string[] = [];
    for (const p of inFlight) {
        try {
            rmSync(p, { force: true });
            removed.push(p);
        } catch {
            // best effort: the handler must still exit
        }
    }
    inFlight.clear();
    return removed;
}

export const SIGNAL_EXIT: Readonly<Record<'SIGINT' | 'SIGTERM', number>> = { SIGINT: 130, SIGTERM: 143 };
