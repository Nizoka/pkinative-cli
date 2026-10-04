import type { Io, OutStream } from './io.js';

/** ANSI colour on a stream: a TTY, NO_COLOR unset, TERM not dumb; FORCE_COLOR forces it. */
export function colorEnabled(io: Io, stream: OutStream, disabledByFlag: boolean): boolean {
    if (disabledByFlag || io.env['NO_COLOR'] !== undefined) return false;
    const force = io.env['FORCE_COLOR'];
    if (force !== undefined && force !== '0') return true;
    if (io.env['TERM'] === 'dumb') return false;
    return stream.isTTY === true;
}

export interface Palette {
    readonly ok: (s: string) => string;
    readonly bad: (s: string) => string;
    readonly warn: (s: string) => string;
    readonly dim: (s: string) => string;
}

const plain = (s: string): string => s;
const wrap = (code: number) => (s: string): string => `\u001b[${code}m${s}\u001b[0m`;

export function palette(enabled: boolean): Palette {
    return enabled
        ? { ok: wrap(32), bad: wrap(31), warn: wrap(33), dim: wrap(2) }
        : { ok: plain, bad: plain, warn: plain, dim: plain };
}
