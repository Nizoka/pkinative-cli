// The CLI's only door to the outside world. stdout carries the artefact (a
// DER or PEM object, or the JSON report), stderr every diagnostic and the
// agent envelopes. Commands never touch `process` directly: they receive an
// `Io`, which tests replace with an in-memory one.

import { randomBytes } from 'node:crypto';
import { lstat, open, rename, rm, type FileHandle } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { CliError, ErrorCode, usageError } from './error.js';
import { clearInFlight, markInFlight } from './inflight.js';
import { mapPkiError } from './pkierr.js';

export interface OutStream {
    write(chunk: string | Uint8Array): unknown;
    readonly isTTY?: boolean | undefined;
}

export interface InStream extends AsyncIterable<string | Uint8Array> {
    readonly isTTY?: boolean | undefined;
}

export interface Io {
    readonly stdout: OutStream;
    readonly stderr: OutStream;
    readonly stdin: InStream;
    readonly env: Readonly<Record<string, string | undefined>>;
    readonly cwd: string;
}

/** The real process streams. */
export function processIo(): Io {
    return { stdout: process.stdout, stderr: process.stderr, stdin: process.stdin, env: process.env, cwd: process.cwd() };
}

function tooLarge(what: string, observed: number, configured: number, flag: string | undefined): CliError {
    if (flag === undefined) {
        // A fixed cap, not a bound a flag lifts: there is no remedy to offer.
        return new CliError(`${what} exceeds its ${configured}-byte cap (observed at least ${observed}).`, 1, ErrorCode.LIMIT, { detail: { limit: 'fixed', configured, observed } });
    }
    return new CliError(
        `${what} exceeds --${flag} (${configured} bytes; observed at least ${observed}). Raise the bound only for trusted input.`,
        1,
        ErrorCode.LIMIT,
        { detail: { limit: flag.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase()), flag: `--${flag}`, configured, observed }, remedy: `--${flag} <size> (trusted input only)` },
    );
}

export interface ReadOptions {
    /** Human name of the input, for messages ("certificate", "content"). */
    readonly what: string;
    /** Upper bound in bytes; checked by stat before a file is read. */
    readonly maxBytes: number;
    /** The flag that raises `maxBytes`, for the remedy; absent for a fixed cap. */
    readonly limitFlag?: string;
}

/**
 * Read a whole input: a file path, or stdin when the path is `-` or absent.
 * An interactive terminal on stdin with no explicit `-` is a usage error
 * rather than a silent hang.
 */
export async function readInput(io: Io, path: string | undefined, options: ReadOptions): Promise<Uint8Array> {
    if (path === undefined || path === '-') {
        if (path === undefined && io.stdin.isTTY === true) {
            throw usageError(`No ${options.what} given: pass a file path, or pipe it on stdin.`);
        }
        return readStream(io.stdin, options);
    }
    try {
        return await readRegularFile(path, options);
    } catch (e) {
        throw mapPkiError(e, `Cannot read ${options.what} "${path}"`);
    }
}

/**
 * A path is read only when it names a regular file, through one descriptor
 * whose own size is checked before the read and bounds it: a FIFO, a device
 * (/dev/zero) or a file that grows between the check and the read is never
 * read past the cap (audit A-13).
 */
async function readRegularFile(path: string, options: ReadOptions): Promise<Uint8Array> {
    const handle = await open(path, 'r');
    try {
        const st = await handle.stat();
        if (st.isDirectory()) throw new CliError(`Cannot read ${options.what} "${path}": it is a directory.`, 1, ErrorCode.IO);
        if (!st.isFile()) {
            throw new CliError(`Cannot read ${options.what} "${path}": it is not a regular file (a device, a FIFO or a socket); pipe it on stdin instead.`, 1, ErrorCode.INPUT);
        }
        if (st.size > options.maxBytes) throw tooLarge(`${options.what} "${path}"`, st.size, options.maxBytes, options.limitFlag);
        const buf = new Uint8Array(st.size);
        const { bytesRead } = await handle.read(buf, 0, st.size, 0);
        return buf.subarray(0, bytesRead);
    } finally {
        await handle.close();
    }
}

async function readStream(stream: InStream, options: ReadOptions): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of stream) {
        const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk;
        total += bytes.length;
        if (total > options.maxBytes) throw tooLarge(`${options.what} on stdin`, total, options.maxBytes, options.limitFlag);
        chunks.push(bytes);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
        out.set(c, offset);
        offset += c.length;
    }
    return out;
}

/** The uniform refusal for an existing output file. */
export function overwriteRefused(path: string): CliError {
    return new CliError(`Refusing to overwrite existing file ${path} (pass --overwrite).`, 1, ErrorCode.IO, { remedy: '--overwrite' });
}

export interface WriteOptions {
    /** Replace an existing file, atomically (temp file + rename). */
    readonly overwrite: boolean;
}

/**
 * Write an artefact to a file, or to stdout when the path is `-` or absent.
 *
 * Without --overwrite the file is opened exclusively (`wx`): an existing file,
 * a dangling symlink, or one that appears between any check and the open is
 * refused, with no check-then-write window. With --overwrite the bytes go to
 * a temp file in the same directory, then rename() replaces the target in one
 * step, so a reader never sees a half-written file and a symlink at the target
 * is replaced, not followed. A write interrupted by a signal is removed.
 */
export async function writeOutput(io: Io, path: string | undefined, data: string | Uint8Array, options: WriteOptions): Promise<void> {
    if (path === undefined || path === '-') {
        io.stdout.write(data);
        return;
    }
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    if (options.overwrite) {
        const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
        await writeExclusive(tmp, bytes, path);
        try {
            await rename(tmp, path);
        } catch (e) {
            await rm(tmp, { force: true });
            throw mapPkiError(e, `Cannot write "${path}"`);
        }
        return;
    }
    await writeExclusive(path, bytes, path);
}

async function lexists(path: string): Promise<boolean> {
    try {
        await lstat(path);
        return true;
    } catch {
        return false;
    }
}

async function writeExclusive(path: string, bytes: Uint8Array, shown: string): Promise<void> {
    // O_EXCL refuses an existing path, dangling symlinks included, on POSIX;
    // Windows' CREATE_NEW follows a dangling symlink and creates its target.
    // lstat first closes that hole; O_EXCL still closes the race on POSIX.
    if (await lexists(path)) throw overwriteRefused(shown);
    let handle: FileHandle;
    try {
        handle = await open(path, 'wx');
    } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw overwriteRefused(shown);
        throw mapPkiError(e, `Cannot write "${shown}"`);
    }
    markInFlight(path);
    try {
        await handle.writeFile(bytes);
        await handle.close();
    } catch (e) {
        await handle.close().catch(() => undefined);
        await rm(path, { force: true });
        throw mapPkiError(e, `Cannot write "${shown}"`);
    } finally {
        clearInFlight(path);
    }
}
