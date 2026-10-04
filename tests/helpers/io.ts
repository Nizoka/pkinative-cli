import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Io } from '../../src/utils/io.js';
import { run } from '../../src/cli.js';

export interface MemoryIo {
    readonly io: Io;
    stdout(): string;
    stdoutBytes(): Uint8Array;
    stderr(): string;
}

export interface MemoryIoOptions {
    readonly stdin?: string | Uint8Array | readonly (string | Uint8Array)[];
    readonly stdinTTY?: boolean;
    readonly stdoutTTY?: boolean;
    readonly env?: Record<string, string | undefined>;
    readonly cwd?: string;
}

function sink(isTTY: boolean) {
    const chunks: Uint8Array[] = [];
    return {
        stream: {
            isTTY,
            write(chunk: string | Uint8Array): boolean {
                chunks.push(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : Uint8Array.from(chunk));
                return true;
            },
        },
        bytes(): Uint8Array {
            const total = chunks.reduce((n, c) => n + c.length, 0);
            const out = new Uint8Array(total);
            let o = 0;
            for (const c of chunks) {
                out.set(c, o);
                o += c.length;
            }
            return out;
        },
    };
}

export function memoryIo(options: MemoryIoOptions = {}): MemoryIo {
    const out = sink(options.stdoutTTY ?? false);
    const err = sink(false);
    const input = options.stdin === undefined ? [] : Array.isArray(options.stdin) ? options.stdin : [options.stdin];
    const stdin = {
        isTTY: options.stdinTTY ?? false,
        async *[Symbol.asyncIterator]() {
            for (const c of input as (string | Uint8Array)[]) yield c;
        },
    };
    const io: Io = {
        stdout: out.stream,
        stderr: err.stream,
        stdin,
        env: options.env ?? {},
        cwd: options.cwd ?? emptyDir(),
    };
    return {
        io,
        stdout: () => new TextDecoder().decode(out.bytes()),
        stdoutBytes: () => out.bytes(),
        stderr: () => new TextDecoder().decode(err.bytes()),
    };
}

export interface RunResult {
    readonly code: number;
    readonly stdout: string;
    readonly stdoutBytes: Uint8Array;
    readonly stderr: string;
}

/** Run the CLI in-process against an in-memory Io. */
export async function cli(argv: readonly string[], options: MemoryIoOptions = {}): Promise<RunResult> {
    const m = memoryIo(options);
    const code = await run(argv, m.io);
    return { code, stdout: m.stdout(), stdoutBytes: m.stdoutBytes(), stderr: m.stderr() };
}

/** Parse the single JSON envelope a --json run writes to stderr. */
export function envelope(stderr: string): Record<string, unknown> {
    const lines = stderr.trim().split('\n');
    return JSON.parse(lines[lines.length - 1] as string) as Record<string, unknown>;
}

/** A fresh, empty temporary directory (no .pkinativerc.json above it is assumed). */
export function emptyDir(): string {
    return mkdtempSync(join(tmpdir(), 'pkinative-cli-'));
}

export const FIXTURES = resolve(import.meta.dirname, '..', 'fixtures', 'pki');

export function fixture(name: string): string {
    return join(FIXTURES, name);
}

export function fixtureBytes(name: string): Uint8Array {
    return new Uint8Array(readFileSync(fixture(name)));
}

/** 2027-01-01T00:00:00Z: inside the fixtures' validity window. */
export const AT = '2027-01-01T00:00:00Z';
