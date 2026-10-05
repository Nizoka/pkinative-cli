// `.pkinativerc.json`: default flag values, found by walking up from the
// working directory (or given with --config; disabled with --no-config).
// Precedence: explicit flag > config file > built-in default. A top-level key
// naming a command ("cert") or a subcommand ("cert inspect") whose value is an
// object is a scoped section; the most specific section wins.
//
// SECURITY (ADR 0007): a configuration file is presentation only. A file
// planted in a cloned repository must never change what a command reads,
// when it judges, what it trusts or where it writes, so only the keys of
// CONFIG_KEYS are accepted — every other key, present or future, is refused.
// A key is applied only where the invoked subcommand declares the flag, and
// the file that supplied defaults is named in the envelope.

import { closeSync, fstatSync, openSync, readSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { FlagValue, ParsedArgs } from './args.js';
import { usageError } from './error.js';

export const CONFIG_FILENAME = '.pkinativerc.json';
const CONFIG_SIZE_LIMIT = 1024 * 1024;

/** The only keys a configuration file may set: how a result is shown, never what is judged. */
export const CONFIG_KEYS: readonly string[] = ['json', 'pretty', 'quiet', 'no-color', 'format', 'encoding', 'fields', 'summary', 'strict'];

export function isConfigKey(key: string): boolean {
    return CONFIG_KEYS.includes(key);
}

function isFile(path: string): boolean {
    try {
        return statSync(path).isFile();
    } catch {
        return false;
    }
}

function findConfigFile(startDir: string): string | undefined {
    let dir = resolve(startDir);
    for (;;) {
        const candidate = join(dir, CONFIG_FILENAME);
        if (isFile(candidate)) return candidate;
        const parent = dirname(dir);
        if (parent === dir) return undefined;
        dir = parent;
    }
}

/**
 * The file's bytes, bounded before anything is read. The path already passed
 * `isFile` (a device or a FIFO never does), and the descriptor's own size is
 * the one checked, so the read is a single call of at most 1 MiB.
 */
function readBounded(path: string): Buffer {
    const fd = openSync(path, 'r');
    try {
        const size = fstatSync(fd).size;
        if (size > CONFIG_SIZE_LIMIT) throw usageError(`Config file exceeds the 1 MiB limit: ${path}`);
        const buf = Buffer.alloc(size);
        return buf.subarray(0, readSync(fd, buf, 0, size, 0));
    } finally {
        closeSync(fd);
    }
}

/** A presentation key takes one value: a string, a boolean or a finite number. */
function coerce(value: unknown): FlagValue | undefined {
    if (typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    return undefined;
}

function assertAllowed(key: string, path: string): void {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw usageError(`Config file ${path} contains the forbidden key "${key}".`);
    }
    if (!isConfigKey(key)) {
        throw usageError(`Config file ${path} sets "${key}", which is accepted on the command line only: a configuration file sets presentation defaults (${CONFIG_KEYS.join(', ')}), never inputs, trust, time, bounds or outputs.`);
    }
}

export interface LoadedConfig {
    /** The file read, when one was found. */
    readonly path?: string;
    /** Every allowed key it sets for this invocation, before the flag filter. */
    readonly defaults: Readonly<Record<string, FlagValue>>;
}

/**
 * Load the defaults that apply to `command` (and `sub`): the global section,
 * then the command's section, then the subcommand's section — each winning
 * over the previous. Every key of every section is checked, applicable or not.
 */
export function loadConfig(command: string, sub: string | undefined, commands: readonly string[], explicitPath: string | undefined, cwd: string): LoadedConfig {
    let path: string | undefined;
    if (explicitPath !== undefined) {
        path = resolve(cwd, explicitPath);
        if (!isFile(path)) throw usageError(`Config file not found: ${explicitPath}`);
    } else {
        path = findConfigFile(cwd);
        if (path === undefined) return { defaults: {} };
    }
    const raw = readBounded(path);
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw.toString('utf8'));
    } catch {
        throw usageError(`Config file ${path} is not valid JSON.`);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw usageError(`Config file ${path} must contain a JSON object.`);
    }
    const isSection = (key: string): boolean => {
        const [head = '', ...tail] = key.split(' ');
        return commands.includes(head) && tail.length <= 1;
    };
    const layers: [Record<string, FlagValue>, Record<string, FlagValue>, Record<string, FlagValue>] = [{}, {}, {}];
    for (const [key, value] of Object.entries(parsed)) {
        if (isSection(key) && value !== null && typeof value === 'object' && !Array.isArray(value)) {
            const layer = key === command ? layers[1] : sub !== undefined && key === `${command} ${sub}` ? layers[2] : undefined;
            for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
                assertAllowed(k, path);
                const c = coerce(v);
                if (layer !== undefined && c !== undefined) layer[k] = c;
            }
            continue;
        }
        assertAllowed(key, path);
        const c = coerce(value);
        if (c !== undefined) layers[0][key] = c;
    }
    return { path, defaults: { ...layers[0], ...layers[1], ...layers[2] } };
}

/**
 * Fill the flags the user did not pass with the config defaults the invoked
 * subcommand declares (`known`); a key it does not declare is ignored, so a
 * default for `cert inspect --format` never breaks `cert create`.
 */
export function applyConfigDefaults(args: ParsedArgs, defaults: Readonly<Record<string, FlagValue>>, known: ReadonlySet<string>): { args: ParsedArgs; applied: readonly string[] } {
    const merged: Record<string, FlagValue> = Object.assign(Object.create(null) as Record<string, FlagValue>, args.flags);
    const applied: string[] = [];
    for (const [key, value] of Object.entries(defaults)) {
        if (!known.has(key) || merged[key] !== undefined) continue;
        merged[key] = value;
        applied.push(key);
    }
    return { args: { flags: merged, positionals: args.positionals }, applied };
}
