// `.pkinativerc.json`: default flag values, found by walking up from the
// working directory (or given with --config; disabled with --no-config).
// Precedence: explicit flag > config file > built-in default. A top-level key
// naming a command whose value is an object is a command-scoped section.
//
// SECURITY: a config file can only set presentation and convenience defaults.
// A file planted in a repository must never relax a verdict or a bound when
// someone runs `pkinative chain verify` inside it, so every flag that weakens
// a check (--allow-*, --max-*, --ber, --pem-mode), replaces files
// (--overwrite) or supplies a secret is accepted on the command line only.

import { readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import type { FlagValue, ParsedArgs } from './args.js';
import { usageError } from './error.js';

export const CONFIG_FILENAME = '.pkinativerc.json';
const CONFIG_SIZE_LIMIT = 1024 * 1024;

export function isForbiddenConfigKey(key: string): boolean {
    return key.startsWith('allow-') || key.startsWith('max-') || key.startsWith('password')
        || ['overwrite', 'ber', 'pem-mode', 'config', 'no-config'].includes(key);
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

function coerce(value: unknown): FlagValue | undefined {
    if (typeof value === 'string' || typeof value === 'boolean') return value;
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    if (Array.isArray(value) && value.every((v) => typeof v === 'string' || typeof v === 'number')) {
        return value.map(String);
    }
    return undefined;
}

function assertAllowed(key: string, path: string): void {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw usageError(`Config file ${path} contains the forbidden key "${key}".`);
    }
    if (isForbiddenConfigKey(key)) {
        throw usageError(`Config file ${path} sets "${key}", which is accepted on the command line only (it relaxes a check, replaces files or carries a secret).`);
    }
}

/**
 * Load the defaults that apply to `command`: the global section merged under
 * the command's own section (the command wins).
 */
export function loadConfig(command: string, commands: readonly string[], explicitPath: string | undefined, cwd: string): Record<string, FlagValue> {
    let path: string | undefined;
    if (explicitPath !== undefined) {
        path = resolve(cwd, explicitPath);
        if (!isFile(path)) throw usageError(`Config file not found: ${explicitPath}`);
    } else {
        path = findConfigFile(cwd);
        if (path === undefined) return {};
    }
    const raw = readFileSync(path);
    if (raw.length > CONFIG_SIZE_LIMIT) throw usageError(`Config file exceeds the 1 MiB limit: ${path}`);
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw.toString('utf8'));
    } catch {
        throw usageError(`Config file ${path} is not valid JSON.`);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw usageError(`Config file ${path} must contain a JSON object.`);
    }
    const global: Record<string, FlagValue> = {};
    const scoped: Record<string, FlagValue> = {};
    for (const [key, value] of Object.entries(parsed)) {
        if (commands.includes(key) && value !== null && typeof value === 'object' && !Array.isArray(value)) {
            for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
                assertAllowed(k, path);
                const c = coerce(v);
                if (key === command && c !== undefined) scoped[k] = c;
            }
            continue;
        }
        assertAllowed(key, path);
        const c = coerce(value);
        if (c !== undefined) global[key] = c;
    }
    return { ...global, ...scoped };
}

/** Fill the flags the user did not pass with config defaults. */
export function applyConfigDefaults(args: ParsedArgs, defaults: Readonly<Record<string, FlagValue>>): ParsedArgs {
    const merged: Record<string, FlagValue> = Object.assign(Object.create(null) as Record<string, FlagValue>, args.flags);
    for (const [key, value] of Object.entries(defaults)) {
        if (merged[key] === undefined) merged[key] = value;
    }
    return { flags: merged, positionals: args.positionals };
}
