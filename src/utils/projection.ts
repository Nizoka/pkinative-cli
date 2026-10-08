// Token-economy projection of a JSON report: `--fields a,b.c` keeps only the
// named dot-paths (a segment landing on an array maps over its items) and
// `--summary` swaps in the command's canonical minimal shape. Pure data.

/** Split `a, b.c,,d` into trimmed, non-empty dot-paths. */
export function parseFieldList(csv: string): string[] {
    return csv.split(',').map((s) => s.trim()).filter((s) => s.length > 0);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function pick(value: unknown, segments: readonly string[]): unknown {
    if (segments.length === 0) return value;
    if (Array.isArray(value)) return value.map((el: unknown) => pick(el, segments));
    if (!isPlainObject(value)) return undefined;
    const [head, ...rest] = segments as [string, ...string[]];
    if (!Object.hasOwn(value, head)) return undefined;
    const picked = pick(value[head], rest);
    return picked === undefined ? undefined : { [head]: picked };
}

function deepMerge(a: unknown, b: unknown): unknown {
    if (b === undefined) return a;
    if (Array.isArray(a) && Array.isArray(b)) {
        return Array.from({ length: Math.max(a.length, b.length) }, (_, i) => deepMerge(a[i], b[i]));
    }
    if (isPlainObject(a) && isPlainObject(b)) {
        const out: Record<string, unknown> = { ...a };
        for (const [k, v] of Object.entries(b)) out[k] = Object.hasOwn(out, k) ? deepMerge(out[k], v) : v;
        return out;
    }
    return b;
}

/**
 * Keep only the requested dot-paths. Unknown paths are omitted silently, so
 * an agent asking for a conditionally absent field never crashes the CLI.
 */
export function selectFields(value: unknown, paths: readonly string[]): unknown {
    let result: unknown;
    for (const path of paths) {
        const segments = path.split('.').map((s) => s.trim()).filter((s) => s.length > 0);
        if (segments.length === 0) continue;
        result = deepMerge(result, pick(value, segments));
    }
    return result ?? {};
}

/** Compact JSON for agents, two-space indentation for humans. */
export function serializeJson(value: unknown, pretty: boolean): string {
    return JSON.stringify(value, null, pretty ? 2 : 0);
}
