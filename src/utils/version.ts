import { createRequire } from 'node:module';
import pkg from '../../package.json' with { type: 'json' };

/** The CLI's own version, inlined at build time from package.json. */
export const CLI_VERSION: string = pkg.version;
export const CLI_NAME: string = pkg.name;

let cachedEngine: string | undefined;

/**
 * The installed pkinative version, read through its exports map
 * (`pkinative/package.json`) without loading the engine.
 */
export function engineVersion(resolve: (id: string) => unknown = createRequire(import.meta.url)): string {
    if (cachedEngine !== undefined) return cachedEngine;
    try {
        const engine = resolve('pkinative/package.json') as { version?: unknown };
        cachedEngine = typeof engine.version === 'string' ? engine.version : 'unknown';
    } catch {
        cachedEngine = 'unknown';
    }
    return cachedEngine;
}

/** Test hook: forget the cached engine version. */
export function resetEngineVersionCache(): void {
    cachedEngine = undefined;
}
