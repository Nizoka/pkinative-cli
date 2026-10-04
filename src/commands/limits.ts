import limitsRegistry from '../../docs/data/pkinative/limits.json' with { type: 'json' };
import { DEFAULT_PKI_LIMITS } from '../core-bridge/index.js';
import { DEFAULT_MAX_CONTENT_SIZE, type Ctx } from '../context.js';
import { effectiveLimits, LIMIT_FLAGS } from '../utils/limits.js';
import { emitReport } from '../utils/output.js';

interface LimitRow {
    readonly limit: string;
    readonly flag: string;
    readonly kind: 'bytes' | 'count';
    readonly default: number;
    readonly effective: number;
    readonly cwe: string;
    readonly guards: string;
}

/** `pkinative limits`: the 22 pkinative bounds with their flags, defaults and effective values. */
export async function limits(ctx: Ctx): Promise<void> {
    const effective = effectiveLimits(ctx.opts.limits);
    // tests/utils/limits.test.ts holds the registry to the 22 keys, so every lookup hits.
    const meta = new Map(limitsRegistry.limits.map((l) => [l.limit, l]));
    const rows: LimitRow[] = LIMIT_FLAGS.map((l) => {
        const m = meta.get(l.key) as { cwe: string; guards: string };
        return {
            limit: l.key,
            flag: `--${l.flag}`,
            kind: l.kind,
            default: DEFAULT_PKI_LIMITS[l.key],
            effective: effective[l.key],
            cwe: m.cwe,
            guards: m.guards,
        };
    });
    const report = { limits: rows, cli: { maxContentSize: ctx.opts.maxContentSize, defaultMaxContentSize: DEFAULT_MAX_CONTENT_SIZE } };
    emitReport(ctx, report, () => {
        const width = Math.max(...rows.map((r) => r.flag.length));
        const lines = rows.map((r) => {
            const changed = r.effective !== r.default ? ctx.color.warn(` (default ${r.default})`) : '';
            return `${r.flag.padEnd(width)}  ${String(r.effective).padStart(10)}${changed}  ${r.cwe}`;
        });
        return [...lines, '', `${'--max-content-size'.padEnd(width)}  ${String(ctx.opts.maxContentSize).padStart(10)}  CLI bound on content read whole`].join('\n');
    }, () => ({ changed: rows.filter((r) => r.effective !== r.default).map((r) => ({ limit: r.limit, effective: r.effective })) }));
}
