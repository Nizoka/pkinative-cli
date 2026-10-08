import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { COMMANDS } from '../../src/commands/registry.js';
import { INVOCATIONS, REPORT_DEFS } from '../../src/generated/report-schemas.js';
import { SAMPLES } from '../../scripts/lib/sample-plan.js';
import { cli, emptyDir, envelope, FIXTURES } from '../helpers/io.js';
import { validate } from '../helpers/json-schema.js';

// The generated schemas (scripts/build-report-schemas.ts) held to what the CLI
// actually prints: every sample is run again in-process under --json (and
// under --summary where the invocation has one), and its stdout report and its
// stderr envelope must validate (audit A-09, B-04).

const INPUTS = resolve(import.meta.dirname, '..', '..', 'samples', 'inputs');
const ENVELOPE_FIELDS = new Set(['ok', 'command', 'diagnostics', 'config']);

const invocations = COMMANDS.flatMap((c) => (c.subcommands.length === 0 ? [c.name] : c.subcommands.map((s) => `${c.name} ${s.name}`)));

function invocationOf(argv: readonly string[]): string {
    const [command = '', sub] = argv;
    const spec = COMMANDS.find((c) => c.name === command);
    return spec !== undefined && spec.subcommands.length > 0 && sub !== undefined ? `${command} ${sub}` : command;
}

describe('report schemas', () => {
    it('describe every invocation of the registry, and nothing else', () => {
        expect(Object.keys(INVOCATIONS).sort()).toEqual([...invocations].sort());
        for (const [name, shape] of Object.entries(INVOCATIONS)) {
            expect(shape.outputs.length, name).toBeGreaterThan(0);
            expect(shape.outputs.includes('report'), name).toBe(shape.report !== undefined);
        }
    });

    it('validate the --json report, the --summary shape and the envelope of every sample', async () => {
        const out = emptyDir();
        const checked = new Set<string>();
        const expand = (arg: string): string => arg.replace(/^\$F/, FIXTURES).replace(/^\$S/, INPUTS).replace(/^\$O/, out);
        for (const sample of SAMPLES) {
            const argv = sample.argv.map(expand);
            const invocation = invocationOf(argv);
            const shape = INVOCATIONS[invocation];
            expect(shape, invocation).toBeDefined();
            // The full report: the sample's own --summary, --fields and --json removed.
            const plain = argv.filter((a, i) => a !== '--json' && a !== '--summary' && a !== '--fields' && argv[i - 1] !== '--fields');
            const runs: Array<['report' | 'summary', string[]]> = [['report', [...plain, '--json']]];
            if (shape?.summary !== undefined) runs.push(['summary', [...plain, '--json', '--summary']]);
            for (const [kind, args] of runs) {
                const r = await cli(args, { env: sample.env ?? {}, cwd: out });
                const env = envelope(r.stderr);
                if (env['ok'] === true) {
                    for (const [key, value] of Object.entries(env)) {
                        if (ENVELOPE_FIELDS.has(key)) continue;
                        const schema = shape?.status[key];
                        expect(schema, `${sample.id}: undeclared status field "${key}"`).toBeDefined();
                        expect(validate(value, schema as Record<string, unknown>, REPORT_DEFS), `${sample.id} status.${key}`).toEqual([]);
                    }
                }
                const text = r.stdout.trim();
                if (!shape?.outputs.includes('report') || !(text.startsWith('{') || text.startsWith('['))) continue;
                const schema = (kind === 'summary' ? shape.summary : shape.report) as Record<string, unknown>;
                expect(validate(JSON.parse(text), schema, REPORT_DEFS), `${sample.id} (${kind})`).toEqual([]);
                checked.add(invocation);
            }
        }
        // The invocations without a sample are run here, so every report schema is exercised.
        for (const argv of [['doctor', '--json'], ['explain', 'PKI_ASN1_TRUNCATED', '--json'], ['explain', '--list', '--json'], ['limits', '--json']]) {
            const r = await cli(argv);
            const shape = INVOCATIONS[invocationOf(argv)];
            expect(validate(JSON.parse(r.stdout), shape?.report as Record<string, unknown>, REPORT_DEFS), argv.join(' ')).toEqual([]);
            checked.add(invocationOf(argv));
        }
        const reporting = Object.entries(INVOCATIONS).filter(([, s]) => s.report !== undefined).map(([n]) => n);
        expect(reporting.filter((n) => !checked.has(n)), 'report invocations no run validated').toEqual([]);
        expect(join(out)).toBeTruthy();
    });

    it('catch a report that drifts from its schema', () => {
        const shape = INVOCATIONS['cert match-name'];
        expect(validate({ match: 'yes' }, shape?.report as Record<string, unknown>, REPORT_DEFS)).toEqual(['$.match: expected boolean, got string']);
        expect(validate({}, shape?.report as Record<string, unknown>, REPORT_DEFS)).toEqual(['$: missing required "match"']);
    });
});
