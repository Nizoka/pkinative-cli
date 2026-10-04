// Runs every sample against the BUILT CLI and holds each output to its pinned
// fingerprint (tests/regression/baselines/samples.sha256.json).
//   npx tsx scripts/verify-samples.ts             verify (exit 1 on a drift)
//   npx tsx scripts/verify-samples.ts --update    re-pin; say why in the release note

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { BASELINE, BIN, ROOT, runSamples, writeInputs } from './lib/samples.ts';

if (!existsSync(BIN)) {
    process.stderr.write('dist/cli.cjs is missing: run npm run build first.\n');
    process.exit(2);
}
writeInputs();
const results = runSamples();
const failures = results.filter((r) => r.problem !== undefined);
for (const f of failures) process.stderr.write(`FAIL ${f.id}: ${f.problem as string}\n`);

const path = join(ROOT, BASELINE);
const current = Object.fromEntries(results.map((r) => [r.id, r.fingerprint]));
if (process.argv.includes('--update')) {
    if (failures.length > 0) process.exit(1);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ $comment: 'Fingerprints of the samples run by scripts/verify-samples.ts against the built CLI.', samples: current }, null, 2) + '\n');
    process.stdout.write(`pinned ${results.length} samples\n`);
    process.exit(0);
}
const pinned = (JSON.parse(readFileSync(path, 'utf8')) as { samples: Record<string, string> }).samples;
const drift = [...new Set([...Object.keys(pinned), ...Object.keys(current)])].filter((id) => pinned[id] !== current[id]);
for (const id of drift) process.stderr.write(`DRIFT ${id}: pinned ${pinned[id] ?? '(none)'}, now ${current[id] ?? '(none)'}\n`);
if (failures.length > 0 || drift.length > 0) process.exit(1);
process.stdout.write(`${results.length} samples match their baseline\n`);
