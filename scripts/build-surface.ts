// Writes docs/data/core-exports.json, the surface matrix (scripts/lib/surface.ts).
//   npx tsx scripts/build-surface.ts            write the file
//   npx tsx scripts/build-surface.ts --check    exit 1 when the committed file is stale

import { readFileSync, writeFileSync } from 'node:fs';
import { surfaceDocument } from './lib/surface.ts';

const PATH = 'docs/data/core-exports.json';
const text = JSON.stringify(surfaceDocument(), null, 2) + '\n';

if (process.argv.includes('--check')) {
    const committed = readFileSync(PATH, 'utf8');
    if (committed !== text) {
        process.stderr.write(`${PATH} is stale: run npx tsx scripts/build-surface.ts\n`);
        process.exit(1);
    }
    process.stdout.write(`${PATH} is current\n`);
} else {
    writeFileSync(PATH, text);
    process.stdout.write(`wrote ${PATH}\n`);
}
