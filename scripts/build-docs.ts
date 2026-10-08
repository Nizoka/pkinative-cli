// Regenerates the derived documentation:
//   docs/data/errors.json                       the shipped error catalogue
//   docs/KNOWLEDGE_BASE.md §6 and §8            the error classes and the API mapping
//   npx tsx scripts/build-docs.ts [--check]

import { readFileSync, writeFileSync } from 'node:fs';
import { generatedDocs } from './lib/docs.ts';

let stale = 0;
for (const [path, text] of Object.entries(generatedDocs())) {
    const current = readFileSync(path, 'utf8');
    if (current === text) continue;
    if (process.argv.includes('--check')) {
        process.stderr.write(`${path} is stale: run npm run docs:build\n`);
        stale++;
    } else {
        writeFileSync(path, text);
        process.stdout.write(`wrote ${path}\n`);
    }
}
process.exitCode = stale > 0 ? 1 : 0;
