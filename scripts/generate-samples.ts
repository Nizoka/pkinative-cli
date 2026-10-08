// Writes samples/<command>/<id>.sh and .ps1 and samples/inputs/ from the plan.
//   npx tsx scripts/generate-samples.ts

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { SAMPLES } from './lib/sample-plan.ts';
import { ROOT, ps1Script, samplePath, shScript, writeInputs } from './lib/samples.ts';

writeInputs();
for (const s of SAMPLES) {
    for (const [ext, text] of [['sh', shScript(s)], ['ps1', ps1Script(s)]] as const) {
        const path = join(ROOT, samplePath(s, ext));
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, text);
    }
}
process.stdout.write(`wrote ${SAMPLES.length * 2} sample scripts\n`);
