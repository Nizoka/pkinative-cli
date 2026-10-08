import { defineConfig } from 'tsup';

// One artefact: dist/cli.cjs, the `pkinative` bin. The package is a
// command-line tool with no programmatic entry point, so there is no ESM
// build, no .d.ts and no source map to ship.
export default defineConfig([
    {
        entry: { cli: 'src/bin.ts' },
        format: ['cjs'],
        dts: false,
        sourcemap: false,
        clean: true,
        splitting: false,
        treeshake: true,
        minify: false,
        target: 'es2022',
        outDir: 'dist',
        banner: { js: '#!/usr/bin/env node' },
        // pkinative MUST stay external: the CLI adopts the engine the user
        // installed, and its security fixes, instead of freezing a copy.
        // The gate's bundle-check fails if engine source is inlined.
        external: ['pkinative'],
    },
]);
