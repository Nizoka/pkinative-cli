import { defineConfig } from 'vitest/config';

const reporters: Array<'dot' | 'github-actions' | ['json', { outputFile: string }]> = ['dot'];
if (process.env['GITHUB_ACTIONS']) reporters.push('github-actions');
if (process.env['GATE'] === '1') reporters.push(['json', { outputFile: 'test-output/.gate/vitest.json' }]);

export default defineConfig({
    test: {
        include: ['tests/**/*.test.ts'],
        environment: 'node',
        globals: false,
        reporters,
        // Certificate validity is UTC by definition (RFC 5280 §4.1.2.5).
        env: { TZ: 'UTC' },
        pool: 'forks',
        sequence: { shuffle: false },
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            // src/bin.ts is the process wrapper around run(); the built-binary
            // tests exercise it, and v8 cannot instrument a child process.
            exclude: ['src/bin.ts'],
            reporter: ['text-summary', 'json-summary', 'html'],
            thresholds: {
                // 100 % on all four axes, never lowered: a branch no input can
                // reach is removed by construction, not excused.
                statements: 100,
                branches: 100,
                functions: 100,
                lines: 100,
            },
        },
    },
});
