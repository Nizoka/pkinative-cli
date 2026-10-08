import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                // tsconfig.test.json includes src/ AND tests/, so one project covers everything linted.
                project: ['./tsconfig.test.json'],
                tsconfigRootDir: import.meta.dirname,
            },
        },
        rules: {
            '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
            '@typescript-eslint/no-explicit-any': 'error',
            '@typescript-eslint/no-non-null-assertion': 'error',
            '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports', fixStyle: 'inline-type-imports' }],
            'eqeqeq': ['error', 'always'],
            'no-throw-literal': 'error',
            'no-shadow': 'off',
            '@typescript-eslint/no-shadow': 'error',
            'no-var': 'error',
            'prefer-const': 'error',
            'no-eval': 'error',
            'no-implied-eval': 'error',
            'no-new-func': 'error',
            // Every byte leaves through src/utils/io.ts: stdout carries the
            // artefact, stderr the diagnostics. A stray console call would mix them.
            'no-console': 'error',
            // The engine enters through one door (src/core-bridge/index.ts),
            // so the surface matrix can prove which exports the CLI reaches.
            'no-restricted-imports': ['error', {
                paths: [{ name: 'pkinative', message: 'Import pkinative symbols from src/core-bridge/index.ts only.' }],
            }],
            '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true, allowBoolean: true }],
            '@typescript-eslint/no-confusing-void-expression': ['error', { ignoreArrowShorthand: true }],
            // Every command handler is async by contract, whether or not it awaits.
            '@typescript-eslint/require-await': 'off',
        },
    },
    {
        files: ['src/core-bridge/index.ts'],
        rules: { 'no-restricted-imports': 'off' },
    },
    {
        files: ['tests/**/*.ts'],
        extends: [tseslint.configs.disableTypeChecked],
        rules: {
            '@typescript-eslint/no-non-null-assertion': 'off',
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-shadow': 'off',
            '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
            'no-console': 'off',
            // Parity tests import pkinative directly on purpose: they compare
            // the CLI's output with the library's own result.
            'no-restricted-imports': 'off',
            '@typescript-eslint/no-unused-expressions': 'off',
            '@typescript-eslint/no-empty-function': 'off',
            '@typescript-eslint/no-extraneous-class': 'off',
            '@typescript-eslint/no-dynamic-delete': 'off',
        },
    },
    {
        ignores: ['dist/**', 'node_modules/**', '*.config.*', 'scripts/**', 'samples/**', 'test-output/**', 'coverage/**'],
    },
);
