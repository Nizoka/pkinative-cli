import { describe, expect, it } from 'vitest';
import { validateIssueMarkdown } from '../../scripts/verify-issue.mjs';

// AI governance: the draft-issue verifier enforces the one-runtime-dependency
// policy and a mandatory reproduction block, and warns on missing fields.

const GOOD = `# Bug: chain verify accepts an expired intermediate

## Environment
- pkinative-cli 1.0.0, pkinative 1.0.0, Node 22, Windows
- installed with npm install --global pkinative-cli

## Expected behavior
E_VERIFY_FAILED with PKI_REASON_EXPIRED.

## Minimal reproduction
\`\`\`sh
pkinative chain verify leaf.pem --trust root.pem --json
\`\`\`
`;

describe('validateIssueMarkdown', () => {
    it('passes a well-formed draft, the CLI install command included', () => {
        const r = validateIssueMarkdown(GOOD);
        expect(r).toEqual({ ok: true, errors: [], warnings: [] });
        expect(validateIssueMarkdown('# X\nnpm i pkinative-cli@1.0.0\n```sh\nx\n```').ok).toBe(true);
    });

    it('rejects a dependency request', () => {
        for (const text of ['Run npm install node-forge', 'yarn add foo', 'pnpm add foo', 'bun add foo', 'npm i pkinative-cli-helper', '"dependencies": { "asn1js": "^3.0.0" }']) {
            const r = validateIssueMarkdown(`# X\n${text}\n\`\`\`sh\nx\n\`\`\``);
            expect(r.ok, text).toBe(false);
            expect(r.errors[0]).toMatch(/pkinative alone/);
        }
    });

    it('rejects a draft without a reproduction block, and only warns on missing fields', () => {
        expect(validateIssueMarkdown('# X\n## Environment\nNode 22\n## Expected behavior\nok').errors[0]).toMatch(/reproduction code block/);
        const r = validateIssueMarkdown('# X\n```sh\nx\n```');
        expect(r.ok).toBe(true);
        expect(r.warnings.length).toBeGreaterThan(0);
    });
});
