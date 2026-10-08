import { readFileSync } from 'node:fs';
import { SUBJECTS } from '../../src/commands/schema.ts';
import { CLI_CODE_MEANING } from '../../src/commands/explain.ts';
import { ERROR_CODES } from '../../src/utils/error.ts';
import { PKI_TO_CLI } from '../../src/utils/pkierr.ts';
import { buildSurface } from './surface.ts';

const KB = 'docs/KNOWLEDGE_BASE.md';
const ERRORS = 'docs/data/errors.json';

function replaceSection(text: string, name: string, body: string): string {
    const begin = `<!-- BEGIN GENERATED: ${name} -->`;
    const end = `<!-- END GENERATED: ${name} -->`;
    const start = text.indexOf(begin);
    const stop = text.indexOf(end);
    if (start === -1 || stop === -1) throw new Error(`${KB}: missing the ${name} markers`);
    return `${text.slice(0, start + begin.length)}\n${body}\n${text.slice(stop)}`;
}

function errorClasses(): string {
    const rows = ERROR_CODES.map((code) => {
        const exit = code === 'E_USAGE' ? 2 : 1;
        const count = Object.values(PKI_TO_CLI).filter(([c]) => c === code).length;
        return `| \`${code}\` | ${exit} | ${count} | ${CLI_CODE_MEANING[code]} |`;
    });
    return ['| Class | Exit | PKI_* codes | Meaning |', '|---|---|---|---|', ...rows].join('\n');
}

function apiMapping(): string {
    const rows = buildSurface().filter((e) => e.reach === 'capability').map((e) => `| \`${e.name}\` | ${e.kind} | ${e.via.map((v) => (v === '*' ? '*' : `\`${v}\``)).join(', ')} |`);
    return ['| Export | Kind | Reached by |', '|---|---|---|', ...rows].join('\n');
}

/** Every generated file, by path, with its expected content. */
export function generatedDocs(): Record<string, string> {
    const errors = SUBJECTS.find((s) => s.name === 'errors');
    if (errors === undefined) throw new Error('schema subject "errors" is missing');
    let kb = readFileSync(KB, 'utf8');
    kb = replaceSection(kb, 'error-classes', errorClasses());
    kb = replaceSection(kb, 'api-mapping', apiMapping());
    const catalogue = JSON.stringify(errors.build(undefined as never), null, 2) + '\n';
    return { [KB]: kb, [ERRORS]: catalogue };
}
