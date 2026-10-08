// The completion scripts held to the registry they are generated from: the
// contexts and their flags, the flags that take a value or a path, the commands
// with subcommands, the literal choices of each enumerated flag, and fish's
// conditions and argument kinds.

import { describe, expect, it } from 'vitest';
import { enumeratedValues } from '../../src/commands/completion.js';
import { COMMANDS, GLOBAL_FLAGS, allFlagSpecs, commandFlags, type FlagSpec } from '../../src/commands/registry.js';
import { cli } from '../helpers/io.js';

const dash = (f: FlagSpec): string => `--${f.name}`;

async function script(shell: string): Promise<string> {
    const r = await cli(['completion', shell]);
    expect(r.code).toBe(0);
    return r.stdout;
}

/** Every invocation key ("fingerprint", "cert inspect") with the flags it completes. */
function expectedContexts(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const c of COMMANDS) {
        const subs = c.subcommands.length === 0 ? [undefined] : c.subcommands.map((s) => s.name);
        for (const sub of subs) {
            out[sub === undefined ? c.name : `${c.name} ${sub}`] = [...commandFlags(c, sub), ...GLOBAL_FLAGS].map(dash).join(' ');
        }
    }
    return out;
}

/** The commands that take a subcommand, with their subcommand names. */
const WITH_SUBS = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => c.name);

/** The lines between two markers of a script. */
function block(text: string, start: string, end: string): string[] {
    const from = text.indexOf(start);
    expect(from, start).toBeGreaterThanOrEqual(0);
    const to = text.indexOf(end, from + start.length);
    expect(to, end).toBeGreaterThan(from);
    return text.slice(from + start.length, to).split('\n').filter((l) => l.trim() !== '');
}

describe('completion: the enumerated values', () => {
    it('offers only the literal choices of a flag whose value is an enumeration', async () => {
        const values = enumeratedValues();
        // A placeholder word stands for "some value" and is never offered.
        expect(values.get('--nonce')).toEqual(['random']);
        expect(values.get('--signing-time')).toEqual(['now', 'none']);
        // "hex" is a placeholder only beside "random".
        expect(values.get('--encoding')).toEqual(['pem', 'der', 'hex']);
        expect(values.get('--format')).toEqual(['text', 'json']);
        // An alias is its flag (audit A2-14).
        expect(values.get('-f')).toEqual(['text', 'json']);
        // Only enumerated flags (a value spec with "|"), under each spelling, are keys, and none is empty.
        const enumerated = new Set(allFlagSpecs().filter((f) => f.value?.includes('|') === true).flatMap((f) => [dash(f), ...(f.alias !== undefined ? [`-${f.alias}`] : [])]));
        for (const [flag, choices] of values) {
            expect(enumerated.has(flag), flag).toBe(true);
            expect(choices.length, flag).toBeGreaterThan(0);
        }
        expect(values.has('--json')).toBe(false);
        expect(values.has('--input')).toBe(false);
        // The bash script offers them after the flag.
        expect(await script('bash')).toContain('        --nonce) COMPREPLY=( $(compgen -W "random" -- "${cur}") ); return 0 ;;');
    });
});

describe('completion: bash', () => {
    it('skips exactly the value flags, under each spelling, and completes paths after a file flag', async () => {
        const text = await script('bash');
        const valueFlags = /^ {12}(\S+)\) skip=1; continue ;;$/m.exec(text)?.[1]?.split('|') ?? [];
        const expected = new Set(allFlagSpecs().filter((f) => f.value !== undefined).flatMap((f) => [dash(f), ...(f.alias !== undefined ? [`-${f.alias}`] : [])]));
        expect(new Set(valueFlags)).toEqual(expected);
        expect(valueFlags).toEqual(expect.arrayContaining(['--input', '-i', '-o', '--max-depth']));
        expect(valueFlags).not.toContain('--json');
        const pathFlags = /^ {8}(\S+)\) COMPREPLY=\( \$\(compgen -f -- /m.exec(text)?.[1]?.split('|') ?? [];
        expect(new Set(pathFlags)).toEqual(new Set(allFlagSpecs().filter((f) => f.value === 'file').flatMap((f) => [dash(f), ...(f.alias !== undefined ? [`-${f.alias}`] : [])])));
        expect(pathFlags).toEqual(expect.arrayContaining(['--input', '-i', '-o']));
        expect(pathFlags).not.toContain('--json');
    });

    it('names one context per invocation, with its flags and the global ones', async () => {
        const text = await script('bash');
        const contexts = Object.fromEntries([...text.matchAll(/^ {8}"([^"]+)"\) opts="([^"]*)" ;;$/gm)].map((m) => [m[1], m[2]]));
        expect(contexts).toEqual(expectedContexts());
        expect(contexts).toHaveProperty('fingerprint');
        expect(contexts).toHaveProperty(['cert inspect']);
    });

    it('lists the subcommands of exactly the commands that have some', async () => {
        const lines = block(await script('bash'), 'case "${cmd}" in\n', '    esac');
        expect(lines.map((l) => /^ {8}(\S+)\) subs="[^"]+" ;;$/.exec(l)?.[1])).toEqual(WITH_SUBS);
    });
});

describe('completion: zsh and powershell', () => {
    it('list the subcommands of exactly the commands that have some', async () => {
        const zsh = block(await script('zsh'), 'case "${args[1]}" in\n', '    esac');
        expect(zsh.map((l) => /^ {8}(\S+)\) subs=\('.+'\) ;;$/.exec(l)?.[1])).toEqual(WITH_SUBS);
        const ps = block(await script('powershell'), '$subs = switch ($cmd) {\n', '        default { @() }');
        expect(ps.map((l) => /^ {8}'(\S+)' \{ @\('.+'\) \}$/.exec(l)?.[1])).toEqual(WITH_SUBS);
    });
});

describe('completion: fish', () => {
    it('conditions each flag on its command and subcommand, with the argument it takes', async () => {
        const lines = (await script('fish')).split('\n');
        const top = "complete -c pkinative -n '__fish_seen_subcommand_from fingerprint'";
        const sub = "complete -c pkinative -n '__fish_seen_subcommand_from cert; and __fish_seen_subcommand_from inspect'";
        // A boolean flag takes no argument; a value flag one (-r); a file flag a path; an enumeration its choices.
        expect(lines).toContain(`${top} -l json`);
        expect(lines).toContain(`${top} -l max-depth -r`);
        expect(lines).toContain(`${top} -l input -s i -r -F`);
        // The shell operand of completion is offered by name (audit A2-14).
        expect(lines).toContain("complete -c pkinative -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell'");
        expect(await script('zsh')).toContain("            completion) _values 'value' 'bash' 'zsh' 'fish' 'powershell'; return ;;");
        expect(lines).toContain(`${top} -l pem-mode -x -a 'strict lax'`);
        expect(lines).toContain(`${sub} -l json`);
        expect(lines).toContain(`${sub} -l max-depth -r`);
    });

    it('never prints an undefined part in any shell', async () => {
        for (const shell of ['bash', 'zsh', 'fish', 'powershell']) expect(await script(shell), shell).not.toContain('undefined');
    });
});
