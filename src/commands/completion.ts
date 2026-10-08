// `pkinative completion <bash|zsh|fish|powershell>` — a completion script
// generated from the registry: commands, subcommands, each one's flags plus the
// global ones, the literal values of an enumerated flag (`--format text|json`),
// and paths after a flag taking a file. The command and subcommand are found by
// skipping flags and the values of value flags, so global flags may come first
// (`pkinative --json cert <TAB>`), as the parser allows. An alias is its flag:
// `-f <TAB>` offers the formats, `-i <TAB>` paths (audit A2-14).

import type { Ctx } from '../context.js';
import { usageError } from '../utils/error.js';
import { COMMANDS, GLOBAL_FLAGS, allFlagSpecs, commandFlags, type CommandSpec, type FlagSpec } from './registry.js';

const dash = (f: FlagSpec): string => `--${f.name}`;

function flagsOf(c: CommandSpec, sub: string | undefined): FlagSpec[] {
    return [...commandFlags(c, sub), ...GLOBAL_FLAGS];
}

/** Every "command" or "command sub" context with its flags. */
function contexts(): { key: string; flags: FlagSpec[] }[] {
    return COMMANDS.flatMap((c) => (c.subcommands.length === 0
        ? [{ key: c.name, flags: flagsOf(c, undefined) }]
        : c.subcommands.map((s) => ({ key: `${c.name} ${s.name}`, flags: flagsOf(c, s.name) }))));
}

/** `--input` and `-i`: every spelling the parser accepts. */
const spellings = (f: FlagSpec): string[] => [dash(f), ...(f.alias !== undefined ? [`-${f.alias}`] : [])];

const ALL_FLAGS = allFlagSpecs();
/** Every spelling of a flag that takes a path. */
const PATH_FLAGS = [...new Set(ALL_FLAGS.filter((f) => f.value === 'file').flatMap(spellings))];
/** Every spelling of a flag that consumes the next word. */
const VALUE_FLAGS = [...new Set(ALL_FLAGS.filter((f) => f.value !== undefined).flatMap(spellings))];
/** The commands whose operand is one of a closed set. */
const OPERAND_CHOICES: Readonly<Record<string, readonly string[]>> = { completion: ['bash', 'zsh', 'fish', 'powershell'] };

/**
 * Inside an enumerated value spec (one with `|`), the words that stand for
 * "some value" rather than a literal choice: `--nonce hex|random` offers only
 * `random`, `--signing-time instant|now|none` offers `now` and `none`, while
 * `--encoding pem|der|hex` offers all three.
 */
function choicesOf(value: string): string[] {
    const placeholder = (v: string): boolean => ['n', 'name', 'oid', 'instant'].includes(v) || (v === 'hex' && value.includes('random'));
    return value.includes('|') ? value.split('|').filter((v) => !placeholder(v)) : [];
}

/** The literal choices of each enumerated flag, under each spelling: `--format` and `-f` → ["text", "json"]. */
export function enumeratedValues(): Map<string, string[]> {
    const out = new Map<string, string[]>();
    for (const f of ALL_FLAGS) {
        const choices = choicesOf(f.value ?? '');
        for (const spelling of choices.length > 0 ? spellings(f) : []) out.set(spelling, [...new Set([...(out.get(spelling) ?? []), ...choices])]);
    }
    return out;
}

function bash(): string {
    const subs = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => `        ${c.name}) subs="${c.subcommands.map((s) => s.name).join(' ')}" ;;`).join('\n');
    const cases = contexts().map((x) => `        "${x.key}") opts="${x.flags.map(dash).join(' ')}" ;;`).join('\n');
    const values = [...enumeratedValues()].map(([flag, v]) => `        ${flag}) COMPREPLY=( $(compgen -W "${v.join(' ')}" -- "\${cur}") ); return 0 ;;`).join('\n');
    const operands = Object.entries(OPERAND_CHOICES).map(([cmd, v]) => `            ${cmd}) COMPREPLY=( $(compgen -W "${v.join(' ')}" -- "\${cur}") ); return 0 ;;`).join('\n');
    return `# bash completion for pkinative
_pkinative() {
    local cur="\${COMP_WORDS[COMP_CWORD]}" prev="\${COMP_WORDS[COMP_CWORD-1]}"
    local -a words=() ; local i skip=0
    for (( i = 1; i < COMP_CWORD; i++ )); do
        local w="\${COMP_WORDS[i]}"
        if (( skip )); then skip=0; continue; fi
        case "\${w}" in
            ${VALUE_FLAGS.join('|')}) skip=1; continue ;;
            -*) continue ;;
        esac
        words+=( "\${w}" )
    done
    case "\${prev}" in
${values}
        ${PATH_FLAGS.join('|')}) COMPREPLY=( $(compgen -f -- "\${cur}") ); return 0 ;;
    esac
    if [[ \${#words[@]} -eq 0 && "\${cur}" != -* ]]; then
        COMPREPLY=( $(compgen -W "${COMMANDS.map((c) => c.name).join(' ')}" -- "\${cur}") ); return 0
    fi
    local cmd="\${words[0]}" sub="\${words[1]}" subs="" opts=""
    case "\${cmd}" in
${subs}
    esac
    if [[ \${#words[@]} -eq 1 && "\${cur}" != -* ]]; then
        case "\${cmd}" in
${operands}
        esac
    fi
    if [[ -n "\${subs}" && \${#words[@]} -eq 1 && "\${cur}" != -* ]]; then
        COMPREPLY=( $(compgen -W "\${subs}" -- "\${cur}") ); return 0
    fi
    local key="\${cmd}"; [[ -n "\${subs}" ]] && key="\${cmd} \${sub}"
    case "\${key}" in
${cases}
        *) opts="${GLOBAL_FLAGS.map(dash).join(' ')}" ;;
    esac
    COMPREPLY=( $(compgen -W "\${opts}" -- "\${cur}") )
}
complete -F _pkinative pkinative
`;
}

function zsh(): string {
    const cmds = COMMANDS.map((c) => `        '${c.name}:${c.summary.replace(/'/g, '')}'`).join('\n');
    const subs = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => `        ${c.name}) subs=(${c.subcommands.map((s) => `'${s.name}:${s.summary.replace(/'/g, '')}'`).join(' ')}) ;;`).join('\n');
    const cases = contexts().map((x) => `        '${x.key}') _values 'flags' ${x.flags.map((f) => `'${dash(f)}'`).join(' ')} ;;`).join('\n');
    const values = [...enumeratedValues()].map(([flag, v]) => `        ${flag}) _values 'value' ${v.map((x) => `'${x}'`).join(' ')}; return ;;`).join('\n');
    const operands = Object.entries(OPERAND_CHOICES).map(([cmd, v]) => `            ${cmd}) _values 'value' ${v.map((x) => `'${x}'`).join(' ')}; return ;;`).join('\n');
    return `#compdef pkinative
# zsh completion for pkinative
_pkinative() {
    local -a commands subs args
    local i skip=0
    for (( i = 2; i < CURRENT; i++ )); do
        if (( skip )); then skip=0; continue; fi
        case "\${words[i]}" in
            ${VALUE_FLAGS.join('|')}) skip=1; continue ;;
            -*) continue ;;
        esac
        args+=( "\${words[i]}" )
    done
    case "\${words[CURRENT-1]}" in
${values}
        ${PATH_FLAGS.join('|')}) _files; return ;;
    esac
    commands=(
${cmds}
    )
    if (( \${#args} == 0 )) && [[ "\${words[CURRENT]}" != -* ]]; then _describe 'command' commands; return; fi
    case "\${args[1]}" in
${subs}
    esac
    if (( \${#subs} > 0 && \${#args} == 1 )) && [[ "\${words[CURRENT]}" != -* ]]; then _describe 'subcommand' subs; return; fi
    if (( \${#args} == 1 )) && [[ "\${words[CURRENT]}" != -* ]]; then
        case "\${args[1]}" in
${operands}
        esac
    fi
    local key="\${args[1]}"; (( \${#subs} > 0 )) && key="\${args[1]} \${args[2]}"
    case "\${key}" in
${cases}
    esac
}
_pkinative "$@"
`;
}

function fish(): string {
    const lines = ['# fish completion for pkinative', 'complete -c pkinative -f'];
    const values = enumeratedValues();
    for (const c of COMMANDS) {
        lines.push(`complete -c pkinative -n __fish_use_subcommand -a ${c.name} -d '${c.summary.replace(/'/g, '')}'`);
        for (const s of c.subcommands) {
            lines.push(`complete -c pkinative -n '__fish_seen_subcommand_from ${c.name}; and not __fish_seen_subcommand_from ${c.subcommands.map((x) => x.name).join(' ')}' -a ${s.name} -d '${s.summary.replace(/'/g, '')}'`);
        }
    }
    for (const [cmd, v] of Object.entries(OPERAND_CHOICES)) lines.push(`complete -c pkinative -n '__fish_seen_subcommand_from ${cmd}' -a '${v.join(' ')}'`);
    for (const x of contexts()) {
        const [cmd, sub] = x.key.split(' ') as [string, string | undefined];
        const cond = sub === undefined ? `__fish_seen_subcommand_from ${cmd}` : `__fish_seen_subcommand_from ${cmd}; and __fish_seen_subcommand_from ${sub}`;
        for (const f of x.flags) {
            const choices = values.get(dash(f));
            const arg = f.value === 'file' ? ' -r -F' : choices !== undefined ? ` -x -a '${choices.join(' ')}'` : f.value !== undefined ? ' -r' : '';
            lines.push(`complete -c pkinative -n '${cond}' -l ${f.name}${f.alias !== undefined ? ` -s ${f.alias}` : ''}${arg}`);
        }
    }
    return lines.join('\n') + '\n';
}

function powershell(): string {
    const subs = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => `        '${c.name}' { @(${c.subcommands.map((s) => `'${s.name}'`).join(', ')}) }`).join('\n');
    const cases = contexts().map((x) => `        '${x.key}' { @(${x.flags.map((f) => `'${dash(f)}'`).join(', ')}) }`).join('\n');
    const values = [...enumeratedValues()].map(([flag, v]) => `        '${flag}' { @(${v.map((x) => `'${x}'`).join(', ')}) }`).join('\n');
    const operands = Object.entries(OPERAND_CHOICES).map(([cmd, v]) => `        '${cmd}' { @(${v.map((x) => `'${x}'`).join(', ')}) }`).join('\n');
    return `# PowerShell completion for pkinative
# Add to your profile:  pkinative completion powershell >> $PROFILE
Register-ArgumentCompleter -Native -CommandName pkinative -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $complete = { param($list, $type) $list | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, $type, $_) } }
    # The words before the one being completed (an empty word is a new position).
    $before = @($commandAst.CommandElements | Where-Object { $_.Extent.EndOffset -lt $cursorPosition -or ($_.Extent.EndOffset -eq $cursorPosition -and $wordToComplete -eq '') } | ForEach-Object { $_.ToString() })
    $valueFlags = @(${VALUE_FLAGS.map((f) => `'${f}'`).join(', ')})
    $words = @(); $skip = $false
    foreach ($w in ($before | Select-Object -Skip 1)) {
        if ($skip) { $skip = $false; continue }
        if ($valueFlags -contains $w) { $skip = $true; continue }
        if ($w.StartsWith('-')) { continue }
        $words += $w
    }
    $prev = if ($before.Count -gt 0) { $before[-1] } else { '' }
    $choices = switch ($prev) {
${values}
        default { $null }
    }
    if ($null -ne $choices) { & $complete $choices 'ParameterValue'; return }
    # After a flag that takes a path, return nothing: PowerShell then completes file names.
    if (@(${PATH_FLAGS.map((f) => `'${f}'`).join(', ')}) -contains $prev) { return }
    $commands = @(${COMMANDS.map((c) => `'${c.name}'`).join(', ')})
    if ($words.Count -eq 0 -and -not $wordToComplete.StartsWith('-')) { & $complete $commands 'ParameterValue'; return }
    $cmd = $words[0]
    $subs = switch ($cmd) {
${subs}
        default { @() }
    }
    if ($subs.Count -gt 0 -and $words.Count -eq 1 -and -not $wordToComplete.StartsWith('-')) { & $complete $subs 'ParameterValue'; return }
    $operands = switch ($cmd) {
${operands}
        default { @() }
    }
    if ($operands.Count -gt 0 -and $words.Count -eq 1 -and -not $wordToComplete.StartsWith('-')) { & $complete $operands 'ParameterValue'; return }
    $key = if ($subs.Count -gt 0) { "$cmd $($words[1])" } else { $cmd }
    $flags = switch ($key) {
${cases}
        default { @(${GLOBAL_FLAGS.map((f) => `'${dash(f)}'`).join(', ')}) }
    }
    & $complete $flags 'ParameterName'
}
`;
}

export async function completion(ctx: Ctx): Promise<void> {
    const [shell] = ctx.args.positionals;
    if (shell === undefined) throw usageError('completion takes one shell: bash, zsh, fish or powershell.');
    const scripts: Readonly<Record<string, () => string>> = { bash, zsh, fish, powershell, pwsh: powershell };
    const build = scripts[shell];
    if (build === undefined) throw usageError(`Unsupported shell "${shell}": ${(OPERAND_CHOICES['completion'] as readonly string[]).join(', ')}.`);
    ctx.io.stdout.write(build());
}
