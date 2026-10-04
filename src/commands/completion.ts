// `pkinative completion <bash|zsh|fish|powershell>` — a completion script
// generated from the registry: commands, subcommands, and each one's flags
// plus the global ones; a flag taking a file completes paths.

import type { Ctx } from '../context.js';
import { usageError } from '../utils/error.js';
import { COMMANDS, GLOBAL_FLAGS, commandFlags, type CommandSpec, type FlagSpec } from './registry.js';

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

const PATH_FLAGS = [...new Set(COMMANDS.flatMap((c) => [...c.flags, ...c.subcommands.flatMap((s) => s.flags)]).concat(GLOBAL_FLAGS).filter((f) => f.value === 'file').map(dash))];

function bash(): string {
    const subs = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => `        ${c.name}) subs="${c.subcommands.map((s) => s.name).join(' ')}" ;;`).join('\n');
    const cases = contexts().map((x) => `        "${x.key}") opts="${x.flags.map(dash).join(' ')}" ;;`).join('\n');
    return `# bash completion for pkinative
_pkinative() {
    local cur="\${COMP_WORDS[COMP_CWORD]}" prev="\${COMP_WORDS[COMP_CWORD-1]}"
    local cmd="\${COMP_WORDS[1]}" sub="\${COMP_WORDS[2]}" subs="" opts=""
    if [[ \${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${COMMANDS.map((c) => c.name).join(' ')}" -- "\${cur}") ); return 0
    fi
    case "\${cmd}" in
${subs}
    esac
    if [[ -n "\${subs}" && \${COMP_CWORD} -eq 2 ]]; then
        COMPREPLY=( $(compgen -W "\${subs}" -- "\${cur}") ); return 0
    fi
    case "\${prev}" in
        ${PATH_FLAGS.join('|')}) COMPREPLY=( $(compgen -f -- "\${cur}") ); return 0 ;;
    esac
    local key="\${cmd}"; [[ -n "\${subs}" ]] && key="\${cmd} \${sub}"
    case "\${key}" in
${cases}
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
    return `#compdef pkinative
# zsh completion for pkinative
_pkinative() {
    local -a commands subs
    commands=(
${cmds}
    )
    if (( CURRENT == 2 )); then _describe 'command' commands; return; fi
    case "\${words[2]}" in
${subs}
    esac
    if (( \${#subs} > 0 && CURRENT == 3 )); then _describe 'subcommand' subs; return; fi
    case "\${words[CURRENT-1]}" in
        ${PATH_FLAGS.join('|')}) _files; return ;;
    esac
    local key="\${words[2]}"; (( \${#subs} > 0 )) && key="\${words[2]} \${words[3]}"
    case "\${key}" in
${cases}
    esac
}
_pkinative "$@"
`;
}

function fish(): string {
    const lines = ['# fish completion for pkinative', 'complete -c pkinative -f'];
    for (const c of COMMANDS) {
        lines.push(`complete -c pkinative -n __fish_use_subcommand -a ${c.name} -d '${c.summary.replace(/'/g, '')}'`);
        for (const s of c.subcommands) {
            lines.push(`complete -c pkinative -n '__fish_seen_subcommand_from ${c.name}; and not __fish_seen_subcommand_from ${c.subcommands.map((x) => x.name).join(' ')}' -a ${s.name} -d '${s.summary.replace(/'/g, '')}'`);
        }
    }
    for (const x of contexts()) {
        const [cmd, sub] = x.key.split(' ') as [string, string | undefined];
        const cond = sub === undefined ? `__fish_seen_subcommand_from ${cmd}` : `__fish_seen_subcommand_from ${cmd}; and __fish_seen_subcommand_from ${sub}`;
        for (const f of x.flags) {
            const arg = f.value === 'file' ? ' -r -F' : f.value !== undefined ? ' -r' : '';
            lines.push(`complete -c pkinative -n '${cond}' -l ${f.name}${f.alias !== undefined ? ` -s ${f.alias}` : ''}${arg}`);
        }
    }
    return lines.join('\n') + '\n';
}

function powershell(): string {
    const subs = COMMANDS.filter((c) => c.subcommands.length > 0).map((c) => `        '${c.name}' { @(${c.subcommands.map((s) => `'${s.name}'`).join(', ')}) }`).join('\n');
    const cases = contexts().map((x) => `        '${x.key}' { @(${x.flags.map((f) => `'${dash(f)}'`).join(', ')}) }`).join('\n');
    return `# PowerShell completion for pkinative
# Add to your profile:  pkinative completion powershell >> $PROFILE
Register-ArgumentCompleter -Native -CommandName pkinative -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $tokens = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    $complete = { param($list, $type) $list | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, $type, $_) } }
    $commands = @(${COMMANDS.map((c) => `'${c.name}'`).join(', ')})
    if ($tokens.Count -le 2 -and -not $wordToComplete.StartsWith('-')) { & $complete $commands 'ParameterValue'; return }
    $cmd = $tokens[1]
    $subs = switch ($cmd) {
${subs}
        default { @() }
    }
    if ($subs.Count -gt 0 -and $tokens.Count -le 3 -and -not $wordToComplete.StartsWith('-')) { & $complete $subs 'ParameterValue'; return }
    $key = if ($subs.Count -gt 0) { "$cmd $($tokens[2])" } else { $cmd }
    $flags = switch ($key) {
${cases}
        default { @(${GLOBAL_FLAGS.map((f) => `'${dash(f)}'`).join(', ')}) }
    }
    & $complete $flags 'ParameterName'
}
`;
}

export async function completion(ctx: Ctx): Promise<void> {
    const [shell, ...extra] = ctx.args.positionals;
    if (shell === undefined || extra.length > 0) throw usageError('completion takes one shell: bash, zsh, fish or powershell.');
    const scripts: Readonly<Record<string, () => string>> = { bash, zsh, fish, powershell, pwsh: powershell };
    const build = scripts[shell];
    if (build === undefined) throw usageError(`Unsupported shell "${shell}": bash, zsh, fish or powershell.`);
    ctx.io.stdout.write(build());
}
