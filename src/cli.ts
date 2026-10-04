// The dispatcher: argv → global options → command → exit code. Nothing here
// calls process.exit; `run()` returns the code, so every path is testable
// in-process and stdout is flushed before the process ends.

import { booleanFlags, commandNames, findCommand, knownFlags } from './commands/registry.js';
import { COMMAND_USAGE, USAGE } from './commands/usage.js';
import { createContext, parseGlobalOptions, type Ctx } from './context.js';
import { assertKnownFlags, firstPositionalIndex, getStringFlag, hasFlag, parseArgs } from './utils/args.js';
import { buildErrorEnvelope, buildStatusEnvelope, formatDiagnostic } from './utils/agent.js';
import { applyConfigDefaults, loadConfig } from './utils/config.js';
import { CliError, ErrorCode, usageError } from './utils/error.js';
import { processIo, type Io } from './utils/io.js';
import { remedyFor } from './utils/pkierr.js';
import { serializeJson } from './utils/projection.js';
import { assertNoLiteralPassword } from './utils/secrets.js';
import { CLI_NAME, CLI_VERSION, engineVersion } from './utils/version.js';

export type CommandHandler = (ctx: Ctx) => Promise<void>;

export async function loadCommand(name: string): Promise<CommandHandler> {
    switch (name) {
        case 'limits': return (await import('./commands/limits.js')).limits;
        default:
            throw new CliError(`Unknown command: ${name}. Run pkinative --help.`, 2);
    }
}

/** Split argv into the command and the rest, wherever the global flags sit. */
function locateCommand(argv: readonly string[], booleans: ReadonlySet<string>): { command: string | undefined; rest: readonly string[] } {
    const index = firstPositionalIndex(argv, booleans);
    if (index === -1) return { command: undefined, rest: argv };
    return { command: argv[index], rest: [...argv.slice(0, index), ...argv.slice(index + 1)] };
}

export async function run(argv: readonly string[], io: Io = processIo()): Promise<number> {
    let commandLabel: string | null = null;
    let ctx: Ctx | undefined;
    let json = io.env['PKINATIVE_JSON'] === '1' || argv.includes('--json');
    try {
        const booleans = booleanFlags();
        const top = parseArgs(argv, booleans);
        json ||= hasFlag(top.flags, 'json');
        assertNoLiteralPassword(top);
        const { command: name, rest } = locateCommand(argv, booleans);

        if (name === undefined) {
            if (hasFlag(top.flags, 'version', 'V')) {
                io.stdout.write(json
                    ? serializeJson({ name: CLI_NAME, version: CLI_VERSION, pkinative: engineVersion() }, false) + '\n'
                    : `${CLI_VERSION}\n`);
                return 0;
            }
            if (hasFlag(top.flags, 'help', 'h') || argv.length === 0) {
                io.stdout.write(USAGE);
                return 0;
            }
            throw usageError(`No command given (got: ${argv.join(' ')}). Run pkinative --help.`);
        }

        const spec = findCommand(name);
        if (spec === undefined) {
            throw usageError(`Unknown command: ${name}. Commands: ${commandNames().join(', ')}.`);
        }
        commandLabel = name;
        let args = parseArgs(rest, booleans);
        let sub: string | undefined;
        if (spec.subcommands.length > 0) {
            sub = args.positionals[0];
            if (sub !== undefined && !spec.subcommands.includes(sub)) {
                throw usageError(`Unknown subcommand "${name} ${sub}". Subcommands: ${spec.subcommands.join(', ')}.`);
            }
            if (sub !== undefined) {
                commandLabel = `${name} ${sub}`;
                args = { flags: args.flags, positionals: args.positionals.slice(1) };
            }
        }
        if (hasFlag(args.flags, 'help', 'h') || (sub === undefined && spec.subcommands.length > 0)) {
            if (sub === undefined && spec.subcommands.length > 0 && !hasFlag(args.flags, 'help', 'h')) {
                throw usageError(`"${name}" needs a subcommand: ${spec.subcommands.join(', ')}. Run pkinative ${name} --help.`);
            }
            io.stdout.write(COMMAND_USAGE[name] ?? USAGE);
            return 0;
        }
        assertKnownFlags(args.flags, knownFlags(spec), name);
        if (!hasFlag(args.flags, 'no-config')) {
            const defaults = loadConfig(name, commandNames(), getStringFlag(args.flags, 'config'), io.cwd);
            args = applyConfigDefaults(args, defaults);
            assertKnownFlags(args.flags, knownFlags(spec), name);
        }
        const opts = parseGlobalOptions(args, io.env);
        json = opts.json;
        ctx = createContext(io, commandLabel, args, opts);
        const handler = await loadCommand(name);
        await handler(ctx);
        if (opts.json) {
            io.stderr.write(serializeJson(buildStatusEnvelope(commandLabel, ctx.status, ctx.diagnostics), false) + '\n');
        } else if (!opts.quiet) {
            for (const d of ctx.diagnostics) io.stderr.write(formatDiagnostic(d) + '\n');
        }
        return 0;
    } catch (e) {
        return reportFailure(io, commandLabel, e, ctx, json);
    }
}

export function reportFailure(io: Io, command: string | null, e: unknown, ctx: Ctx | undefined, json: boolean): number {
    const diagnostics = ctx?.diagnostics ?? [];
    const debug = io.env['PKINATIVE_DEBUG'] === '1';
    if (json) {
        io.stderr.write(serializeJson(buildErrorEnvelope(command, e, diagnostics), false) + '\n');
    } else {
        if (ctx !== undefined && !ctx.opts.quiet) {
            for (const d of diagnostics) io.stderr.write(formatDiagnostic(d) + '\n');
        }
        const err = e instanceof CliError ? e : new CliError(e instanceof Error ? e.message : String(e), 1, ErrorCode.RUNTIME);
        io.stderr.write(`error ${err.code}${err.pkiCode !== undefined ? ` (${err.pkiCode})` : ''}: ${err.message}\n`);
        const remedy = remedyFor(err);
        if (remedy !== undefined) io.stderr.write(`remedy: ${remedy}\n`);
    }
    if (debug && e instanceof Error && e.stack !== undefined) io.stderr.write(e.stack + '\n');
    return e instanceof CliError ? e.exitCode : 1;
}
