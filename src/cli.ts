// The dispatcher: argv → global options → command → exit code. Nothing here
// calls process.exit; `run()` returns the code, so every path is testable
// in-process and stdout is flushed before the process ends.

import { aliasedFlags, booleanFlags, commandNames, configSections, findCommand, knownFlags, operandRule, repeatableFlags } from './commands/registry.js';
import { COMMAND_USAGE, USAGE } from './commands/usage.js';
import { createContext, parseGlobalOptions, type Ctx } from './context.js';
import { assertKnownFlags, assertOperands, assertSingleValues, canonicaliseAliases, firstPositionalIndex, getStringFlag, hasFlag, parseArgs } from './utils/args.js';
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
        case 'pem': return (await import('./commands/pem.js')).pem;
        case 'oid': return (await import('./commands/oid.js')).oid;
        case 'fingerprint': return (await import('./commands/fingerprint.js')).fingerprint;
        case 'asn1': return (await import('./commands/asn1.js')).asn1;
        case 'cert': return (await import('./commands/cert.js')).cert;
        case 'csr': return (await import('./commands/csr.js')).csr;
        case 'chain': return (await import('./commands/chain.js')).chain;
        case 'crl': return (await import('./commands/crl.js')).crl;
        case 'ocsp': return (await import('./commands/ocsp.js')).ocsp;
        case 'cms': return (await import('./commands/cms.js')).cms;
        case 'tsp': return (await import('./commands/tsp.js')).tsp;
        case 'key': return (await import('./commands/key.js')).key;
        case 'p12': return (await import('./commands/p12.js')).p12;
        case 'doctor': return (await import('./commands/doctor.js')).doctor;
        case 'limits': return (await import('./commands/limits.js')).limits;
        case 'explain': return (await import('./commands/explain.js')).explain;
        case 'schema': return (await import('./commands/schema.js')).schema;
        case 'completion': return (await import('./commands/completion.js')).completion;
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
    let configPath: string | undefined;
    let json = io.env['PKINATIVE_JSON'] === '1' || argv.includes('--json');
    try {
        const booleans = booleanFlags();
        const top = parseArgs(argv, booleans);
        json ||= hasFlag(top.flags, 'json');
        const { command: name, rest } = locateCommand(argv, booleans);

        if (name === undefined) {
            assertNoLiteralPassword(top);
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
        const help = hasFlag(args.flags, 'help', 'h');
        let sub: string | undefined;
        if (spec.subcommands.length > 0) {
            const names = spec.subcommands.map((s) => s.name);
            sub = args.positionals[0];
            if (sub === undefined) {
                if (!help) throw usageError(`"${name}" needs a subcommand: ${names.join(', ')}. Run pkinative ${name} --help.`);
            } else if (!names.includes(sub)) {
                throw usageError(`Unknown subcommand "${name} ${sub}". Subcommands: ${names.join(', ')}.`);
            } else {
                commandLabel = `${name} ${sub}`;
                args = { flags: args.flags, positionals: args.positionals.slice(1) };
            }
        }
        // After the command is known, so the envelope names it; before help or anything else runs.
        assertNoLiteralPassword(args);
        if (help) {
            // tests/docs/usage.test.ts holds one help block per registered command.
            io.stdout.write(COMMAND_USAGE[name] as string);
            return 0;
        }
        const known = knownFlags(spec, sub);
        assertKnownFlags(args.flags, known, commandLabel);
        args = { flags: canonicaliseAliases(args.flags, aliasedFlags(spec, sub)), positionals: args.positionals };
        assertSingleValues(args.flags, repeatableFlags(spec, sub), commandLabel);
        assertOperands(args, operandRule(spec, sub), commandLabel);
        if (!hasFlag(args.flags, 'no-config')) {
            const config = loadConfig(name, sub, configSections(), getStringFlag(args.flags, 'config'), io.cwd);
            const merged = applyConfigDefaults(args, config.defaults, known);
            args = merged.args;
            if (merged.applied.length > 0) configPath = config.path;
        }
        const opts = parseGlobalOptions(args, io.env);
        json = opts.json;
        ctx = createContext(io, commandLabel, args, opts);
        if (configPath !== undefined) {
            ctx.status['config'] = configPath;
            if (!opts.json && !opts.quiet) io.stderr.write(`note: defaults from ${configPath}\n`);
        }
        const handler = await loadCommand(name);
        await handler(ctx);
        if (opts.json) {
            io.stderr.write(serializeJson(buildStatusEnvelope(commandLabel, ctx.status, ctx.diagnostics), false) + '\n');
        } else if (!opts.quiet) {
            for (const d of ctx.diagnostics) io.stderr.write(formatDiagnostic(d) + '\n');
        }
        return 0;
    } catch (e) {
        return reportFailure(io, commandLabel, redactMistypedPassword(argv, e), ctx, json, configPath);
    }
}

/**
 * `--password-stdin hunter2` is a password typed on argv by mistake: the
 * switch takes no value, so hunter2 becomes an operand, and a failure that
 * names the operand would print it. That token is never echoed (audit A2-03).
 */
export function redactMistypedPassword(argv: readonly string[], e: unknown): unknown {
    const i = argv.indexOf('--password-stdin');
    const next = i === -1 ? undefined : argv[i + 1];
    if (e instanceof Error && next !== undefined && !next.startsWith('-') && e.message.includes(next)) {
        e.message = e.message.replaceAll(next, '<operand>');
    }
    return e;
}

export function reportFailure(io: Io, command: string | null, e: unknown, ctx: Ctx | undefined, json: boolean, configPath?: string): number {
    const diagnostics = ctx?.diagnostics ?? [];
    const debug = io.env['PKINATIVE_DEBUG'] === '1';
    if (json) {
        io.stderr.write(serializeJson(buildErrorEnvelope(command, e, diagnostics, configPath), false) + '\n');
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
