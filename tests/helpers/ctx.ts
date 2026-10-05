import { COMMANDS, GLOBAL_FLAGS, booleanFlags } from '../../src/commands/registry.js';
import { createContext, parseGlobalOptions, type Ctx } from '../../src/context.js';
import { canonicaliseAliases, parseArgs } from '../../src/utils/args.js';
import { memoryIo, type MemoryIo, type MemoryIoOptions } from './io.js';

/** Every aliased flag, as the dispatcher renames them before a handler runs. */
const ALIASED = [...GLOBAL_FLAGS, ...COMMANDS.flatMap((c) => [...c.flags, ...c.subcommands.flatMap((s) => s.flags)])].filter((f) => f.alias !== undefined);

/** A command context over an in-memory Io, for unit tests of helpers. */
export function makeCtx(argv: readonly string[] = [], options: MemoryIoOptions = {}): Ctx & { readonly mem: MemoryIo } {
    const mem = memoryIo(options);
    const parsed = parseArgs(argv, booleanFlags());
    const args = { flags: canonicaliseAliases(parsed.flags, ALIASED), positionals: parsed.positionals };
    const ctx = createContext(mem.io, 'test', args, parseGlobalOptions(args, mem.io.env));
    return Object.assign(ctx, { mem });
}
