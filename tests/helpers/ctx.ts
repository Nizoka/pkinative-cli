import { booleanFlags } from '../../src/commands/registry.js';
import { createContext, parseGlobalOptions, type Ctx } from '../../src/context.js';
import { parseArgs } from '../../src/utils/args.js';
import { memoryIo, type MemoryIo, type MemoryIoOptions } from './io.js';

/** A command context over an in-memory Io, for unit tests of helpers. */
export function makeCtx(argv: readonly string[] = [], options: MemoryIoOptions = {}): Ctx & { readonly mem: MemoryIo } {
    const mem = memoryIo(options);
    const args = parseArgs(argv, booleanFlags());
    const ctx = createContext(mem.io, 'test', args, parseGlobalOptions(args, mem.io.env));
    return Object.assign(ctx, { mem });
}
