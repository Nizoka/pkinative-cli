export async function run(argv: readonly string[]): Promise<number> {
    process.stdout.write(`pkinative-cli: ${argv.length} argument(s)\n`);
    return 0;
}
