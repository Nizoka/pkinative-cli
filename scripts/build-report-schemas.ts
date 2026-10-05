// Generates src/generated/report-schemas.ts: the JSON Schema (draft 2020-12)
// of every report, every --summary shape and every envelope status field, for
// each of the CLI's invocations — derived from the TypeScript types, never
// written by hand, so the schemas cannot drift from what the code prints.
//
// For each invocation the generator starts at its handler (the `case` of the
// command's dispatcher, or the dispatcher itself), follows every call into a
// function of src/, and records:
//   emitReport(ctx, value, text, summary?)   the type of `value`, and the
//                                            return type of `summary`
//   emitArtifact(...)                        that it writes an artefact
//   ctx.status['key'] = expression           the key and the expression's type
// Types become schemas under pkinative's ADR 0018 wire form (src/utils/wire.ts):
// bigint → decimal string, bytes → lowercase hex, absent optional → omitted.
// Objects stay open (fields are only ever added, AGENT_CONTRACT §0).
//
//   npx tsx scripts/build-report-schemas.ts           write
//   npx tsx scripts/build-report-schemas.ts --check   exit 1 when stale

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import { COMMANDS } from '../src/commands/registry.ts';

export const OUT = 'src/generated/report-schemas.ts';
const ROOT = resolve(import.meta.dirname, '..');
const SRC = join(ROOT, 'src').replace(/\\/g, '/');

type Schema = Record<string, unknown>;

export interface InvocationShape {
    /** What stdout carries: a report, an artefact, a JSON document (schema) or a script (completion). */
    readonly outputs: readonly ('report' | 'artifact' | 'document' | 'script')[];
    readonly report?: Schema;
    readonly summary?: Schema;
    /** The envelope fields this invocation may add, with their schemas. */
    readonly status: Readonly<Record<string, Schema>>;
}

function createProgram(): ts.Program {
    const config = ts.readConfigFile(join(ROOT, 'tsconfig.json'), (p) => ts.sys.readFile(p));
    const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, ROOT);
    return ts.createProgram(parsed.fileNames, parsed.options);
}

/** Converts checker types to JSON Schema, collecting named types in $defs. */
class SchemaWriter {
    readonly defs: Record<string, Schema> = {};
    private readonly names = new Map<ts.Symbol, string>();
    private readonly taken = new Set<string>();

    constructor(private readonly checker: ts.TypeChecker) {}

    private nameOf(symbol: ts.Symbol): string {
        const known = this.names.get(symbol);
        if (known !== undefined) return known;
        let name = symbol.getName();
        for (let i = 2; this.taken.has(name); i++) name = `${symbol.getName()}${i}`;
        this.names.set(symbol, name);
        this.taken.add(name);
        return name;
    }

    schema(type: ts.Type): Schema {
        const checker = this.checker;
        if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return {};
        if (type.isUnion()) return this.union(type.types);
        if (type.flags & ts.TypeFlags.Null) return { type: 'null' };
        if (type.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)) return { type: 'null' };
        if (type.flags & ts.TypeFlags.BooleanLike) return type.flags & ts.TypeFlags.BooleanLiteral ? { const: checker.typeToString(type) === 'true' } : { type: 'boolean' };
        if (type.isStringLiteral()) return { const: type.value };
        if (type.isNumberLiteral()) return { const: type.value };
        if (type.flags & ts.TypeFlags.StringLike) return { type: 'string' };
        if (type.flags & ts.TypeFlags.NumberLike) return { type: 'number' };
        if (type.flags & ts.TypeFlags.BigIntLike) return { type: 'string', pattern: '^-?[0-9]+$', description: 'bigint as a decimal string (ADR 0018)' };
        if (type.flags & ts.TypeFlags.Never) return { not: {} };
        const symbol = type.getSymbol() ?? type.aliasSymbol;
        const name = symbol?.getName();
        if (name === 'Uint8Array' || name === 'Buffer' || name === 'ArrayBuffer') {
            return { type: 'string', pattern: '^([0-9a-f]{2})*$', description: 'bytes as lowercase hexadecimal (ADR 0018)' };
        }
        if (name === 'CryptoKey') {
            return { type: 'object', required: ['type', 'algorithm', 'extractable', 'usages'], properties: { type: { type: 'string' }, algorithm: { type: 'string' }, extractable: { type: 'boolean' }, usages: { type: 'array', items: { type: 'string' } } } };
        }
        if (checker.isArrayType(type) || checker.isTupleType(type)) {
            const args = checker.getTypeArguments(type as ts.TypeReference);
            if (checker.isTupleType(type)) return { type: 'array', prefixItems: args.map((a) => this.schema(a)), items: false };
            return { type: 'array', items: args[0] === undefined ? {} : this.schema(args[0]) };
        }
        if ((name === 'Map' || name === 'ReadonlyMap') && (type as ts.TypeReference).typeArguments !== undefined) {
            const [, value] = checker.getTypeArguments(type as ts.TypeReference);
            return { type: 'object', additionalProperties: value === undefined ? {} : this.schema(value) };
        }
        if ((name === 'Set' || name === 'ReadonlySet') && (type as ts.TypeReference).typeArguments !== undefined) {
            const [item] = checker.getTypeArguments(type as ts.TypeReference);
            return { type: 'array', items: item === undefined ? {} : this.schema(item) };
        }
        if (type.flags & ts.TypeFlags.Object || type.isIntersection()) {
            const named = type.aliasSymbol ?? (symbol !== undefined && !(symbol.flags & ts.SymbolFlags.TypeLiteral) && !(symbol.flags & ts.SymbolFlags.ObjectLiteral) && name !== '__type' && name !== '__object' ? symbol : undefined);
            const generic = (type as ts.TypeReference).typeArguments !== undefined && (type as ts.TypeReference).typeArguments!.length > 0;
            if (named !== undefined && !generic && !type.isIntersection()) {
                const key = this.nameOf(named);
                if (this.defs[key] === undefined) {
                    this.defs[key] = {};
                    this.defs[key] = this.object(type);
                }
                return { $ref: `#/$defs/${key}` };
            }
            return this.object(type);
        }
        return {};
    }

    private union(types: readonly ts.Type[]): Schema {
        const present = types.filter((t) => !(t.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void)));
        const booleans = present.filter((t) => t.flags & ts.TypeFlags.BooleanLiteral);
        const rest = present.filter((t) => !(t.flags & ts.TypeFlags.BooleanLiteral));
        const parts: Schema[] = [];
        if (booleans.length === 2) parts.push({ type: 'boolean' });
        else for (const b of booleans) parts.push(this.schema(b));
        const strings = rest.filter((t) => t.isStringLiteral()) as ts.StringLiteralType[];
        const numbers = rest.filter((t) => t.isNumberLiteral()) as ts.NumberLiteralType[];
        if (strings.length > 1) parts.push({ type: 'string', enum: strings.map((s) => s.value) });
        else if (strings.length === 1) parts.push({ const: strings[0]?.value });
        if (numbers.length > 1) parts.push({ type: 'number', enum: numbers.map((n) => n.value) });
        else if (numbers.length === 1) parts.push({ const: numbers[0]?.value });
        for (const t of rest.filter((x) => !x.isStringLiteral() && !x.isNumberLiteral())) parts.push(this.schema(t));
        const unique = parts.filter((p, i) => parts.findIndex((q) => JSON.stringify(q) === JSON.stringify(p)) === i);
        if (unique.length === 0) return { type: 'null' };
        return unique.length === 1 ? (unique[0] as Schema) : { anyOf: unique };
    }

    private object(type: ts.Type): Schema {
        const checker = this.checker;
        const properties: Record<string, Schema> = {};
        const required: string[] = [];
        for (const prop of checker.getPropertiesOfType(type)) {
            if (prop.flags & ts.SymbolFlags.Method) continue;
            const decl = prop.valueDeclaration ?? prop.declarations?.[0];
            const propType = decl !== undefined ? checker.getTypeOfSymbolAtLocation(prop, decl) : checker.getTypeOfSymbol(prop);
            if (propType.getCallSignatures().length > 0 && propType.getProperties().length === 0) continue;
            const types = propType.isUnion() ? propType.types : [propType];
            if (types.every((t) => t.flags & (ts.TypeFlags.Undefined | ts.TypeFlags.Void))) continue;
            properties[prop.getName()] = this.schema(propType);
            const optional = (prop.flags & ts.SymbolFlags.Optional) !== 0 || types.some((t) => t.flags & ts.TypeFlags.Undefined);
            if (!optional) required.push(prop.getName());
        }
        const out: Schema = { type: 'object', properties };
        if (required.length > 0) out['required'] = required;
        const index = checker.getIndexInfosOfType(type).find((i) => i.keyType.flags & ts.TypeFlags.String);
        if (index !== undefined) out['additionalProperties'] = this.schema(index.type);
        return out;
    }
}

interface Found {
    readonly reports: ts.CallExpression[];
    artifact: boolean;
    readonly status: Map<string, ts.Expression[]>;
}

/** The function declaration a call or identifier resolves to, inside src/ only. */
function declarationOf(checker: ts.TypeChecker, node: ts.Expression): ts.FunctionLikeDeclaration | undefined {
    let symbol = checker.getSymbolAtLocation(node);
    if (symbol !== undefined && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    const decl = symbol?.valueDeclaration ?? symbol?.declarations?.[0];
    if (decl === undefined || !decl.getSourceFile().fileName.replace(/\\/g, '/').startsWith(SRC)) return undefined;
    if (ts.isFunctionDeclaration(decl) || ts.isMethodDeclaration(decl)) return decl;
    if (ts.isVariableDeclaration(decl) && decl.initializer !== undefined && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) return decl.initializer;
    return undefined;
}

function collect(checker: ts.TypeChecker, entry: ts.FunctionLikeDeclaration): Found {
    const found: Found = { reports: [], artifact: false, status: new Map() };
    const seen = new Set<ts.Node>();
    const visitFunction = (fn: ts.FunctionLikeDeclaration): void => {
        if (seen.has(fn) || fn.body === undefined) return;
        seen.add(fn);
        const walk = (node: ts.Node): void => {
            if (ts.isCallExpression(node)) {
                const callee = ts.isIdentifier(node.expression) ? node.expression.text : undefined;
                if (callee === 'emitReport') found.reports.push(node);
                else if (callee === 'emitArtifact') found.artifact = true;
                const target = declarationOf(checker, node.expression);
                if (target !== undefined && callee !== 'emitReport') visitFunction(target);
            }
            if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isElementAccessExpression(node.left)) {
                const target = node.left.expression;
                if (ts.isPropertyAccessExpression(target) && target.name.text === 'status' && ts.isStringLiteral(node.left.argumentExpression)) {
                    const key = node.left.argumentExpression.text;
                    found.status.set(key, [...(found.status.get(key) ?? []), node.right]);
                }
            }
            ts.forEachChild(node, walk);
        };
        walk(fn.body);
    };
    visitFunction(entry);
    return found;
}

/** Each invocation's handler: the dispatcher's `case '<cmd> <sub>': return f(ctx)`, its default, or the dispatcher itself. */
function handlers(program: ts.Program, checker: ts.TypeChecker): Map<string, ts.FunctionLikeDeclaration> {
    const out = new Map<string, ts.FunctionLikeDeclaration>();
    for (const command of COMMANDS) {
        const file = program.getSourceFile(join(ROOT, 'src', 'commands', `${command.name}.ts`).replace(/\\/g, '/')) ?? program.getSourceFiles().find((f) => f.fileName.replace(/\\/g, '/').endsWith(`/src/commands/${command.name}.ts`));
        if (file === undefined) throw new Error(`src/commands/${command.name}.ts is not in the program`);
        const dispatcher = file.statements.find((s): s is ts.FunctionDeclaration => ts.isFunctionDeclaration(s) && s.name?.text === command.name);
        if (dispatcher === undefined) throw new Error(`src/commands/${command.name}.ts exports no function ${command.name}`);
        if (command.subcommands.length === 0) {
            out.set(command.name, dispatcher);
            continue;
        }
        // Two dispatcher shapes: `switch (ctx.command) { case '…': return f(ctx); default: return g(ctx); }`
        // and `if (ctx.command === '…') return f(ctx); … return g(ctx);`.
        const covered = new Set<string>();
        let fallback: ts.FunctionLikeDeclaration | undefined;
        const target = (stmt: ts.Statement | undefined): ts.FunctionLikeDeclaration => {
            const ret = stmt !== undefined && ts.isBlock(stmt) ? stmt.statements[0] : stmt;
            const call = ret !== undefined && ts.isReturnStatement(ret) && ret.expression !== undefined && ts.isCallExpression(ret.expression) ? ret.expression : undefined;
            const decl = call === undefined ? undefined : declarationOf(checker, call.expression);
            if (decl === undefined) throw new Error(`${command.name}: a dispatcher branch does not return f(ctx)`);
            return decl;
        };
        for (const stmt of dispatcher.body?.statements ?? []) {
            if (ts.isSwitchStatement(stmt)) {
                for (const clause of stmt.caseBlock.clauses) {
                    const decl = target(clause.statements.find((s) => ts.isReturnStatement(s)));
                    if (ts.isCaseClause(clause) && ts.isStringLiteral(clause.expression)) {
                        covered.add(clause.expression.text);
                        out.set(clause.expression.text, decl);
                    } else {
                        fallback = decl;
                    }
                }
            } else if (ts.isIfStatement(stmt) && ts.isBinaryExpression(stmt.expression) && ts.isStringLiteral(stmt.expression.right)) {
                covered.add(stmt.expression.right.text);
                out.set(stmt.expression.right.text, target(stmt.thenStatement));
            } else if (ts.isReturnStatement(stmt)) {
                fallback = target(stmt);
            }
        }
        const rest = command.subcommands.map((s) => `${command.name} ${s.name}`).filter((n) => !covered.has(n));
        if (rest.length !== (fallback === undefined ? 0 : 1)) throw new Error(`${command.name}: the dispatcher does not map ${rest.join(', ')}`);
        if (fallback !== undefined && rest[0] !== undefined) out.set(rest[0], fallback);
    }
    return out;
}

function dedupe(schemas: Schema[]): Schema | undefined {
    const unique = schemas.filter((s, i) => schemas.findIndex((t) => JSON.stringify(t) === JSON.stringify(s)) === i);
    if (unique.length === 0) return undefined;
    return unique.length === 1 ? unique[0] : { anyOf: unique };
}

/** The generated module's text. */
export function generateReportSchemas(): string {
    const program = createProgram();
    const checker = program.getTypeChecker();
    const writer = new SchemaWriter(checker);
    const invocations: Record<string, InvocationShape> = {};
    for (const [invocation, handler] of [...handlers(program, checker)].sort(([a], [b]) => (a < b ? -1 : 1))) {
        const found = collect(checker, handler);
        const reports: Schema[] = [];
        const summaries: Schema[] = [];
        // Under --summary a call without a summary prints its full report, so
        // the summary shape of an invocation is, call by call, the summary or
        // else the report.
        const withSummary = found.reports.some((call) => call.arguments[3] !== undefined);
        for (const call of found.reports) {
            const [, value, , summary] = call.arguments;
            const report = value === undefined ? {} : writer.schema(checker.getTypeAtLocation(value));
            reports.push(report);
            if (!withSummary) continue;
            const signature = summary === undefined ? undefined : checker.getTypeAtLocation(summary).getCallSignatures()[0];
            summaries.push(signature === undefined ? report : writer.schema(signature.getReturnType()));
        }
        const outputs: InvocationShape['outputs'][number][] = [];
        if (found.reports.length > 0) outputs.push('report');
        if (found.artifact) outputs.push('artifact');
        if (invocation === 'schema') outputs.push('document');
        if (invocation === 'completion') outputs.push('script');
        const status: Record<string, Schema> = {};
        for (const key of [...found.status.keys()].sort()) {
            status[key] = dedupe((found.status.get(key) ?? []).map((e) => writer.schema(checker.getTypeAtLocation(e)))) ?? {};
        }
        const report = dedupe(reports);
        const summary = dedupe(summaries);
        invocations[invocation] = { outputs, ...(report !== undefined ? { report } : {}), ...(summary !== undefined ? { summary } : {}), status };
    }
    const defs = Object.fromEntries(Object.entries(writer.defs).sort(([a], [b]) => (a < b ? -1 : 1)));
    const lines = [
        '// GENERATED by scripts/build-report-schemas.ts from the TypeScript types of every',
        '// report, --summary shape and envelope status field — do not edit; run',
        '// npm run schemas:build. One line per type and per invocation.',
        '',
        'export interface InvocationShape {',
        "    readonly outputs: readonly ('report' | 'artifact' | 'document' | 'script')[];",
        '    readonly report?: object;',
        '    readonly summary?: object;',
        '    readonly status: Readonly<Record<string, object>>;',
        '}',
        '',
        '/** Named types the schemas reference as #/$defs/<name>. */',
        'export const REPORT_DEFS: Readonly<Record<string, object>> = {',
        ...Object.entries(defs).map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`),
        '};',
        '',
        '/** Every invocation of the CLI and what it prints. */',
        'export const INVOCATIONS: Readonly<Record<string, InvocationShape>> = {',
        ...Object.entries(invocations).map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)},`),
        '};',
        '',
    ];
    return lines.join('\n');
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(import.meta.filename)) {
    const text = generateReportSchemas();
    const path = join(ROOT, OUT);
    if (process.argv.includes('--check')) {
        let current = '';
        try {
            current = readFileSync(path, 'utf8');
        } catch {
            // missing counts as stale
        }
        if (current !== text) {
            process.stderr.write(`${OUT} is stale: run npm run schemas:build\n`);
            process.exitCode = 1;
        }
    } else {
        writeFileSync(path, text);
        process.stdout.write(`wrote ${OUT} (${text.length} bytes)\n`);
    }
}
