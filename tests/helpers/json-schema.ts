// A minimal JSON Schema (draft 2020-12) validator for the tests, so the schemas
// `pkinative schema report …` publishes are held to what the CLI prints without
// a validator dependency. It covers exactly the keywords the generator emits:
// type, const, enum, pattern, properties, required, additionalProperties,
// items, prefixItems, anyOf, oneOf, not and $ref into the root's $defs.

type Schema = Readonly<Record<string, unknown>> | boolean;

function typeOf(value: unknown): string {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
    return typeof value;
}

function typeMatches(value: unknown, type: string): boolean {
    const actual = typeOf(value);
    return actual === type || (type === 'number' && actual === 'integer');
}

/** Every violation of `schema` by `value`, as `<path>: <reason>`; empty when it validates. */
export function validate(value: unknown, schema: Schema, defs: Readonly<Record<string, unknown>> = {}, path = '$'): string[] {
    if (schema === true) return [];
    if (schema === false) return [`${path}: no value is allowed here`];
    const s = schema;
    const errors: string[] = [];
    if (typeof s['$ref'] === 'string') {
        const name = (s['$ref']).replace(/^#\/\$defs\//, '');
        const target = defs[name];
        if (target === undefined) return [`${path}: unresolved ${s['$ref']}`];
        return validate(value, target as Schema, defs, path);
    }
    if (s['type'] !== undefined) {
        const types = Array.isArray(s['type']) ? (s['type'] as string[]) : [s['type'] as string];
        if (!types.some((t) => typeMatches(value, t))) return [`${path}: expected ${types.join('|')}, got ${typeOf(value)}`];
    }
    if ('const' in s && JSON.stringify(value) !== JSON.stringify(s['const'])) errors.push(`${path}: expected ${JSON.stringify(s['const'])}`);
    if (Array.isArray(s['enum']) && !s['enum'].some((e) => JSON.stringify(e) === JSON.stringify(value))) errors.push(`${path}: ${JSON.stringify(value)} is not one of ${JSON.stringify(s['enum'])}`);
    if (typeof s['pattern'] === 'string' && typeof value === 'string' && !new RegExp(s['pattern']).test(value)) errors.push(`${path}: "${value.slice(0, 40)}" does not match ${s['pattern']}`);
    if (Array.isArray(s['anyOf']) && !s['anyOf'].some((sub) => validate(value, sub as Schema, defs, path).length === 0)) {
        errors.push(`${path}: matches none of anyOf (${(s['anyOf'] as Schema[]).map((sub) => validate(value, sub, defs, path)[0] ?? 'ok').join(' / ')})`);
    }
    if (Array.isArray(s['oneOf']) && s['oneOf'].filter((sub) => validate(value, sub as Schema, defs, path).length === 0).length !== 1) errors.push(`${path}: does not match exactly one of oneOf`);
    if (s['not'] !== undefined && validate(value, s['not'] as Schema, defs, path).length === 0) errors.push(`${path}: matches a "not" schema`);
    if (typeOf(value) === 'object') {
        const obj = value as Record<string, unknown>;
        const properties = (s['properties'] ?? {}) as Record<string, Schema>;
        for (const key of (s['required'] ?? []) as string[]) if (!(key in obj)) errors.push(`${path}: missing required "${key}"`);
        for (const [key, v] of Object.entries(obj)) {
            const sub = properties[key];
            if (sub !== undefined) errors.push(...validate(v, sub, defs, `${path}.${key}`));
            else if (s['additionalProperties'] !== undefined) errors.push(...validate(v, s['additionalProperties'] as Schema, defs, `${path}.${key}`));
        }
    }
    if (Array.isArray(value)) {
        const prefix = (s['prefixItems'] ?? []) as Schema[];
        value.forEach((item, i) => {
            const sub = i < prefix.length ? prefix[i] : (s['items'] as Schema | undefined);
            if (sub !== undefined) errors.push(...validate(item, sub, defs, `${path}[${i}]`));
        });
    }
    return errors;
}
