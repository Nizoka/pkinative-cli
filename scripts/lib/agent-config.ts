// Pure checks over the repository's agent configuration and line endings,
// shared by scripts/verify-docs.ts (the rules) and tests/tools/scripts.test.ts
// (the fixtures). Nothing here reads the file system or spawns a process: the
// caller hands the text in and gets findings (strings) back.

// ── eol-lf ───────────────────────────────────────────────────────────

export interface EolEntry {
    /** `i/lf`, `i/crlf`, `i/mixed`, `i/none` or `i/-text`: the blob in the index. */
    readonly index: string;
    /** The working-tree form, ignored by the rule (an autocrlf checkout may show CRLF over a correct blob). */
    readonly worktree: string;
    /** The attributes `git ls-files --eol` prints after `attr/`. */
    readonly attrs: string;
    readonly path: string;
}

/** Parse the table `git ls-files --eol` prints, one entry per tracked path. */
export function parseLsFilesEol(output: string): EolEntry[] {
    const out: EolEntry[] = [];
    for (const line of output.replace(/\r\n/g, '\n').split('\n')) {
        const m = /^(i\/\S+)\s+(w\/\S+)\s+(attr\/[^\t]*)\t(.+)$/.exec(line);
        if (m !== null) out.push({ index: m[1] ?? '', worktree: m[2] ?? '', attrs: (m[3] ?? '').slice('attr/'.length).trim(), path: m[4] ?? '' });
    }
    return out;
}

/** Tracked files whose blob is CRLF or mixed although nothing declares them `-text` or binary. */
export function crlfTextFiles(entries: readonly EolEntry[]): EolEntry[] {
    return entries.filter((e) => (e.index === 'i/crlf' || e.index === 'i/mixed') && !/(?:^|\s)-text(?:\s|$)/.test(e.attrs) && !/\bbinary\b/.test(e.attrs));
}

// ── agents: settings, hook and governance in agreement ───────────────

/** The shell tools the guard hook covers; a deny family must exist once per tool, a family denied for one and allowed for the other is not denied. */
export const GUARDED_SHELL_TOOLS = ['Bash', 'PowerShell'] as const;
/** The maintainer's acts that `permissions.deny` refuses beside the hook (.github/AGENT_RULES.md §5). */
export const HITL_DENY_FAMILIES = ['npm publish', 'git push', 'gh pr create', 'gh issue create', 'gh release'] as const;
/** The generated or vendored paths CLAUDE.md says are never read; each needs its `Read(...)` deny. */
export const READ_DENIES = ['Read(package-lock.json)', 'Read(coverage/**)', 'Read(dist/**)', 'Read(test-output/**)', 'Read(node_modules/**)', 'Read(docs/data/pkinative/api.frozen.json)'] as const;

interface ClaudeSettings {
    readonly attribution?: { readonly commit?: unknown; readonly pr?: unknown };
    readonly permissions?: { readonly deny?: unknown };
    readonly hooks?: { readonly PreToolUse?: unknown };
    readonly env?: Readonly<Record<string, unknown>>;
}

interface GovernanceClaudeCode {
    readonly settings?: unknown;
    readonly hooks?: ReadonlyArray<{ readonly matcher?: unknown; readonly command?: unknown }>;
    readonly attribution?: unknown;
    readonly env_limits?: unknown;
    readonly skills?: ReadonlyArray<{ readonly path?: unknown }>;
}

export interface AgentConfigInput {
    readonly settingsText: string | null;
    readonly governanceText: string | null;
    readonly claudeMd: string;
    readonly hook: { readonly exists: boolean; readonly checkStatus: number | null; readonly checkStderr: string };
    readonly fileExists: (path: string) => boolean;
}

/** The `claude_code` object of ai-governance.json, wherever it sits. */
function claudeCodeOf(node: unknown): GovernanceClaudeCode | null {
    if (node === null || typeof node !== 'object') return null;
    for (const [key, value] of Object.entries(node)) {
        if (key === 'claude_code' && value !== null && typeof value === 'object') return value as GovernanceClaudeCode;
        const found = claudeCodeOf(value);
        if (found !== null) return found;
    }
    return null;
}

function parseJson<T>(text: string, file: string, out: string[]): T | null {
    try {
        return JSON.parse(text) as T;
    } catch (err) {
        out.push(`${file}: not valid JSON — ${(err as Error).message}`);
        return null;
    }
}

/** settings.json, the hook and ai-governance.json say the same thing; the hook loads. */
export function checkAgentConfig(input: AgentConfigInput): string[] {
    const SETTINGS = '.claude/settings.json';
    const HOOK = '.claude/hooks/guard.mjs';
    const GOVERNANCE = '.github/ai-governance.json';
    const out: string[] = [];
    if (input.settingsText === null) return [`${SETTINGS}: missing — it carries the deny list and the guard hook`];
    const settings = parseJson<ClaudeSettings>(input.settingsText, SETTINGS, out);
    if (settings === null) return out;
    if (settings.attribution?.commit !== '' || settings.attribution?.pr !== '') out.push(`${SETTINGS}: attribution.commit and attribution.pr must both be ""`);
    const deny = Array.isArray(settings.permissions?.deny) ? settings.permissions.deny.filter((d): d is string => typeof d === 'string') : [];
    for (const entry of READ_DENIES) {
        if (!deny.includes(entry)) out.push(`${SETTINGS}: deny lacks ${entry}`);
        const path = entry.slice('Read('.length, -1).replace(/\/\*\*$/, '/');
        if (!input.claudeMd.includes(`\`${path}\``)) out.push(`CLAUDE.md does not name \`${path}\` among the paths never read`);
    }
    for (const tool of GUARDED_SHELL_TOOLS) {
        for (const family of HITL_DENY_FAMILIES) {
            if (!deny.some((d) => d.startsWith(`${tool}(${family}`))) out.push(`${SETTINGS}: deny lacks ${tool}(${family}…) — the HITL gate is enforced twice, by the deny list and by the hook, once per shell tool`);
        }
    }
    const pre = Array.isArray(settings.hooks?.PreToolUse) ? (settings.hooks.PreToolUse as ReadonlyArray<{ matcher?: unknown; hooks?: ReadonlyArray<{ command?: unknown }> }>) : [];
    const guarded = pre.filter((h) => (h.hooks ?? []).some((x) => typeof x.command === 'string' && x.command.includes('guard.mjs')));
    const matchers = new Set(guarded.flatMap((h) => (typeof h.matcher === 'string' ? h.matcher.split('|') : [])));
    for (const tool of GUARDED_SHELL_TOOLS) {
        if (!matchers.has(tool)) out.push(`${SETTINGS}: hooks.PreToolUse has no ${tool} matcher running ${HOOK} — a shell tool without the hook is a door around the guard`);
    }
    const command = guarded.map((h) => (h.hooks ?? []).find((x) => typeof x.command === 'string' && x.command.includes('guard.mjs'))?.command).find((c): c is string => typeof c === 'string') ?? '';
    if (!command.includes('$CLAUDE_PROJECT_DIR/')) out.push(`${SETTINGS}: the hook command must reach ${HOOK} through $CLAUDE_PROJECT_DIR (a relative path stops guarding once the shell leaves the root)`);
    if (!input.hook.exists) out.push(`${HOOK}: missing — settings.json wires it as the PreToolUse hook`);
    else if (input.hook.checkStatus !== 0) out.push(`${HOOK}: node --check fails (exit ${input.hook.checkStatus ?? 'null'}) — a broken hook refuses every shell call: ${input.hook.checkStderr.trim().split('\n')[0] ?? ''}`);
    if (input.governanceText === null) return [...out, `${GOVERNANCE}: missing`];
    const governance = parseJson<unknown>(input.governanceText, GOVERNANCE, out);
    if (governance === null) return out;
    const manifest = claudeCodeOf(governance);
    if (manifest === null) return [...out, `${GOVERNANCE}: no claude_code manifest`];
    if (manifest.settings !== SETTINGS) out.push(`${GOVERNANCE}: claude_code.settings is not ${SETTINGS}`);
    const first = manifest.hooks?.[0];
    const matcherText = guarded.map((h) => h.matcher).find((m): m is string => typeof m === 'string') ?? '';
    if (typeof first?.matcher !== 'string' || !first.matcher.startsWith(matcherText)) out.push(`${GOVERNANCE}: claude_code.hooks[0].matcher does not start with the settings matcher "${matcherText}"`);
    if (typeof first?.command !== 'string' || !first.command.startsWith(command)) out.push(`${GOVERNANCE}: claude_code.hooks[0].command does not start with the settings command`);
    if (JSON.stringify(manifest.attribution) !== JSON.stringify(settings.attribution)) out.push(`${GOVERNANCE}: claude_code.attribution differs from settings.json`);
    if (JSON.stringify(manifest.env_limits) !== JSON.stringify(settings.env)) out.push(`${GOVERNANCE}: claude_code.env_limits differs from settings.json env`);
    for (const skill of manifest.skills ?? []) {
        if (typeof skill.path !== 'string' || !input.fileExists(skill.path)) out.push(`${GOVERNANCE}: skill path ${String(skill.path)} does not exist`);
    }
    return out;
}

// ── agent-budget: what every session loads ────────────────────────────

/** Bytes CLAUDE.md plus its imports plus every unscoped rule may load into every session. */
export const CLAUDE_CONTEXT_BUDGET = 16 * 1024;
/** Lines of CLAUDE.md and of AGENTS.md: a longer always-loaded file belongs in a scoped rule. */
export const INSTRUCTION_LINE_BUDGET = 120;
/** Bytes of .github/copilot-instructions.md, which Copilot loads on every request. */
export const COPILOT_BYTES_BUDGET = 16 * 1024;
/** A scoped rule above this taxes every task that touches its paths: split the instruction file. */
export const SCOPED_RULE_BYTES_BUDGET = 32 * 1024;

/** The `@file` imports of CLAUDE.md (a line that is only `@path`). */
export function claudeImports(claudeMd: string): string[] {
    return claudeMd.replace(/\r\n/g, '\n').split('\n').map((l) => /^@(\S+)\s*$/.exec(l)?.[1]).filter((p): p is string => p !== undefined);
}

/** True when a rule declares a non-empty `paths:` scope (an unscoped rule loads on every session). */
export function ruleHasPaths(text: string): boolean {
    const m = /^---\n([\s\S]*?)\n---/.exec(text.replace(/\r\n/g, '\n'));
    if (m === null) return false;
    const block = m[1] ?? '';
    const start = block.search(/^paths:/m);
    if (start === -1) return false;
    const rest = block.slice(start + 'paths:'.length);
    return /\S/.test(rest.split(/\n(?=[A-Za-z])/)[0] ?? '');
}

export interface AgentBudgetInput {
    readonly claudeMd: string;
    readonly resolveImport: (name: string) => string | null;
    readonly copilot: string | null;
    readonly rules: Readonly<Record<string, string>>;
}

export function checkAgentBudgets(input: AgentBudgetInput): string[] {
    const out: string[] = [];
    const lines = (text: string): number => text.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n').length;
    const firstLine = input.claudeMd.replace(/\r\n/g, '\n').split('\n').find((l) => l.trim() !== '') ?? '';
    if (firstLine !== '@AGENTS.md') out.push('CLAUDE.md: the first line must be @AGENTS.md (one always-loaded source)');
    if (lines(input.claudeMd) > INSTRUCTION_LINE_BUDGET) out.push(`CLAUDE.md: ${lines(input.claudeMd)} lines — the budget is ${INSTRUCTION_LINE_BUDGET}; move detail to a scoped rule`);
    const parts: Array<{ name: string; bytes: number }> = [{ name: 'CLAUDE.md', bytes: Buffer.byteLength(input.claudeMd, 'utf8') }];
    for (const name of claudeImports(input.claudeMd)) {
        const text = input.resolveImport(name);
        if (text === null) {
            out.push(`CLAUDE.md imports @${name}, which does not exist`);
            continue;
        }
        parts.push({ name, bytes: Buffer.byteLength(text, 'utf8') });
        if (lines(text) > INSTRUCTION_LINE_BUDGET) out.push(`${name}: ${lines(text)} lines — the budget is ${INSTRUCTION_LINE_BUDGET}; move detail to a scoped rule`);
    }
    if (input.copilot !== null && Buffer.byteLength(input.copilot, 'utf8') > COPILOT_BYTES_BUDGET) out.push(`.github/copilot-instructions.md: ${Buffer.byteLength(input.copilot, 'utf8')} bytes — the budget is ${COPILOT_BYTES_BUDGET}`);
    for (const [name, text] of Object.entries(input.rules).sort()) {
        const bytes = Buffer.byteLength(text, 'utf8');
        if (!ruleHasPaths(text)) {
            parts.push({ name: `.claude/rules/${name}`, bytes });
            out.push(`.claude/rules/${name}: no paths: scope — an unscoped rule loads on every session; generate it from an instruction file with applyTo`);
        } else if (bytes > SCOPED_RULE_BYTES_BUDGET) {
            out.push(`.claude/rules/${name}: ${bytes} bytes — a scoped rule over ${SCOPED_RULE_BYTES_BUDGET} taxes every task that touches its paths; split the instruction file`);
        }
    }
    const total = parts.reduce((n, p) => n + p.bytes, 0);
    if (total > CLAUDE_CONTEXT_BUDGET) out.push(`CLAUDE.md: ${total} bytes always loaded (${parts.map((p) => `${p.name} ${p.bytes}`).join(', ')}) — the budget is ${CLAUDE_CONTEXT_BUDGET}; move detail to a scoped rule`);
    return out;
}
