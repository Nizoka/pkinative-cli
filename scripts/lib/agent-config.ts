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
