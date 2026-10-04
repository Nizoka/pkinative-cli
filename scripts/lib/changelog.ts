export interface Bullet {
    readonly section: string;
    /** The bullet's first 100 characters, emphasis markers removed. */
    readonly title: string;
}

/** The top-level bullets of a Keep a Changelog entry, with their section. */
export function changelogBullets(markdown: string): Bullet[] {
    const out: Bullet[] = [];
    let section = '';
    for (const line of markdown.split('\n')) {
        const heading = /^### (\w+)/.exec(line);
        if (heading !== null) {
            section = heading[1] as string;
            continue;
        }
        if (line.startsWith('- ')) {
            out.push({ section, title: line.slice(2).replace(/\*\*/g, '').slice(0, 100) });
        }
    }
    return out;
}
