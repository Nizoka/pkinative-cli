/** mulberry32: a small seeded PRNG, so every fuzz failure reproduces from its seed. */
export function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

export function pick<T>(rand: () => number, items: readonly T[]): T {
    return items[Math.floor(rand() * items.length)] as T;
}

/** A hostile variant of `bytes`: bit flips, truncation, length-byte damage or insertion. */
export function mutate(rand: () => number, bytes: Uint8Array): Uint8Array {
    const out = Uint8Array.from(bytes);
    switch (Math.floor(rand() * 5)) {
        case 0: {
            for (let i = 0; i < 1 + Math.floor(rand() * 4); i++) {
                const at = Math.floor(rand() * out.length);
                out[at] = (out[at] as number) ^ (1 << Math.floor(rand() * 8));
            }
            return out;
        }
        case 1: return out.subarray(0, Math.floor(rand() * out.length));
        case 2: {
            // Damage a length octet: the byte after a likely tag.
            const at = 1 + Math.floor(rand() * Math.min(out.length - 1, 64));
            out[at] = pick(rand, [0x00, 0x7f, 0x80, 0x81, 0x84, 0xff]);
            return out;
        }
        case 3: {
            const at = Math.floor(rand() * out.length);
            const junk = Uint8Array.from({ length: 1 + Math.floor(rand() * 16) }, () => Math.floor(rand() * 256));
            return Uint8Array.from([...out.subarray(0, at), ...junk, ...out.subarray(at)]);
        }
        default: return Uint8Array.from({ length: Math.floor(rand() * 64) }, () => Math.floor(rand() * 256));
    }
}
