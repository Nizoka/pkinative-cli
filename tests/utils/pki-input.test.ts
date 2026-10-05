import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { LABELS, decodePemBlocks, looksLikePem, readContentBytes, readPkiBundle, readPkiObject, readPkiObjects } from '../../src/utils/pki-input.js';
import { makeCtx } from '../helpers/ctx.js';
import { emptyDir, fixture, fixtureBytes } from '../helpers/io.js';

describe('looksLikePem', () => {
    it('sniffs PEM after a BOM and whitespace, and nothing else', () => {
        const enc = (s: string) => new TextEncoder().encode(s);
        expect(looksLikePem(enc('-----BEGIN X-----'))).toBe(true);
        expect(looksLikePem(enc('﻿ \r\n\t-----BEGIN X'))).toBe(true);
        expect(looksLikePem(enc('-----BEGIN'))).toBe(false);
        expect(looksLikePem(enc('  -----END X'))).toBe(false);
        expect(looksLikePem(fixtureBytes('leaf.crt.der'))).toBe(false);
        expect(looksLikePem(new Uint8Array())).toBe(false);
        expect(looksLikePem(enc('-----BEGIN '))).toBe(true);
        expect(looksLikePem(enc('   '))).toBe(false);
    });

    it('skips a BOM only when all three of its bytes are there', () => {
        const begin = new TextEncoder().encode('-----BEGIN X');
        const after = (prefix: number[]) => Uint8Array.from([...prefix, ...begin]);
        expect(looksLikePem(after([0xef, 0xbb, 0xbf]))).toBe(true);
        expect(looksLikePem(after([0xef, 0x00, 0x00]))).toBe(false);
        expect(looksLikePem(after([0x00, 0xbb, 0xbf]))).toBe(false);
        expect(looksLikePem(after([0x00, 0x00, 0xbf]))).toBe(false);
        expect(looksLikePem(after([0xef, 0xbb, 0x00]))).toBe(false);
    });
});

describe('readPkiObjects', () => {
    it('reads DER as one object and PEM by label', async () => {
        const ctx = makeCtx();
        const [der] = await readPkiObjects(ctx, fixture('leaf.crt.der'), 'certificate', LABELS.certificate);
        expect(der).toMatchObject({ label: undefined, source: fixture('leaf.crt.der') });
        const [pem] = await readPkiObjects(ctx, fixture('leaf.crt.pem'), 'certificate', LABELS.certificate);
        expect(pem?.der).toEqual(der?.der);
        expect(pem?.label).toBe('CERTIFICATE');
    });

    it('reads from stdin and accepts any label with an empty list', async () => {
        const ctx = makeCtx([], { stdin: readFileSync(fixture('leaf.key.pem'), 'utf8') });
        const [obj] = await readPkiObjects(ctx, '-', 'key', LABELS.any);
        expect(obj).toMatchObject({ label: 'PRIVATE KEY', source: 'stdin' });
    });

    it('refuses a PEM file without a matching block, naming the labels present', async () => {
        await expect(readPkiObjects(makeCtx(), fixture('leaf.key.pem'), 'certificate', LABELS.certificate)).rejects.toMatchObject({
            code: 'E_INPUT', pkiCode: 'PKI_PEM_UNEXPECTED_LABEL', message: expect.stringMatching(/labels present: PRIVATE KEY/),
        });
    });

    it('maps a malformed PEM to E_PARSE and honours --pem-mode lax', async () => {
        const dir = emptyDir();
        const pem = readFileSync(fixture('leaf.crt.pem'), 'utf8').replace(/\n(?=[A-Za-z0-9+/])/, '\n  ');
        writeFileSync(join(dir, 'ws.pem'), pem);
        await expect(readPkiObjects(makeCtx(), join(dir, 'ws.pem'), 'certificate', LABELS.certificate)).rejects.toMatchObject({ code: 'E_PARSE' });
        await expect(readPkiObjects(makeCtx(['--pem-mode', 'lax']), join(dir, 'ws.pem'), 'certificate', LABELS.certificate)).resolves.toHaveLength(1);
    });
});

describe('readPkiObject / readPkiBundle', () => {
    it('refuses a bundle where one object is expected', async () => {
        const dir = emptyDir();
        const bundle = join(dir, 'chain.pem');
        writeFileSync(bundle, readFileSync(fixture('leaf.crt.pem'), 'utf8') + readFileSync(fixture('inter.crt.pem'), 'utf8'));
        await expect(readPkiObject(makeCtx(), bundle, 'certificate', LABELS.certificate)).rejects.toMatchObject({
            code: 'E_INPUT', message: expect.stringMatching(/holds 2 CERTIFICATE/),
        });
        const all = await readPkiBundle(makeCtx(), [bundle, fixture('root.crt.der')], 'certificate', LABELS.certificate);
        expect(all).toHaveLength(3);
        await expect(readPkiObject(makeCtx(), fixture('root.crt.pem'), 'certificate', LABELS.certificate)).resolves.toMatchObject({ label: 'CERTIFICATE' });
    });

    it('caps PKI reads by --max-input-bytes and content reads by --max-content-size', async () => {
        await expect(readPkiObject(makeCtx(['--max-input-bytes', '100']), fixture('leaf.crt.der'), 'certificate', LABELS.certificate))
            .rejects.toMatchObject({ code: 'E_LIMIT', remedy: expect.stringMatching(/--max-input-bytes/) });
        await expect(readContentBytes(makeCtx(['--max-content-size', '4']), fixture('content.txt'), 'content'))
            .rejects.toMatchObject({ code: 'E_LIMIT', remedy: expect.stringMatching(/--max-content-size/) });
        await expect(readContentBytes(makeCtx(), fixture('content.txt'), 'content')).resolves.toHaveLength(27);
    });

    it('decodes PEM blocks with the engine', () => {
        expect(decodePemBlocks(makeCtx(), fixtureBytes('leaf.crt.pem'), 'x')).toHaveLength(1);
    });
});
