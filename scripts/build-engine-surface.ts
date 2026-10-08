// Writes tests/regression/engine-surface.json: every bullet of pkinative's
// 1.0.0 CHANGELOG entry (docs/data/pkinative/changelog-1.0.0.md) mapped to the
// CLI tests that exercise it, or to a typed waiver. "A release of the engine
// that the CLI's tests do not exercise is a release the CLI has not adopted."
//   npx tsx scripts/build-engine-surface.ts [--check]

import { readFileSync, writeFileSync } from 'node:fs';
import { changelogBullets } from './lib/changelog.ts';

type Test = readonly [file: string, name: string];
type Item = { tests: readonly Test[] } | { waiver: 'LIB' | 'TOOLING' | 'DOCS'; note: string } | { waiver: 'tested-upstream'; note: string; tests: readonly Test[] };

const CERT = 'tests/commands/cert.test.ts';
const CHAIN = 'tests/commands/chain.test.ts';
const REV = 'tests/commands/revocation.test.ts';
const KEYS = 'tests/commands/keys.test.ts';
const SIG = 'tests/commands/signatures.test.ts';
const ENC = 'tests/commands/encodings.test.ts';
const META = 'tests/commands/meta.test.ts';

/** The decision for each bullet, by its 1-based position in the entry. */
const MAP: Readonly<Record<number, Item>> = {
    1: { tests: [[KEYS, 'bounds the PBKDF2 work of a whole PKCS#12']] },
    2: { waiver: 'tested-upstream', note: 'crl check passes signatureVerified only when --issuer verified the CRL', tests: [[REV, 'checks a certificate against the CRL']] },
    3: { waiver: 'tested-upstream', note: 'cert check-name forwards --chain as CheckServerNameOptions.path', tests: [[CERT, 'checks DNS names, wildcards and IP addresses']] },
    4: { waiver: 'tested-upstream', note: 'id-RSASSA-PSS keys sign through the signer', tests: [[CERT, 'signs with an id-RSASSA-PSS key by RSA-PSS only']] },
    5: { waiver: 'tested-upstream', note: 'chain verify reports NO_TRUST_ANCHOR from the engine', tests: [[CHAIN, 'fails an expired path, a wrong name, a wrong purpose, a missing anchor']] },
    6: { waiver: 'LIB', note: 'CRL issuer validation inside verifyCertificateChain; the CLI passes --crl bytes unchanged' },
    7: { waiver: 'tested-upstream', note: 'chain --policy is the initial policy set', tests: [[CHAIN, 'applies the policy inputs']] },
    8: { waiver: 'LIB', note: 'RSA exponent policy inside the engine' },
    9: { waiver: 'LIB', note: 'tsp verify forwards --allow-sha1 as allowSha1 and nothing else' },
    10: { waiver: 'LIB', note: 'PBMAC1 key length check inside verifyPkcs12Mac' },
    11: { waiver: 'LIB', note: 'the CLI signer always names the curve (utils/signer.ts)' },
    12: { tests: [['tests/utils/pki-input.test.ts', 'caps PKI reads by --max-input-bytes and content reads by --max-content-size']] },
    13: { waiver: 'tested-upstream', note: 'the CLI caps --shake256 at 1 MiB and nonces by the engine', tests: [[ENC, 'computes SHAKE256 of any length'], [REV, 'builds a request, with nonces and hashes, and its CertID']] },
    14: { waiver: 'LIB', note: 'path and revocation rules inside the engine' },
    15: { waiver: 'LIB', note: 'parser differentials inside the engine' },
    16: { waiver: 'TOOLING', note: 'engine CVE-class corpus' },
    17: { tests: [['tests/utils/pkierr.test.ts', 'maps exactly the 57 codes of the pinned registry'], ['tests/docs/surface.test.ts', 'reaches every one of the 294 exports']] },
    18: { tests: [['tests/utils/wire.test.ts', 'converts bigint, bytes, numbers and omits absent members']] },
    19: { tests: [['tests/docs/surface.test.ts', 'imports pkinative through core-bridge only']] },
    20: { tests: [[CERT, 'decodes a subjectDirectoryAttributes value']] },
    21: { tests: [[CERT, 'inspects a request'], [CERT, 'verifies a request, and fails on a tampered one']] },
    22: { tests: [[ENC, 'reads null, enumerated, relative-oid and refuses a wrong type'], [ENC, 'encodes content octets, TLV and relative OIDs']] },
    23: { tests: [[ENC, 'computes SHAKE256 of any length']] },
    24: { tests: [[SIG, 'routes the diagnostics of a verdict to the envelope']] },
    25: { waiver: 'LIB', note: 'name diagnostics emitted by the engine, routed like every diagnostic' },
    26: { tests: [[CERT, 'signs with an id-RSASSA-PSS key by RSA-PSS only']] },
    27: { tests: [[SIG, 'signs and verifies CMS with an Ed448 signer']] },
    28: { waiver: 'TOOLING', note: 'engine interop matrix' },
    29: { waiver: 'TOOLING', note: 'engine fuzzing' },
    30: { waiver: 'TOOLING', note: 'engine requirement inventories' },
    31: { waiver: 'TOOLING', note: 'engine tarball checks' },
    32: { waiver: 'TOOLING', note: 'engine guide compilation' },
    33: { waiver: 'TOOLING', note: 'engine site accessibility' },
    34: { waiver: 'TOOLING', note: 'engine advisory Node.js 26 workflow' },
    35: { waiver: 'DOCS', note: 'engine standards guide' },
    36: { tests: [[KEYS, 'needs a scheme for an RSA key, and reports failures by class']] },
    37: { waiver: 'LIB', note: 'string types chosen by encodeNameAttribute; the CLI passes stringType through' },
    38: { waiver: 'LIB', note: 'RSASSA-PSS AlgorithmIdentifier encoding inside the engine' },
    39: { waiver: 'TOOLING', note: 'engine release path' },
    40: { waiver: 'TOOLING', note: 'engine CI' },
    41: { tests: [[META, 'reports on both sides of the Node.js floor'], [META, 'evaluates ^, >= and exact clauses']] },
    42: { waiver: 'DOCS', note: 'engine release history' },
    43: { tests: [[CERT, 'escalates the first engine warning to E_CHECK_FAILED']] },
    44: { waiver: 'LIB', note: 'lazy signature verification inside verifyCertificateChain' },
    45: { waiver: 'LIB', note: 'delegated responder timing inside checkOcspStatus' },
    46: { waiver: 'TOOLING', note: 'engine API snapshot classifier' },
    47: { tests: [['tests/docs/surface.test.ts', 'vendors the v1.0.0 registries at schemaVersion 1']] },
    48: { waiver: 'LIB', note: 'verdict corrections inside the engine' },
    49: { waiver: 'DOCS', note: 'engine SECURITY.md' },
    50: { waiver: 'LIB', note: 'string diagnostics inside the engine' },
    51: { waiver: 'LIB', note: 'reason paths produced by the engine, printed unchanged' },
    52: { waiver: 'LIB', note: 'KEY_USAGE_BITS immutability inside the engine' },
    53: { tests: [[KEYS, 'converts legacy PKCS#12 with the two-step OpenSSL remedy (engine 1.0.0 item 53)']] },
    54: { waiver: 'TOOLING', note: 'engine interop limitations' },
    55: { waiver: 'DOCS', note: 'engine prose' },
};

const bullets = changelogBullets(readFileSync('docs/data/pkinative/changelog-1.0.0.md', 'utf8'));
const doc = {
    $comment: 'Generated by scripts/build-engine-surface.ts; held by tests/regression/engine-surface.test.ts.',
    engine: '1.0.0',
    items: bullets.map((b, i) => {
        const item = MAP[i + 1];
        if (item === undefined) throw new Error(`bullet ${i + 1} has no decision: ${b.title}`);
        const tests = 'tests' in item ? item.tests.map(([file, name]) => ({ file, name })) : undefined;
        return { id: i + 1, section: b.section, bullet: b.title, ...('waiver' in item ? { waiver: item.waiver, note: item.note } : {}), ...(tests !== undefined ? { tests } : {}) };
    }),
};
const text = JSON.stringify(doc, null, 2) + '\n';
const PATH = 'tests/regression/engine-surface.json';
if (process.argv.includes('--check')) {
    if (readFileSync(PATH, 'utf8') !== text) {
        process.stderr.write(`${PATH} is stale: run npx tsx scripts/build-engine-surface.ts\n`);
        process.exit(1);
    }
} else {
    writeFileSync(PATH, text);
    process.stdout.write(`wrote ${PATH} (${doc.items.length} items)\n`);
}
