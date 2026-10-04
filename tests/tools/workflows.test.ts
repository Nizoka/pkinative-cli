import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// ── Workflow, supply-chain and contributor invariants ─────────────────
//
// None of this is visible to the type checker or to the suite proper: a
// floating action tag, a checkout that keeps the job token, a release job that
// publishes a 0.x version, an npm client that drifts between two publishes, a
// required check nothing reports. Each is locked here as a plain-text
// assertion on the files that carry it. Ported from pkinative's
// tests/tools/workflows.test.ts.

const ROOT = process.cwd();
const WORKFLOWS = join(ROOT, '.github', 'workflows');
const workflowFiles = readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml')).sort();
// Every assertion is a regex over file text: a CRLF checkout would mismatch
// them all silently, so line endings are normalised on the way in.
const lf = (text: string): string => text.replace(/\r\n/g, '\n');
const readWorkflow = (f: string): string => lf(readFileSync(join(WORKFLOWS, f), 'utf8'));
const readText = (...parts: string[]): string => lf(readFileSync(join(ROOT, ...parts), 'utf8'));

const HARDEN_RUNNER = 'step-security/harden-runner@';

/** Every step block of every job, in order, keyed by job id. */
function jobSteps(text: string): Map<string, string[]> {
    const jobs = new Map<string, string[]>();
    const jobsAt = text.search(/^jobs:\s*$/m);
    if (jobsAt < 0) return jobs;
    let job: string | null = null;
    let steps: string[] | null = null;
    for (const line of text.slice(jobsAt).split('\n').slice(1)) {
        const jobHead = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
        if (jobHead) { job = jobHead[1] ?? null; steps = null; continue; }
        if (/^ {4}steps:\s*$/.test(line) && job) { steps = []; jobs.set(job, steps); continue; }
        if (steps === null) continue;
        if (/^ {6}- /.test(line)) steps.push(line);
        else if (/^ {8,}\S/.test(line) && steps.length > 0) steps[steps.length - 1] += `\n${line}`;
    }
    return jobs;
}

/** One job's text, from its head to the next job head. */
const jobBody = (text: string, job: string): string =>
    new RegExp(`^  ${job}:\\s*\\n([\\s\\S]*?)(?=^  [A-Za-z0-9_-]+:\\s*$|(?![\\s\\S]))`, 'm').exec(text)?.[1] ?? '';

/** Every check a workflow reports: the matrix `name:` values, else the job `name:`, else the job id. */
function reported(file: string): string[] {
    const text = readWorkflow(file);
    const out: string[] = [];
    for (const job of jobSteps(text).keys()) {
        const body = jobBody(text, job);
        const name = /^ {4}name:\s*(.+?)\s*$/m.exec(body)?.[1] ?? job;
        if (name === '${{ matrix.name }}') out.push(...[...body.matchAll(/^\s+- \{ name: '?([^,']+)'?,/gm)].map((m) => m[1] ?? ''));
        else out.push(name);
    }
    return out;
}

const ruleset = JSON.parse(readText('.github', 'rulesets', 'main.json')) as {
    rules: Array<{ type: string; parameters?: { required_status_checks?: Array<{ context: string; integration_id?: number }>; code_scanning_tools?: Array<Record<string, string>> } }>;
};
const required = ruleset.rules.find((r) => r.type === 'required_status_checks')?.parameters?.required_status_checks ?? [];

// ── Actions: pinned, hardened, credential-free ───────────────────────

describe('every workflow', () => {
    const allFiles = workflowFiles.map((f) => ({ label: f, text: readWorkflow(f) }));

    it('is exactly the expected set of workflow files', () => {
        // A new workflow is a new holder of tokens; it arrives with its own assertions here.
        expect(workflowFiles).toEqual([
            'audit.yml', 'ci.yml', 'codeql.yml', 'conformance.yml', 'dependency-review.yml', 'docs.yml',
            'node-current.yml', 'publish.yml', 'sample-regression.yml', 'scorecard.yml',
        ]);
    });

    it('resolves every action to a single SHA across the tree, with a version comment', () => {
        const pins = new Map<string, Set<string>>();
        for (const { label, text } of allFiles) {
            for (const m of text.matchAll(/^\s*(?:- )?uses:\s*(\S+)[^\n]*$/gm)) {
                const ref = m[1] ?? '';
                expect(ref, `${label}: ${ref}`).toMatch(/^[^@\s]+@[0-9a-f]{40}$/);
                expect(m[0], `${label}: ${ref} lacks a "# vX[.Y[.Z]]" comment`).toMatch(/#\s*v\d+(?:\.\d+){0,2}\s*$/);
                const [action, sha] = ref.split('@') as [string, string];
                const key = action.startsWith('github/codeql-action/') ? 'github/codeql-action' : action;
                pins.set(key, new Set([...(pins.get(key) ?? []), sha]));
            }
        }
        for (const [action, shas] of pins) expect([...shas], `${action} is pinned to more than one SHA`).toHaveLength(1);
    });

    it('drops the checkout credentials, grants read-only at workflow level, and times out every job', () => {
        for (const { label, text } of allFiles) {
            for (const m of text.matchAll(/uses: actions\/checkout@[^\n]*\n((?:[ \t]+[^\n]*\n)*)/g)) {
                const block = (m[1] ?? '').split('\n').filter((l) => l.trim() !== '' && !/^\s+- /.test(l));
                expect(block.some((l) => /persist-credentials:\s*false/.test(l)), `${label}: checkout keeps credentials`).toBe(true);
            }
            const top = /^permissions:[ \t]*\n((?:[ \t]+\S[^\n]*\n)*)/m.exec(text);
            expect(top, `${label}: no workflow-level permissions`).not.toBeNull();
            for (const grant of (top?.[1] ?? '').split('\n').map((l) => l.trim()).filter((l) => l !== '' && !l.startsWith('#'))) {
                expect(grant, `${label}: workflow-level write`).toMatch(/^[a-z-]+:\s*read$/);
            }
            for (const job of jobSteps(text).keys()) expect(jobBody(text, job), `${label} › ${job}`).toMatch(/timeout-minutes:\s*\d+/);
        }
    });

    it('starts every job with harden-runner: block with an allow-list, or audit with a dated reason', () => {
        for (const f of workflowFiles) {
            for (const [job, steps] of jobSteps(readWorkflow(f))) {
                const first = steps[0] ?? '';
                expect(first, `${f} › ${job}`).toContain(HARDEN_RUNNER);
                expect(first, `${f} › ${job}`).not.toMatch(/^\s+if:/m);
                if (/egress-policy:\s*block\s*$/m.test(first)) {
                    const list = /allowed-endpoints:\s*>\s*\n((?:[ \t]+[a-z0-9.-]+:\d+[ \t]*(?:\n|$))+)/.exec(first)?.[1] ?? '';
                    const endpoints = list.split('\n').map((l) => l.trim()).filter((l) => l !== '');
                    expect(endpoints.length, `${f} › ${job}`).toBeGreaterThan(0);
                    for (const e of endpoints) expect(e).toMatch(/^[a-z0-9.-]+:443$/);
                } else {
                    expect(first, `${f} › ${job}`).toMatch(/egress-policy:\s*audit\s*#\s*\d{4}-\d{2}-\d{2}:\s*\S/);
                }
            }
        }
    });

    it('blocks egress on every job whose endpoints are known', () => {
        const blocking: Record<string, string[]> = {
            'publish.yml': ['guard', 'build', 'publish', 'attest'],
            'audit.yml': ['audit'],
            'conformance.yml': ['conformance'],
            'sample-regression.yml': ['sample-regression'],
            'dependency-review.yml': ['dependency-review'],
            'docs.yml': ['verify', 'npm-drift'],
            'node-current.yml': ['node-current'],
        };
        for (const [f, jobs] of Object.entries(blocking)) {
            const steps = jobSteps(readWorkflow(f));
            for (const job of jobs) expect(steps.get(job)?.[0], `${f} › ${job}`).toMatch(/egress-policy:\s*block\s*$/m);
        }
    });

    it('installs dependencies with --ignore-scripts', () => {
        for (const f of workflowFiles) {
            for (const m of readWorkflow(f).matchAll(/run: npm ci\b[^\n]*/g)) expect(m[0], f).toContain('npm ci --ignore-scripts');
        }
    });

    it('puts no expression of the event payload inside a run: script', () => {
        // Template injection: event data reaches a script through env only.
        for (const f of workflowFiles) {
            for (const step of [...jobSteps(readWorkflow(f)).values()].flat()) {
                const run = /run: [|>]?([\s\S]*)$/.exec(step)?.[1] ?? '';
                expect(run, f).not.toMatch(/\$\{\{\s*github\.event\./);
            }
        }
    });
});

// ── The required checks ──────────────────────────────────────────────

describe('the main ruleset', () => {
    it('requires exactly the checks the blocking workflows report, all from GitHub Actions, none path-filtered', () => {
        // Both directions: a required context nothing reports blocks every
        // pull request; a blocking job nobody requires is advisory in fact.
        const blocking = ['ci.yml', 'conformance.yml', 'sample-regression.yml', 'dependency-review.yml'].flatMap(reported).filter((n) => n !== 'runtimes');
        expect(required.map((c) => c.context).sort()).toEqual(blocking.sort());
        for (const c of required) expect(c.integration_id, c.context).toBe(15368);
        for (const f of ['ci.yml', 'conformance.yml', 'sample-regression.yml', 'dependency-review.yml', 'codeql.yml']) {
            expect(readWorkflow(f), f).not.toMatch(/^\s+paths(-ignore)?:/m);
        }
    });

    it('requires CodeQL results over the workflows and the TypeScript, and waives signed commits in writing', () => {
        const scanning = ruleset.rules.find((r) => r.type === 'code_scanning')?.parameters?.code_scanning_tools ?? [];
        expect(scanning).toEqual([{ tool: 'CodeQL', security_alerts_threshold: 'high_or_higher', alerts_threshold: 'errors' }]);
        expect(ruleset.rules.some((r) => r.type === 'required_signatures')).toBe(false);
        expect(readText('CONTRIBUTING.md')).toContain('**Signed commits are not required.**');
        const codeql = readWorkflow('codeql.yml');
        expect(codeql).toMatch(/- \{ language: actions, build-mode: none \}/);
        expect(codeql).toMatch(/- \{ language: javascript-typescript, build-mode: none \}/);
    });

    it('protects release tags', () => {
        const tags = JSON.parse(readText('.github', 'rulesets', 'tags.json')) as { target: string; conditions: { ref_name: { include: string[] } }; rules: Array<{ type: string }>; bypass_actors: unknown[] };
        expect(tags.target).toBe('tag');
        expect(tags.conditions.ref_name.include).toEqual(['refs/tags/v*']);
        expect(tags.rules.map((r) => r.type).sort()).toEqual(['deletion', 'non_fast_forward', 'update']);
        expect(tags.bypass_actors).toEqual([]);
    });
});

// ── The gate is the only definition of green ─────────────────────────

describe('ci.yml', () => {
    const ci = readWorkflow('ci.yml');

    it('runs on every push and pull request, on three platforms and two Node lines', () => {
        expect(ci).toMatch(/^on:\s*\n\s+push:\s*\n\s+branches: \[main, master\]\s*\n\s+pull_request:\s*\n\s+branches: \[main, master\]\s*$/m);
        expect(ci).toMatch(/^ {2}ci:\s*\n\s+name: \$\{\{ matrix\.name \}\}/m);
        expect(reported('ci.yml').sort()).toEqual(['ci (22)', 'ci (24)', 'macos', 'runtimes', 'windows', 'workflow lint']);
        const pinned = readText('.nvmrc').trim();
        expect(ci).toMatch(new RegExp(`name: 'ci \\(${pinned}\\)', os: ubuntu-latest, node-version: ${pinned},`));
    });

    it('runs the gate once per leg with --require-all, audits once, and lists no gate step by hand', () => {
        expect([...ci.matchAll(/run: npx tsx scripts\/gate\.ts --ci --require-all/g)]).toHaveLength(1);
        expect(ci).toMatch(/if: matrix\.audit\s*\n\s+run: npm audit --audit-level=high/);
        expect(ci).toMatch(/if: failure\(\)[\s\S]*upload-artifact[\s\S]*test-output\/\.gate\//);
        for (const step of ['typecheck:all', 'test:coverage', 'check:package', 'verify:docs', 'npm run lint', 'npm test']) {
            expect(jobBody(ci, 'ci'), step).not.toContain(`run: ${step}`);
        }
    });

    it('runs OpenSSL 3 on macOS rather than the LibreSSL `openssl`', () => {
        expect(jobBody(ci, 'ci')).toMatch(/if: runner\.os == 'macOS'[\s\S]*brew --prefix openssl@3/);
    });

    it('lints the workflows with zizmor, a checksum-verified actionlint, and reuse', () => {
        const job = jobBody(ci, 'workflow-lint');
        expect(job).toMatch(/uses: zizmorcore\/zizmor-action@[0-9a-f]{40} # v\d/);
        expect(job).toMatch(/min-severity: medium/);
        expect(job).toMatch(/ACTIONLINT_SHA256: [0-9a-f]{64}\s*$/m);
        expect(job.indexOf('sha256sum --check --strict')).toBeLessThan(job.indexOf('/actionlint" -color'));
        expect(job).toMatch(/REUSE_VERSION: \d+\.\d+\.\d+/);
        expect(job).toContain('reuse lint');
    });
});

describe('conformance.yml and sample-regression.yml', () => {
    it('require OpenSSL and the build, then run the interop and built-binary suites', () => {
        const conformance = readWorkflow('conformance.yml');
        expect(conformance).toMatch(/REQUIRE_INTEROP: '1'/);
        expect(conformance).toMatch(/GATE_REQUIRE_ARTIFACTS: '1'/);
        expect(conformance.indexOf('run: npm run build')).toBeLessThan(conformance.indexOf('npx vitest run tests/interop tests/integration'));
    });

    it('verify the samples on the built CLI and hold a re-pin to a CHANGELOG change', () => {
        const samples = readWorkflow('sample-regression.yml');
        expect(samples.indexOf('run: npm run build')).toBeLessThan(samples.indexOf('run: npx tsx scripts/verify-samples.ts'));
        expect(samples).toMatch(/BASE: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
        expect(samples).toContain("grep -qx 'tests/regression/baselines/samples.sha256.json'");
        expect(samples).toContain("grep -qx 'CHANGELOG.md'");
    });
});

// ── publish.yml ──────────────────────────────────────────────────────

/** Whether a setup-node v6 step restores the npm cache, as the action decides it. */
function npmCacheEnabled(step: string, pkg: { packageManager?: string }): boolean {
    if (/^\s+cache:\s*['"]?npm['"]?\s*$/m.test(step)) return true;
    return (pkg.packageManager ?? '').startsWith('npm@') && !/^\s+package-manager-cache:\s*false\s*$/m.test(step);
}

describe('publish.yml', () => {
    const publish = readWorkflow('publish.yml');
    const jobs = jobSteps(publish);
    const pkg = JSON.parse(readText('package.json')) as { packageManager?: string };
    const grants = (job: string): string[] => {
        const block = /^ {4}permissions:\s*\n((?: {6}[a-z-]+:[^\n]*\n)+)/m.exec(jobBody(publish, job))?.[1] ?? '';
        return block.trim().split('\n').map((l) => l.replace(/#.*$/, '').trim()).sort();
    };
    const stepIndex = (job: string, needle: string | RegExp): number =>
        (jobs.get(job) ?? []).findIndex((s) => (typeof needle === 'string' ? s.includes(needle) : needle.test(s)));

    it('starts from a published release or a manual run, never from a tag push, without an NPM_TOKEN', () => {
        expect(publish).toMatch(/^on:\s*\n\s+release:\s*\n\s+types: \[published\]\s*\n\s+workflow_dispatch:\s*$/m);
        expect(publish).not.toMatch(/^\s+push:\s*$/m);
        expect(publish).not.toMatch(/secrets\.NPM_TOKEN/);
        expect(publish).toContain('SLSA Build L2');
    });

    it('runs guard → build → publish → attest, the npm-publish environment on one job, one release at a time', () => {
        expect([...jobs.keys()]).toEqual(['guard', 'build', 'publish', 'attest']);
        expect(jobBody(publish, 'build')).toMatch(/^ {4}needs:\s*guard\s*$/m);
        expect(jobBody(publish, 'publish')).toMatch(/^ {4}needs:\s*build\s*$/m);
        expect(jobBody(publish, 'attest')).toMatch(/^ {4}needs:\s*\[build, publish\]\s*$/m);
        expect([...publish.matchAll(/^\s*environment:/gm)]).toHaveLength(1);
        expect(jobBody(publish, 'publish')).toMatch(/^ {4}environment:\s*npm-publish\s*$/m);
        expect(publish).toMatch(/concurrency:\s*\n\s*group:\s*publish\s*\n\s*cancel-in-progress:\s*false/);
    });

    it('holds id-token: write only where nothing from the dev toolchain runs', () => {
        expect(grants('guard')).toEqual(['contents: read']);
        expect(grants('build')).toEqual(['contents: read']);
        expect(grants('publish')).toEqual(['contents: read', 'id-token: write']);
        expect(grants('attest')).toEqual(['attestations: write', 'contents: write', 'id-token: write']);
        const body = jobBody(publish, 'publish');
        expect(body).not.toMatch(/npm ci|npm run |npx |scripts\/|npm install/);
        const checkouts = (jobs.get('publish') ?? []).filter((s) => s.includes('actions/checkout@'));
        expect(checkouts).toHaveLength(1);
        expect(checkouts[0]).toMatch(/sparse-checkout: \.nvmrc\s*$/m);
    });

    it('refuses a branch, a mismatched tag and a 0.x version before any approval', () => {
        const guard = jobBody(publish, 'guard');
        expect(guard).not.toMatch(/^\s*environment:|npm (ci|install|publish)|id-token/m);
        expect(guard).toMatch(/if \[ "\$\{GITHUB_REF_TYPE\}" != "tag" \]; then[\s\S]*exit 1/);
        expect(guard).toContain('does not match package.json version');
        expect(guard).toMatch(/\[ "\$\{VERSION%%\.\*\}" = "0" \][\s\S]*no version below 1\.0\.0 is released/);
        const confirm = stepIndex('build', 'Confirm the guarded version');
        expect(confirm).toBeGreaterThanOrEqual(0);
        expect(confirm).toBeLessThan(stepIndex('build', 'run: npm ci --ignore-scripts'));
    });

    it('restores no dependency cache in a release job, and builds on the .nvmrc line', () => {
        const setups = [...jobs.values()].flat().filter((s) => s.includes('actions/setup-node@'));
        expect(setups).toHaveLength(3);
        for (const step of setups) {
            expect(npmCacheEnabled(step, pkg), step.split('\n')[0]).toBe(false);
            expect(step).toMatch(/node-version-file:\s*\.nvmrc/);
        }
        expect(npmCacheEnabled('      - uses: actions/setup-node@x\n        with:\n          node-version-file: .nvmrc', pkg)).toBe(true);
    });

    it('runs the publish gate with --require-all, packs once and hands the tarball on with its digests', () => {
        const order = ['run: npx tsx scripts/gate.ts --publish --require-all', 'run: npm pack --dry-run', 'Pack the tarball and record its digests', 'name: release-tarball'].map((n) => stepIndex('build', n));
        expect(order.every((i) => i >= 0), String(order)).toBe(true);
        expect([...order].sort((a, b) => a - b)).toEqual(order);
        const pack = (jobs.get('build') ?? [])[order[2] ?? 0] ?? '';
        expect(pack).toContain('TARBALL="pkinative-cli-${VERSION}.tgz"');
        expect(pack).toMatch(/INTEGRITY="sha512-\$\(openssl dgst -sha512 -binary/);
    });

    it('uploads exactly the handed-on tarball, after both digests and its version, with a client pinned by content', () => {
        const steps = jobs.get('publish') ?? [];
        const verify = stepIndex('publish', 'Verify the tarball against the build job');
        const client = stepIndex('publish', 'Fetch and verify the pinned npm client');
        const upload = stepIndex('publish', /publish "\.\/\$\{TARBALL\}"/);
        expect(verify).toBeLessThan(upload);
        expect(client).toBeLessThan(upload);
        expect(steps[verify]).toContain('sha256sum --check --strict');
        expect(steps[verify]).toContain('test "${TARBALL}" = "pkinative-cli-${VERSION}.tgz"');
        expect(steps[upload]).toMatch(/publish "\.\/\$\{TARBALL\}" --provenance --access public\s*$/m);
        const body = jobBody(publish, 'publish');
        const version = /^ {6}NPM_CLIENT_VERSION: (\d+)\.(\d+)\.(\d+)\s*$/m.exec(body);
        const [major, minor, patch] = (version ?? []).slice(1).map(Number);
        expect(major === 11 && ((minor ?? 0) > 5 || (minor === 5 && (patch ?? 0) >= 1))).toBe(true);
        expect(body).toMatch(/^ {6}NPM_CLIENT_INTEGRITY: sha512-[A-Za-z0-9+/]{86}==\s*$/m);
        expect(publish).not.toMatch(/npm install -g/);
    });

    it('attests the bytes npm serves, with the SBOMs and the Sigstore bundle attached to the release', () => {
        const attest = jobBody(publish, 'attest');
        const fetch = stepIndex('attest', 'Fetch the published tarball and check it against the build');
        expect(fetch).toBeLessThan(stepIndex('attest', 'npm audit signatures'));
        expect(stepIndex('attest', 'npm audit signatures')).toBeLessThan(stepIndex('attest', 'actions/attest-build-provenance@'));
        expect(attest).toContain('npm pack "pkinative-cli@${VERSION}"');
        expect(attest).toContain('npm sbom --sbom-format spdx --omit dev --package-lock-only > "pkinative-cli-${VERSION}.spdx.json"');
        for (const f of ['.tgz', '.cdx.json', '.spdx.json', '.toolchain.cdx.json', '.sigstore.json']) expect(attest).toContain(`"pkinative-cli-\${VERSION}${f}"`);
        expect(publish).not.toMatch(/gh release (create|edit|delete)/);
    });
});

// ── Dependency hygiene and contributor defaults ──────────────────────

describe('dependency review, audit and defaults', () => {
    it('reviews every pull request for high vulnerabilities and licences, the MPL exception named package by package', () => {
        const review = readWorkflow('dependency-review.yml');
        expect(review).toMatch(/fail-on-severity:\s*high/);
        expect(review).toMatch(/allow-licenses:\s*MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, 0BSD, CC0-1.0, Unlicense, BlueOak-1.0.0, Python-2.0\s*$/m);
        expect(review).not.toMatch(/allow-licenses:.*MPL/);
        expect([...review.matchAll(/pkg:npm\/(lightningcss[a-z0-9-]*)/g)].map((m) => m[1]).every((p) => (p ?? '').startsWith('lightningcss'))).toBe(true);
    });

    it('audits the lockfile weekly with npm audit and a pinned OSV-Scanner', () => {
        const audit = readWorkflow('audit.yml');
        expect(audit).toMatch(/schedule:\s*\n\s*- cron:/);
        expect(audit).toMatch(/run: npm audit --audit-level=high/);
        expect(audit).toMatch(/go install github\.com\/google\/osv-scanner\/v2\/cmd\/osv-scanner@v\d+\.\d+\.\d+\n/);
    });

    it('carries the contributor defaults and holds Dependabot back seven days', () => {
        expect(readText('.npmrc')).toBe('ignore-scripts=true\nfund=false\naudit-level=high\nengine-strict=true\n');
        expect(readText('.node-version').trim()).toBe(readText('.nvmrc').trim());
        expect(readText('.gitattributes')).toMatch(/^\* text=auto eol=lf$/m);
        const blocks = readText('.github', 'dependabot.yml').split(/^ {2}- package-ecosystem: /m).slice(1);
        expect(blocks.map((b) => b.split('\n')[0]?.trim()).sort()).toEqual(['github-actions', 'npm']);
        for (const block of blocks) expect(Number(/cooldown:\s*\n\s+default-days: (\d+)/.exec(block)?.[1])).toBeGreaterThanOrEqual(7);
    });

    it('declares one runtime dependency, public access with provenance, and a bin', () => {
        const pkg = JSON.parse(readText('package.json')) as Record<string, unknown>;
        expect(Object.keys(pkg['dependencies'] as object)).toEqual(['pkinative']);
        for (const field of ['peerDependencies', 'optionalDependencies', 'bundleDependencies', 'bundledDependencies']) expect(pkg[field], field).toBeUndefined();
        expect(pkg['publishConfig']).toEqual({ access: 'public', provenance: true });
        expect(pkg['bin']).toEqual({ pkinative: './dist/cli.cjs' });
    });
});
