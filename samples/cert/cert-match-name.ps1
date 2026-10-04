# Match a presented DNS name
# Run from the repository root after `npm run build`. Expected exit: 1.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs cert match-name '*.example.test' a.b.example.test
