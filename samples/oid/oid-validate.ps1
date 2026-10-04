# Validate dotted OIDs (one is invalid)
# Run from the repository root after `npm run build`. Expected exit: 1.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs oid validate 2.5.4.3 2.99.x
