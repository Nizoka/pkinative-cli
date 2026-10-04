# Verify the PBMAC1 integrity
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
$env:PKINATIVE_PASSWORD = 'test-only-password'
node dist/cli.cjs p12 verify-mac "$F/leaf.p12"
