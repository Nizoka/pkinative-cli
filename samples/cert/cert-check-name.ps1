# Check a host name (wildcard SAN)
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs cert check-name "$F/leaf.crt.pem" --host api.wild.example.test
