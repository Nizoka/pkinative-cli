# Open a PKCS#12 and export its certificates
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
$env:PKINATIVE_PASSWORD = 'test-only-password'
node dist/cli.cjs p12 open "$F/leaf.p12" --certs-out "$O/bundle.pem" -q
