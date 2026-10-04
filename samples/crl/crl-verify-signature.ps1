# Verify a CRL signature
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs crl verify-signature "$F/inter.crl.der" --issuer "$F/inter.crt.pem"
