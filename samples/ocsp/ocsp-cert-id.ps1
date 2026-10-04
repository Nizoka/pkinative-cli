# Encode a CertID
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs ocsp cert-id --cert "$F/leaf.crt.pem" --issuer "$F/inter.crt.pem" --hash SHA-256
