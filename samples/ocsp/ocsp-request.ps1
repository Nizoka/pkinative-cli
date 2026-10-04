# Build an OCSP request
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs ocsp request --cert "$F/leaf.crt.pem" --issuer "$F/inter.crt.pem" -o "$O/ocsp-req.der"
