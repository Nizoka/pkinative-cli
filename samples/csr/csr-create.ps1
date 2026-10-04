# Create a request (ECDSA: the signed part is pinned)
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs csr create --spec "$S/csr.json" --key "$F/leaf.key.pem" --encoding der -o "$O/req.der"
