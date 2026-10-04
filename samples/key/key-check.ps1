# Prove an encrypted key decrypts
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
$env:PKINATIVE_PASSWORD = 'test-only-password'
node dist/cli.cjs key check "$F/leaf.key.enc.pem" --key-type ec-p256 --json
