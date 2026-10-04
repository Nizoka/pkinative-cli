# A revoked leaf fails the verdict
# Run from the repository root after `npm run build`. Expected exit: 1.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs chain verify "$F/revoked.crt.pem" --untrusted "$F/inter.crt.pem" --trust "$F/root.crt.pem" --crl "$F/inter.crl.pem" --at 2027-01-01T00:00:00Z -q
