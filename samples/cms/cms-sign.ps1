# Sign detached (Ed25519: deterministic)
# Run from the repository root after `npm run build`. Expected exit: 0.
# $env:PKINATIVE names another pkinative (e.g. 'pkinative' when installed).
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
$Cli = if ($env:PKINATIVE) { $env:PKINATIVE -split ' ' } else { @('node', 'dist/cli.cjs') }
New-Item -ItemType Directory -Force $O | Out-Null
& $Cli[0] @($Cli | Select-Object -Skip 1) cms sign --content "$F/content.txt" --cert "$O/ca.pem" --key "$F/ed25519.key.pem" --detached --signing-time 2027-01-01T00:00:00Z -o "$O/content.p7s"
