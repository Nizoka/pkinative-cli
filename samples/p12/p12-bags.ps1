# List the bags, decrypted
# Run from the repository root after `npm run build`. Expected exit: 0.
# $env:PKINATIVE names another pkinative (e.g. 'pkinative' when installed).
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
$Cli = if ($env:PKINATIVE) { $env:PKINATIVE -split ' ' } else { @('node', 'dist/cli.cjs') }
New-Item -ItemType Directory -Force $O | Out-Null
$env:PKINATIVE_PASSWORD = 'test-only-password'
& $Cli[0] @($Cli | Select-Object -Skip 1) p12 bags "$F/leaf.p12"
Remove-Item Env:PKINATIVE_PASSWORD
