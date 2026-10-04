# Add a counter time-stamp
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs cms add-timestamp "$F/attached.p7s" --token "$F/content.tsr" -o "$O/stamped.p7s"
