# Build a time-stamp request
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs tsp request --data "$F/content.txt" --nonce 42 -o "$O/req.tsq"
