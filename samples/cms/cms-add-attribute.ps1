# Add an unsigned attribute
# Run from the repository root after `npm run build`. Expected exit: 0.
$F = 'tests/fixtures/pki'; $S = 'samples/inputs'; $O = 'test-output/samples'
New-Item -ItemType Directory -Force $O | Out-Null
node dist/cli.cjs cms add-attribute "$O/content.p7s" --attribute "$S/attribute.der" -o "$O/content-attr.p7s"
