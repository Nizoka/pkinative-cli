#!/bin/sh
# Print one decoded extension as JSON
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert inspect "$F"/leaf.crt.pem --extension subjectAltName --json
