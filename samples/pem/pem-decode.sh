#!/bin/sh
# List the PEM blocks of a file
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} pem decode "$F"/leaf.crt.pem --json
