#!/bin/sh
# Describe a PKCS#12 file
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} p12 inspect "$F"/leaf.p12
