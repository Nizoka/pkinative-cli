#!/bin/sh
# List the bags, decrypted
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
PKINATIVE_PASSWORD=test-only-password ${PKINATIVE:-node dist/cli.cjs} p12 bags "$F"/leaf.p12
