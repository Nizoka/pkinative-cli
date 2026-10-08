#!/bin/sh
# Verify the PBMAC1 integrity
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
PKINATIVE_PASSWORD=test-only-password ${PKINATIVE:-node dist/cli.cjs} p12 verify-mac "$F"/leaf.p12
