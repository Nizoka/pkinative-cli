#!/bin/sh
# Verify a certificate signature against its issuer
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert verify-signature "$F"/leaf.crt.pem --issuer "$F"/inter.crt.pem
