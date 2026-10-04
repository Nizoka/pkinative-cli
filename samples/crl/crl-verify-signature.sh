#!/bin/sh
# Verify a CRL signature
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} crl verify-signature "$F"/inter.crl.der --issuer "$F"/inter.crt.pem
