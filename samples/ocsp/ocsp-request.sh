#!/bin/sh
# Build an OCSP request
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} ocsp request --cert "$F"/leaf.crt.pem --issuer "$F"/inter.crt.pem -o "$O"/ocsp-req.der
