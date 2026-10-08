#!/bin/sh
# Open a PKCS#12 and export its certificates
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
PKINATIVE_PASSWORD=test-only-password ${PKINATIVE:-node dist/cli.cjs} p12 open "$F"/leaf.p12 --certs-out "$O"/bundle.pem -q
