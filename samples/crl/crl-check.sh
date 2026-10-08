#!/bin/sh
# Decide a status from a CRL
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} crl check "$F"/inter.crl.der --cert "$F"/leaf.crt.pem --issuer "$F"/inter.crt.pem --at 2027-01-01T00:00:00Z
