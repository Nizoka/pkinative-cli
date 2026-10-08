#!/bin/sh
# Decide a status from an OCSP response
# Run from the repository root after `npm run build`. Expected exit: 1.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} ocsp check "$F"/revoked.ocsp.der --cert "$F"/revoked.crt.pem --issuer "$F"/inter.crt.pem --at 2027-01-01T00:00:00Z -q
