#!/bin/sh
# One-call verdict with revocation
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} chain verify "$F"/leaf.crt.pem --untrusted "$F"/inter.crt.pem --trust "$F"/root.crt.pem --host example.test --crl "$F"/inter.crl.pem --ocsp "$F"/leaf.ocsp.der --require-revocation --at 2027-01-01T00:00:00Z
