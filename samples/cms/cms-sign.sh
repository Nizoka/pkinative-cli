#!/bin/sh
# Sign detached (Ed25519: deterministic)
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cms sign --content "$F"/content.txt --cert "$O"/ca.pem --key "$F"/ed25519.key.pem --detached --signing-time 2027-01-01T00:00:00Z -o "$O"/content.p7s
