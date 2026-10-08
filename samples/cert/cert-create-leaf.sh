#!/bin/sh
# Issue a leaf under that CA
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert create --spec "$S"/leaf.json --key "$F"/ed25519.key.pem --issuer "$O"/ca.pem --public-key "$F"/leaf.pub.pem -o "$O"/leaf-issued.pem
