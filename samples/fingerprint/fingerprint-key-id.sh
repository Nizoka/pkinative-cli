#!/bin/sh
# RFC 5280 key identifier of a public key
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} fingerprint "$F"/leaf.pub.pem --key-id
