#!/bin/sh
# Create a request (ECDSA: the signed part is pinned)
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} csr create --spec "$S"/csr.json --key "$F"/leaf.key.pem --encoding der -o "$O"/req.der
