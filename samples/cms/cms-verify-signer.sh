#!/bin/sh
# Verify one signer against a certificate
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cms verify-signer "$F"/detached.p7s --cert "$F"/leaf.crt.pem --content "$F"/content.txt
