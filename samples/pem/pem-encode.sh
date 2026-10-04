#!/bin/sh
# Wrap DER bytes in PEM
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} pem encode "$F"/leaf.crt.der --label CERTIFICATE -o "$O"/leaf.pem
