#!/bin/sh
# Look a serial up in a CRL
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} crl find "$F"/inter.crl.der --serial 1002
