#!/bin/sh
# Decode OID content octets
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} oid decode 2a864886f70d01010b
