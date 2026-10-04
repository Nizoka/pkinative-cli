#!/bin/sh
# Encode an OID as a TLV
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} oid encode 1.2.840.113549.1.1.11 --tlv
