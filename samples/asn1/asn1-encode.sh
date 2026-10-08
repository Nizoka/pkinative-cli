#!/bin/sh
# Encode a JSON node spec
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} asn1 encode --spec "$S"/asn1-spec.json --encoding hex
