#!/bin/sh
# Verify a time-stamp against its request and data
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} tsp verify --response "$F"/content.tsr --request "$F"/content.tsq --data "$F"/content.txt --trust "$F"/root.crt.pem --at 2027-01-01T00:00:00Z -q
