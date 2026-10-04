#!/bin/sh
# Validate an ordered path
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} chain validate --path "$F"/leaf.crt.pem --path "$F"/inter.crt.pem --trust "$F"/root.crt.pem --at 2027-01-01T00:00:00Z
