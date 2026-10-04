#!/bin/sh
# Validate dotted OIDs (one is invalid)
# Run from the repository root after `npm run build`. Expected exit: 1.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} oid validate 2.5.4.3 2.99.x
