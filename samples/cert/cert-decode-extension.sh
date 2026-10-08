#!/bin/sh
# Decode an extension value
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert decode-extension --oid 2.5.29.19 --value 30030101ff --critical
