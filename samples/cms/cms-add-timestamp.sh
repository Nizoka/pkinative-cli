#!/bin/sh
# Refuse a token that stamps the content, not the signature value
# Run from the repository root after `npm run build`. Expected exit: 1.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cms add-timestamp "$F"/attached.p7s --token "$F"/content.tsr -o "$O"/stamped.p7s
