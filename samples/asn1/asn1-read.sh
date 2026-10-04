#!/bin/sh
# Read one node of the tree
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} asn1 decode "$F"/root.crt.der --path 0.4.0 --read time --json
