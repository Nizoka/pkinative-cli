#!/bin/sh
# Describe an encrypted key (no password needed)
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} key inspect "$F"/leaf.key.enc.pem --json
