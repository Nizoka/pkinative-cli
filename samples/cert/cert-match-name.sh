#!/bin/sh
# Match a presented DNS name
# Run from the repository root after `npm run build`. Expected exit: 1.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert match-name '*.example.test' a.b.example.test
