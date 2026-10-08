#!/bin/sh
# Check an extended key usage along a path
# Run from the repository root after `npm run build`. Expected exit: 0.
set -u
F=tests/fixtures/pki S=samples/inputs O=test-output/samples
mkdir -p "$O"
${PKINATIVE:-node dist/cli.cjs} cert check-purpose "$F"/leaf.crt.pem --chain "$F"/inter.crt.pem --purpose serverAuth
