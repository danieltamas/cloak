#!/bin/bash
set -euo pipefail

echo "Running cross-compatibility tests..."
cd "$(dirname "$0")/../extension"
npm test -- --reporter verbose tests/cross-compat.test.ts
echo "All cross-compatibility tests passed"
