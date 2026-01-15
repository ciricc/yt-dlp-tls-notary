#!/bin/bash
# Verify TLSNotary proof and reconstruct video
# Usage: ./verify_proof.sh <manifest.json> [output_file]

set -e

MANIFEST="${1:?Usage: $0 <manifest.json> [output_file]}"
OUTPUT="${2:-reconstructed_video}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/../tlsn-cli/target/release/tlsn-cli"

# Check if CLI is built
if [ ! -f "$CLI" ]; then
    echo "Building tlsn-cli..."
    cd "$SCRIPT_DIR/../tlsn-cli"
    cargo build --release
    cd -
fi

echo "=== TLSNotary Proof Verification ==="
echo "Manifest: $MANIFEST"
echo ""

# Verify and reconstruct
"$CLI" verify-stream \
    --manifest "$MANIFEST" \
    --output "$OUTPUT"

echo ""
echo "=== File Info ==="
file "$OUTPUT"
echo ""

if command -v ffprobe &> /dev/null; then
    echo "=== Media Info ==="
    ffprobe -hide_banner "$OUTPUT" 2>&1 | head -15
fi

echo ""
echo "Verified file saved to: $OUTPUT"
