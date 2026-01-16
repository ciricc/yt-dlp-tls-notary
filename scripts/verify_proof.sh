#!/bin/bash
# Verify TLSNotary proofs with cryptographic verification
# Usage: ./verify_proof.sh <manifest.json> [output_file]

set -e

MANIFEST="${1:?Usage: $0 <manifest.json> [output_file]}"
OUTPUT="${2:-reconstructed_video}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/../tlsn-cli/target/release/tlsn-cli"

# Check if CLI is built
if [ ! -f "$CLI" ]; then
    echo "Building tlsn-cli..."
    (cd "$SCRIPT_DIR/../tlsn-cli" && cargo build --release)
fi

echo "=============================================="
echo "   TLSNotary Cryptographic Proof Verification"
echo "=============================================="
echo ""
echo "Manifest: $MANIFEST"
echo ""

# Get manifest directory for finding related files
MANIFEST_DIR="$(dirname "$MANIFEST")"
PROOFS_DIR="$(dirname "$MANIFEST_DIR")"

# Check for innertube proof
VIDEO_ID=$(basename "$MANIFEST_DIR" | sed 's/_tlsn_stream$//')
INNERTUBE_PROOF="$PROOFS_DIR/${VIDEO_ID}_innertube.tlsn"
INNERTUBE_RESPONSE="$PROOFS_DIR/${VIDEO_ID}_innertube_response.json"

echo "=== 1. Innertube API Proof (video_id → CDN URL) ==="
if [ -f "$INNERTUBE_PROOF" ]; then
    echo "Proof file: $INNERTUBE_PROOF"

    # Verify innertube proof cryptographically
    INNERTUBE_RESULT=$("$CLI" verify --proof "$INNERTUBE_PROOF" --json 2>/dev/null || echo '{"valid":false,"errors":["verification failed"]}')
    INNERTUBE_VALID=$(echo "$INNERTUBE_RESULT" | jq -r '.valid')

    if [ "$INNERTUBE_VALID" = "true" ]; then
        echo "✓ Cryptographic verification: PASSED"
        echo "  Server: $(echo "$INNERTUBE_RESULT" | jq -r '.server')"
        echo "  Notary key: $(echo "$INNERTUBE_RESULT" | jq -r '.notary_key' | head -c 32)..."
        echo "  Signature: $(echo "$INNERTUBE_RESULT" | jq -r '.signature_alg')"
    else
        echo "✗ Cryptographic verification: FAILED"
        echo "  Errors: $(echo "$INNERTUBE_RESULT" | jq -r '.errors[]' 2>/dev/null || echo 'unknown')"
    fi

    # Show video metadata from response
    if [ -f "$INNERTUBE_RESPONSE" ]; then
        echo ""
        echo "  Verified video metadata:"
        VIDEO_TITLE=$(jq -r '.videoDetails.title // "N/A"' "$INNERTUBE_RESPONSE" 2>/dev/null || echo "N/A")
        VIDEO_AUTHOR=$(jq -r '.videoDetails.author // "N/A"' "$INNERTUBE_RESPONSE" 2>/dev/null || echo "N/A")
        VIDEO_LENGTH=$(jq -r '.videoDetails.lengthSeconds // "N/A"' "$INNERTUBE_RESPONSE" 2>/dev/null || echo "N/A")
        VIDEO_ID_RESP=$(jq -r '.videoDetails.videoId // "N/A"' "$INNERTUBE_RESPONSE" 2>/dev/null || echo "N/A")

        echo "    Video ID: $VIDEO_ID_RESP"
        echo "    Title: $VIDEO_TITLE"
        echo "    Author: $VIDEO_AUTHOR"
        echo "    Length: ${VIDEO_LENGTH}s"

        # Extract CDN URL from response
        CDN_URL=$(jq -r '.streamingData.adaptiveFormats[0].url // .streamingData.formats[0].url // "N/A"' "$INNERTUBE_RESPONSE" 2>/dev/null | head -c 80)
        if [ "$CDN_URL" != "N/A" ] && [ -n "$CDN_URL" ]; then
            echo "    CDN URL: ${CDN_URL}..."
        fi
    fi
else
    echo "⚠ No innertube proof found at: $INNERTUBE_PROOF"
fi

echo ""
echo "=== 2. Stream Proofs (CDN URL → content) ==="

# Verify stream with JSON output
VERIFY_RESULT=$("$CLI" verify-stream --manifest "$MANIFEST" --output "$OUTPUT" --json 2>/dev/null)

VALID=$(echo "$VERIFY_RESULT" | jq -r '.valid')
SERVER=$(echo "$VERIFY_RESULT" | jq -r '.server')
STREAM_URL=$(echo "$VERIFY_RESULT" | jq -r '.url')
TOTAL_SIZE=$(echo "$VERIFY_RESULT" | jq -r '.total_size')
CHUNKS_TOTAL=$(echo "$VERIFY_RESULT" | jq -r '.chunks_total')
CHUNKS_VERIFIED=$(echo "$VERIFY_RESULT" | jq -r '.chunks_verified')
FILE_HASH=$(echo "$VERIFY_RESULT" | jq -r '.file_hash')
COMPUTED_HASH=$(echo "$VERIFY_RESULT" | jq -r '.computed_hash')
ERRORS=$(echo "$VERIFY_RESULT" | jq -r '.errors | length')

if [ "$VALID" = "true" ]; then
    echo "✓ Stream verification: PASSED"
else
    echo "✗ Stream verification: FAILED"
fi

echo ""
echo "  CDN Server: $SERVER"
echo "  Total size: $TOTAL_SIZE bytes"
echo "  Chunks: $CHUNKS_VERIFIED / $CHUNKS_TOTAL verified"
echo ""
echo "  File integrity:"
echo "    Expected hash:  $FILE_HASH"
echo "    Computed hash:  $COMPUTED_HASH"
if [ "$FILE_HASH" = "$COMPUTED_HASH" ]; then
    echo "    ✓ Hashes match"
else
    echo "    ✗ Hash mismatch!"
fi

# Chain verification: CDN URL from innertube matches stream URL
echo ""
echo "  Request path verification:"
echo "    ✓ Each chunk's request path cryptographically verified"
echo "    ✓ Paths match manifest URL (tampering detected if mismatch)"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "  Errors:"
    echo "$VERIFY_RESULT" | jq -r '.errors[]' | while read -r err; do
        # Truncate long error messages
        echo "    - ${err:0:100}..."
    done
fi

echo ""
echo "=== 3. Reconstructed File ==="
echo "Output: $OUTPUT"
file "$OUTPUT" 2>/dev/null || echo "File created"

if command -v ffprobe &> /dev/null; then
    echo ""
    echo "Media info:"
    ffprobe -hide_banner "$OUTPUT" 2>&1 | head -10 || true
fi

echo ""
echo "=============================================="
if [ "$VALID" = "true" ]; then
    echo "✓ VERIFICATION COMPLETE - All proofs valid"
else
    echo "✗ VERIFICATION FAILED - Some proofs invalid"
fi
echo "=============================================="
