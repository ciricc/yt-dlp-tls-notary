#!/bin/bash
# Download and notarize a YouTube video
# Usage: ./download_and_notarize.sh <youtube_url> [output_dir]

set -e

YOUTUBE_URL="${1:?Usage: $0 <youtube_url> [output_dir]}"
OUTPUT_DIR="${2:-./output}"
WORKERS="${WORKERS:-20}"
RPS_LIMIT="${RPS_LIMIT:-2}"
FORMAT="${FORMAT:-140}"  # Default: m4a audio

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="$SCRIPT_DIR/../tlsn-cli/target/release/tlsn-cli"

# Check if CLI is built
if [ ! -f "$CLI" ]; then
    echo "Building tlsn-cli..."
    cd "$SCRIPT_DIR/../tlsn-cli"
    cargo build --release
    cd -
fi

# Get direct URL from YouTube
echo "Extracting video URL..."
VIDEO_URL=$(python3 -m yt_dlp -f "$FORMAT" --get-url "$YOUTUBE_URL" 2>/dev/null)

if [ -z "$VIDEO_URL" ]; then
    echo "Error: Could not extract video URL"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo ""
echo "=== TLSNotary YouTube Download ==="
echo "YouTube URL: $YOUTUBE_URL"
echo "Format: $FORMAT"
echo "Workers: $WORKERS"
echo "RPS Limit: $RPS_LIMIT"
echo "Output: $OUTPUT_DIR"
echo ""

# Run notarization
"$CLI" notarize-stream \
    --url "$VIDEO_URL" \
    --output-dir "$OUTPUT_DIR" \
    --workers "$WORKERS" \
    --rps-limit "$RPS_LIMIT"

echo ""
echo "Done! Proofs saved to: $OUTPUT_DIR"
echo "To verify: ./verify_proof.sh $OUTPUT_DIR/manifest.json"
