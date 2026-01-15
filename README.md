# TLSNotary YouTube Demo

Cryptographic proof-of-origin for YouTube videos using TLS Notary.

## Concept

This project creates **cryptographic proofs** that a video was downloaded from YouTube with a complete chain of trust:

1. **video_id → CDN URL** (innertube API proof)
2. **CDN URL → content** (stream download proof)

Anyone can verify these proofs without trusting the downloader.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  yt-dlp + TLSNotaryRH (Request Handler)                         │
│                                                                 │
│  1. yt-dlp requests /youtubei/v1/player                         │
│  2. TLSNotaryRH intercepts → routes through tlsn-cli      ───┐  │
│  3. Proof saved, response returned to yt-dlp                 │  │
│  4. yt-dlp extracts video info as usual                      │  │
└───────────────────────────────────────────────────────────────┼──┘
                                                                │
┌───────────────────────────────────────────────────────────────┼──┐
│  TLSNotaryStreamPP (PostProcessor)                            │  │
│                                                               ▼  │
│  5. NOTARIZE stream download (CDN URL → video bytes)            │
│  6. Combine proofs into manifest                                │
└──────────────────────────────────────────────────────────────────┘

Output:
├── manifest.json           # Links everything together
├── innertube.tlsn          # Proof: YouTube said video_id X has URL Y
└── proofs/
    ├── chunk_000000.tlsn   # Proof: bytes 0-1MB came from URL Y
    ├── chunk_000001.tlsn
    └── ...
```

## Key Feature: No yt-dlp Patching Required

The `TLSNotaryRH` request handler integrates at the **transport layer**, intercepting HTTP requests before they're sent. This means:

- No file modifications to yt-dlp
- Survives yt-dlp updates automatically
- Just import the module before using yt-dlp

## What's Proven

| Claim | Proof | How to Verify |
|-------|-------|---------------|
| Video has ID `X` | innertube.tlsn | `grep videoId *_innertube_response.json` |
| YouTube returned CDN URL | innertube.tlsn | `grep googlevideo.com *_innertube_response.json` |
| Content came from CDN | chunk proofs (.tlsn files) | `tlsn-cli verify-stream --manifest ...` |
| Content not modified | SHA256 hashes | `file_hash == computed_hash` in verify output |

## Performance

| Metric | Value |
|--------|-------|
| Innertube notarization | ~20 seconds |
| Stream download speed | ~75-150 KB/s (depends on workers) |
| 35MB audio | ~4-5 minutes (20 workers, RPS=2) |
| Parallelism | Up to 30 workers |

**Real test results (35.5MB audio file):**
```
Workers: 20, RPS limit: 2.0
Chunks: 37 × 1MB
Total time: 257 seconds (~145 KB/s effective)
```

## Quick Start

### Prerequisites

- Rust 1.70+
- Python 3.8+
- yt-dlp

### 1. Build tlsn-cli

```bash
cd tlsn-youtube-demo/tlsn-cli
cargo build --release

# Add to PATH or set TLSN_CLI_PATH
export PATH="$PWD/target/release:$PATH"
```

### 2. Install the handler

**Option A: Copy to yt-dlp (recommended)**
```bash
cp yt-dlp-integration/tlsn_handler.py /path/to/yt_dlp/networking/
```

**Option B: Import before yt-dlp**
```bash
# Set PYTHONPATH to include the integration directory
export PYTHONPATH="/path/to/tlsn-youtube-demo/yt-dlp-integration:$PYTHONPATH"
```

### 3. Usage

```bash
# Set configuration via environment variables
export TLSN_PROOF_DIR="./proofs"
export TLSN_CLI_PATH="/path/to/tlsn-cli"  # Optional if in PATH

# Innertube notarization only (proves video_id → CDN URL)
python -c "import tlsn_handler; import yt_dlp; yt_dlp.main()" \
    -f 140 \
    "https://www.youtube.com/watch?v=VIDEO_ID"

# Full notarization: innertube + stream
python -c "import tlsn_handler; import yt_dlp; yt_dlp.main()" \
    -f 140 \
    --use-postprocessor "TLSNotaryStreamPP:workers=20;rps_limit=2" \
    "https://www.youtube.com/watch?v=VIDEO_ID"
```

### 4. Verify

```bash
# Verify the proof chain
./tlsn-cli/target/release/tlsn-cli verify-stream \
    --manifest ./VIDEO_ID_tlsn_stream/manifest.json \
    --json

# Output:
# {
#   "valid": true,
#   "url": "https://rr4---sn-xxx.googlevideo.com/videoplayback?...",
#   "server": "rr4---sn-xxx.googlevideo.com",
#   "total_size": 37222910,
#   "chunks_total": 37,
#   "chunks_verified": 37,
#   "file_hash": "67d82cd0...",
#   "computed_hash": "67d82cd0...",  # Must match file_hash
#   "errors": []
# }

# Optionally reconstruct verified file
./tlsn-cli/target/release/tlsn-cli verify-stream \
    --manifest ./VIDEO_ID_tlsn_stream/manifest.json \
    --output verified_video.m4a
```

### 5. Verify the Full Chain

To verify video_id → CDN URL → content:

```bash
# 1. Check video_id in innertube response
grep '"videoId"' ./proofs/VIDEO_ID_innertube_response.json
# Output: "videoId":"ZorWdKIgSbs"

# 2. Check CDN URL in innertube response matches manifest
grep 'googlevideo.com/videoplayback' ./proofs/VIDEO_ID_innertube_response.json

# 3. Verify stream proofs
./tlsn-cli verify-stream --manifest ./VIDEO_ID_tlsn_stream/manifest.json --json
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TLSN_ENABLED` | `1` | Enable/disable TLSN (set `0` to disable) |
| `TLSN_CLI_PATH` | auto-detect | Path to tlsn-cli binary |
| `TLSN_PROOF_DIR` | `./proofs` | Directory for proof files |

## File Structure

```
tlsn-youtube-demo/
├── README.md
├── tlsn-cli/                    # Rust CLI tool
│   ├── Cargo.toml
│   └── src/main.rs
├── yt-dlp-integration/          # yt-dlp integration
│   ├── tlsn_handler.py          # Request Handler (transport layer)
│   ├── tlsnotary.py             # PostProcessor (stream notarization)
│   └── tlsn_download.py         # Convenience wrapper script
└── yt-dlp-patch/                # Legacy patch approach (optional)
    ├── README.md
    └── tlsn_youtube.patch
```

## How It Works

1. **Request Handler Registration**: When `tlsn_handler` is imported, `@register_rh` decorator adds `TLSNotaryRH` to yt-dlp's request handlers.

2. **Request Interception**: When yt-dlp makes a request to `/youtubei/v1/player`, `TLSNotaryRH` intercepts it based on URL matching and high preference score.

3. **Notarization**: The handler routes the request through `tlsn-cli`, which:
   - Establishes MPC-TLS session with YouTube
   - Sends the request and receives the response
   - Creates cryptographic proof of the exchange
   - Saves proof and response files

4. **Response Forwarding**: The handler returns the response to yt-dlp, which processes it normally (extracts video URLs, formats, etc.)

5. **Stream Notarization** (optional): `TLSNotaryStreamPP` PostProcessor downloads the video in chunks, each through a separate TLSN session.

## Proof Format

### manifest.json

```json
{
  "version": 1,
  "url": "https://rr4---sn-xxx.googlevideo.com/videoplayback?...",
  "server": "rr4---sn-xxx.googlevideo.com",
  "total_size": 37222910,
  "chunk_size": 1024000,
  "file_hash": "67d82cd0557c18fdb742ce58a72fc3a5191e83672a0f80f247a8f1f18993aa61",
  "chunks": [
    {
      "index": 0,
      "range_start": 0,
      "range_end": 1023999,
      "size": 1024000,
      "hash": "c03232cb...",
      "proof_file": "proofs/chunk_000000.tlsn",
      "timestamp": "2026-01-15T15:28:51.118066+00:00"
    },
    // ... more chunks
  ],
  "started_at": "2026-01-15T15:26:46.900104+00:00",
  "completed_at": "2026-01-15T15:31:04.085630+00:00"
}
```

The innertube proof is saved separately as `VIDEO_ID_innertube.tlsn` with the response in `VIDEO_ID_innertube_response.json`.

## Limitations

- **Speed**: ~75-150 KB/s due to MPC overhead (vs 10+ MB/s normal download)
- **Not all videos**: Some videos require PO tokens or authentication (fallback to normal download)
- **Large requests**: Innertube requests must fit in TLSN's buffer limits (~4KB sent, ~1MB received)
- **URL expiration**: YouTube CDN URLs expire after ~6 hours, proofs remain valid but URL won't work for re-download

## Security

- Proofs are unforgeable without breaking TLS or MPC assumptions
- Server identity verified via certificate chain
- Content integrity verified via hash commitments
- Complete chain: video_id → YouTube API → CDN URL → content

## License

MIT

## Credits

- [TLSNotary](https://github.com/tlsnotary/tlsn) - MPC-TLS implementation
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - YouTube extraction
