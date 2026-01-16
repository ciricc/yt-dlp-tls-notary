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
    ├── chunk_000000.tlsn   # Proof: bytes 0-60KB came from URL Y
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
| Video has ID `X` | innertube.tlsn | `jq .videoDetails.videoId *_innertube_response.json` |
| YouTube returned CDN URL | innertube.tlsn | `jq .streamingData.adaptiveFormats[0].url *_innertube_response.json` |
| Content came from CDN | chunk proofs (.tlsn files) | `tlsn-cli verify-stream --manifest ...` |
| Content not modified | SHA256 hashes | `file_hash == computed_hash` in verify output |

## Performance

| Metric | Value |
|--------|-------|
| Innertube notarization | ~20-30 seconds |
| Stream chunk size | 60 KB (optimal for YouTube CDN) |
| Stream notarization | ~20 sec per chunk |
| 300KB audio (6 chunks) | ~2 minutes |
| Parallelism | Up to 10 workers |

**Real test results ("Me at the zoo" - 19 sec audio):**
```
Video: jNQXAC9IVRw
Size: 309,288 bytes
Chunk size: 60 KB
Chunks: 6
Workers: 10
Total time: 126 seconds
```

**Why 60KB chunks?**
- YouTube CDN has aggressive timeouts (~30-60 sec)
- MPC-TLS overhead means large chunks timeout before completion
- 60KB is the sweet spot: fast enough to complete, few enough sessions

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

### 2. Run with yt-dlp integration

```bash
# Set PYTHONPATH to include the integration directory
export PYTHONPATH="/path/to/tlsn-youtube-demo/yt-dlp-integration:$PYTHONPATH"
export TLSN_PROOF_DIR="./proofs"

# Full notarization: innertube + stream
python -c "
import tlsn_handler  # Registers TLSNotaryRH
from tlsnotary import TLSNotaryStreamPP
from yt_dlp import YoutubeDL

ydl_opts = {
    'format': '140',  # audio only
    'outtmpl': './%(id)s.%(ext)s',
    'postprocessors': [{
        'key': 'TLSNotaryStream',
        'workers': 10,
        'chunk_size': 60000,
    }],
}

with YoutubeDL(ydl_opts) as ydl:
    ydl.download(['https://youtu.be/VIDEO_ID'])
"
```

### 3. Verify

```bash
# Full verification with the script
./scripts/verify_proof.sh ./proofs/VIDEO_ID_tlsn_stream/manifest.json

# Or use tlsn-cli directly
./tlsn-cli/target/release/tlsn-cli verify-stream \
    --manifest ./proofs/VIDEO_ID_tlsn_stream/manifest.json \
    --output verified_video.m4a \
    --json
```

**Example verification output:**
```
==============================================
   TLSNotary Cryptographic Proof Verification
==============================================

=== 1. Innertube API Proof (video_id → CDN URL) ===
✓ Cryptographic verification: PASSED
  Server: www.youtube.com
  Video ID: jNQXAC9IVRw
  Title: Me at the zoo
  Author: jawed

=== 2. Stream Proofs (CDN URL → content) ===
✓ Stream verification: PASSED
  CDN Server: rr1---sn-xxx.googlevideo.com
  Chunks: 6 / 6 verified
  ✓ Hashes match

==============================================
✓ VERIFICATION COMPLETE - All proofs valid
==============================================
```

## Cryptographic Proof Format

Each `.tlsn` file contains:

- **Attestation** - Public proof with notary's signature
- **Secrets** - TLS session keys for verification

For sharing proofs:
1. **Full disclosure**: Share `.tlsn` files directly (includes all data)
2. **Selective disclosure** (TODO): Create Presentation that reveals only specific fields

### Proof Files

```
proofs/
├── VIDEO_ID_innertube.tlsn           # Innertube API proof
├── VIDEO_ID_innertube_response.json  # API response (for inspection)
└── VIDEO_ID_tlsn_stream/
    ├── manifest.json                 # Stream metadata + chunk list
    ├── output.bin                    # Reconstructed file
    └── proofs/
        ├── chunk_000000.tlsn         # Chunk 0 proof
        ├── chunk_000001.tlsn
        └── ...
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TLSN_ENABLED` | `1` | Enable/disable TLSN (set `0` to disable) |
| `TLSN_CLI_PATH` | auto-detect | Path to tlsn-cli binary |
| `TLSN_PROOF_DIR` | `./proofs` | Directory for proof files |

## Trust Model

### Self-Notarization (Current)

The prover and notary run in the same process. This provides:
- ✓ Proof of server identity (TLS certificate)
- ✓ Proof of data integrity (hashes match)
- ✗ No third-party attestation

**Use case**: Proving to yourself that data is authentic, or when you trust the prover.

### Remote Notary (Production)

For third-party verification, use a trusted remote notary:
- ✓ All of the above
- ✓ Third-party attestation (notary's signature)

```bash
# Future: Remote notary support
export TLSN_NOTARY_URL="wss://notary.example.com:7047"
```

**Note:** Remote notary WebSocket support is not yet implemented.

## Limitations

- **Speed**: ~2-5 KB/s effective due to MPC overhead (vs 10+ MB/s normal download)
- **Chunk size**: Must be ≤60KB for YouTube CDN (larger chunks timeout)
- **Not all videos**: Some require PO tokens or authentication
- **URL expiration**: CDN URLs expire after ~6 hours

### Bandwidth Overhead

MPC-TLS has significant bandwidth overhead:
- ~25 MB fixed cost per TLSNotary session
- ~10 MB per 1 KB of outgoing data
- ~40 KB per 1 KB of incoming data

**Example:** 60KB chunk = ~25MB + ~2.4MB ≈ 27MB overhead per chunk

## Security

- Proofs are unforgeable without breaking TLS or MPC assumptions
- Server identity verified via certificate chain
- Content integrity verified via hash commitments
- Complete chain: video_id → YouTube API → CDN URL → content

## TODO

- [ ] **Remote notary WebSocket support** - Connect to remote notary servers
- [ ] **Selective disclosure** - Create Presentations that reveal only specific fields (video_id, title) while hiding others (IP, cookies)
- [ ] **Proof compression** - Optimize proof file sizes
- [ ] **Python verification** - Native verification without calling tlsn-cli

## License

MIT

## Credits

- [TLSNotary](https://github.com/tlsnotary/tlsn) - MPC-TLS implementation
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - YouTube extraction
