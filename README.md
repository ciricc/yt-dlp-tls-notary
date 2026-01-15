# TLSNotary YouTube Demo

Cryptographic proof-of-origin for YouTube videos using TLS Notary.

## Concept

This project demonstrates how to create **cryptographic proofs** that a video file was downloaded from YouTube (or any HTTPS source). Using TLS Notary's MPC protocol, we can prove:

1. **The video came from a specific server** (e.g., `googlevideo.com`)
2. **The content was not modified** after download
3. **The download happened via valid HTTPS** connection

Anyone can verify these proofs without trusting the downloader.

## Use Cases

### 1. Evidence Preservation
- Archive controversial videos with cryptographic proof of authenticity
- Prove a video existed on a platform at a specific time
- Legal evidence that cannot be disputed as fabricated

### 2. Journalism & OSINT
- Verify source of leaked/sensitive videos
- Chain of custody for investigative journalism
- Prove content origin without revealing sources

### 3. Content Authenticity
- NFT provenance for video content
- Verify original source of viral videos
- Combat deepfakes by proving original source

### 4. Regulatory Compliance
- Auditable proof of data origin
- Compliance with data provenance requirements
- Immutable audit trail for downloads

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│                 │     │                 │     │                 │
│  YouTube CDN    │────▶│  TLS Notary     │────▶│  Proof Files    │
│  (HTTPS)        │     │  (MPC Protocol) │     │  (.tlsn)        │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              │
                              ▼
                        ┌─────────────────┐
                        │                 │
                        │  Reconstructed  │
                        │  Video File     │
                        │                 │
                        └─────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| Download speed | ~75 KB/s |
| 10MB video | ~2 minutes |
| 100MB video | ~20 minutes |
| Chunk size | 1MB |
| Parallelism | Up to 30 workers |

## Quick Start

### Prerequisites

- Rust 1.70+
- Python 3.8+
- yt-dlp

### Build

```bash
cd tlsn-cli
cargo build --release
```

### Usage

#### Option 1: Direct CLI

```bash
# Download and notarize a video
./tlsn-cli/target/release/tlsn-cli notarize-stream \
  --url "https://example.com/video.mp4" \
  --output-dir ./proofs \
  --workers 20 \
  --rps-limit 2

# Verify and reconstruct
./tlsn-cli/target/release/tlsn-cli verify-stream \
  --manifest ./proofs/manifest.json \
  --output reconstructed_video.mp4
```

#### Option 2: yt-dlp Integration

```bash
# Copy the postprocessor to yt-dlp
cp yt-dlp-integration/tlsnotary.py /path/to/yt-dlp/yt_dlp/postprocessor/

# Download with notarization
python -m yt_dlp \
  -f 140 \
  --use-postprocessor "TLSNotaryStreamPP:workers=20;rps_limit=2" \
  "https://www.youtube.com/watch?v=VIDEO_ID"
```

## File Structure

```
tlsn-youtube-demo/
├── README.md                 # This file
├── tlsn-cli/                 # Rust CLI tool
│   ├── Cargo.toml
│   └── src/main.rs
├── yt-dlp-integration/       # yt-dlp postprocessor
│   └── tlsnotary.py
└── scripts/                  # Helper scripts
    ├── download_and_notarize.sh
    └── verify_proof.sh
```

## Proof Format

### manifest.json

```json
{
  "url": "https://...",
  "server": "rr2---sn-xxx.googlevideo.com",
  "total_size": 6684364,
  "chunks": [
    {
      "index": 0,
      "range_start": 0,
      "range_end": 1023999,
      "size": 1024000,
      "hash": "abc123...",
      "proof_file": "proofs/chunk_000000.tlsn"
    }
  ],
  "file_hash": "4ff00fea...",
  "timestamp": "2026-01-15T14:33:34Z"
}
```

### Chunk Proof (.tlsn)

Each `.tlsn` file contains:
- TLS transcript (encrypted)
- MPC commitment
- Server certificate chain
- Timestamp

## How It Works

1. **Chunked Download**: Video is split into 1MB chunks with HTTP Range requests
2. **MPC Protocol**: Each chunk is downloaded through TLS Notary's 2-party computation
3. **Commitment**: Prover and Verifier jointly commit to the TLS transcript
4. **Proof Generation**: Cryptographic proof is generated for each chunk
5. **Reconstruction**: Video can be reconstructed from verified chunks

## Limitations

- **Speed**: ~75 KB/s due to MPC overhead (1000x slower than normal download)
- **CPU intensive**: MPC requires significant computation
- **YouTube URLs expire**: Need fresh URL for each download session
- **No streaming**: Full download required before playback

## Security

- Proofs are unforgeable without breaking TLS or MPC assumptions
- Server identity verified via certificate chain
- Content integrity verified via hash commitments
- Timestamp from TLS handshake

## Dependencies

- [TLSNotary](https://github.com/tlsnotary/tlsn) - Core MPC-TLS library
- [yt-dlp](https://github.com/yt-dlp/yt-dlp) - YouTube downloader

## License

MIT

## Credits

- TLSNotary team for the amazing MPC-TLS implementation
- yt-dlp team for the robust YouTube extraction
