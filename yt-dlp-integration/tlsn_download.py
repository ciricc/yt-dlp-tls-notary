#!/usr/bin/env python3
"""
TLS Notary YouTube Download Wrapper

Simple wrapper that imports tlsn_handler before yt-dlp to enable TLSN notarization.

Usage:
    ./tlsn_download.py [yt-dlp options] URL

Environment variables:
    TLSN_ENABLED=1          Enable TLSN (default: 1)
    TLSN_CLI_PATH=/path     Path to tlsn-cli binary
    TLSN_PROOF_DIR=./proofs Directory for proofs

Example:
    TLSN_PROOF_DIR=./my_proofs ./tlsn_download.py -f 140 "https://youtube.com/watch?v=VIDEO_ID"
"""

import os
import sys
from pathlib import Path

# Add this directory to path for tlsn_handler import
sys.path.insert(0, str(Path(__file__).parent))

# CRITICAL: Import tlsn_handler BEFORE yt_dlp
# This registers TLSNotaryRH via @register_rh decorator
import tlsn_handler  # noqa: F401

# Now import and run yt-dlp
import yt_dlp

if __name__ == '__main__':
    # Show config
    proof_dir = os.environ.get('TLSN_PROOF_DIR', './proofs')
    cli_path = os.environ.get('TLSN_CLI_PATH', 'auto-detect')
    enabled = os.environ.get('TLSN_ENABLED', '1') == '1'

    if enabled:
        print(f'[tlsn] TLSN notarization enabled')
        print(f'[tlsn] Proof directory: {proof_dir}')
        print(f'[tlsn] CLI path: {cli_path}')
    else:
        print(f'[tlsn] TLSN notarization disabled')

    # Run yt-dlp with all arguments
    sys.exit(yt_dlp.main())
