"""
TLS Notary Request Handler for yt-dlp

This handler intercepts YouTube API requests and routes them through
tlsn-cli to create cryptographic proofs of the request/response.

Configuration via environment variables:
    TLSN_ENABLED=1          Enable TLSN notarization (default: 1)
    TLSN_CLI_PATH=/path     Path to tlsn-cli binary (default: auto-detect)
    TLSN_PROOF_DIR=./proofs Directory for proof files (default: ./proofs)

Usage:
    # Option 1: Copy to yt_dlp/networking/ and it auto-registers
    cp tlsn_handler.py /path/to/yt_dlp/networking/

    # Option 2: Import before using yt-dlp
    import tlsn_handler  # Registers handler via @register_rh
    import yt_dlp
    # Now use yt-dlp normally

Example:
    TLSN_PROOF_DIR=./my_proofs python -c "
    import sys; sys.path.insert(0, '.')
    import tlsn_handler
    import yt_dlp
    yt_dlp.main()
    " https://www.youtube.com/watch?v=VIDEO_ID
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import urllib.parse
from pathlib import Path

from yt_dlp.networking.common import (
    Request,
    RequestHandler,
    Response,
    register_preference,
    register_rh,
)
from yt_dlp.networking.exceptions import (
    RequestError,
    TransportError,
    UnsupportedRequest,
)


@register_rh
class TLSNotaryRH(RequestHandler):
    """
    Request handler that routes YouTube API requests through TLS Notary.

    Creates cryptographic proofs that can be verified by third parties,
    proving that specific data came from YouTube's servers.
    """

    RH_NAME = 'tlsnotary'
    _SUPPORTED_URL_SCHEMES = ('https',)
    _SUPPORTED_PROXY_SCHEMES = ()  # No proxy support (TLSN handles connection directly)
    _SUPPORTED_FEATURES = ()

    # Endpoints to notarize
    _NOTARIZE_ENDPOINTS = (
        '/youtubei/v1/player',  # Main video info API
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Configuration via environment variables
        self.tlsn_enabled = os.environ.get('TLSN_ENABLED', '1') == '1'
        self.tlsn_cli = os.environ.get('TLSN_CLI_PATH') or self._find_tlsn_cli()
        self.proof_dir = Path(os.environ.get('TLSN_PROOF_DIR', './proofs'))
        self.proofs: dict[str, dict] = {}  # video_id -> proof info

        # Create proof directory
        if self.tlsn_enabled and self.tlsn_cli:
            self.proof_dir.mkdir(parents=True, exist_ok=True)

    def _find_tlsn_cli(self) -> str | None:
        """Find tlsn-cli binary in common locations."""
        import shutil

        candidates = [
            # In PATH
            'tlsn-cli',
            # Relative to this file
            str(Path(__file__).parent.parent / 'tlsn-cli' / 'target' / 'release' / 'tlsn-cli'),
        ]

        for candidate in candidates:
            if shutil.which(candidate):
                return candidate
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def _validate(self, request: Request):
        """Only handle YouTube innertube API requests when TLSN is enabled."""
        super()._validate(request)

        if not self.tlsn_enabled:
            raise UnsupportedRequest('TLSN notarization is disabled')

        if not self.tlsn_cli:
            raise UnsupportedRequest('tlsn-cli not found')

        # Only intercept specific YouTube API endpoints
        parsed = urllib.parse.urlparse(request.url)

        if not any(parsed.path.startswith(ep) for ep in self._NOTARIZE_ENDPOINTS):
            raise UnsupportedRequest(
                f'TLSNotary only handles YouTube API endpoints: {self._NOTARIZE_ENDPOINTS}'
            )

        # Must be youtube domain
        if 'youtube' not in parsed.netloc and 'googlevideo' not in parsed.netloc:
            raise UnsupportedRequest('Not a YouTube/Google domain')

    def _send(self, request: Request) -> Response:
        """Send request through tlsn-cli and return the response."""
        try:
            headers = self._get_headers(request)
            timeout = self._calculate_timeout(request)

            # Extract video_id from request body
            video_id = self._extract_video_id(request)

            # Prepare proof file paths
            proof_file = self.proof_dir / f'{video_id}_innertube.tlsn'
            response_file = self.proof_dir / f'{video_id}_innertube_response.json'

            # Build tlsn-cli command
            cmd = [
                self.tlsn_cli,
                'notarize',
                '--url', request.url,
                '--method', request.method or 'POST',
                '--output', str(proof_file),
                '--output-response', str(response_file),
                '--json',
            ]

            # Add headers
            for key, value in headers.items():
                cmd.extend(['--header', f'{key}: {value}'])

            # Add body for POST requests
            if request.data:
                body_data = request.data
                if hasattr(body_data, 'read'):
                    body_data = body_data.read()
                if isinstance(body_data, bytes):
                    body_data = body_data.decode('utf-8')
                cmd.extend(['--body', body_data])

            # Log the notarization attempt
            if self._logger:
                self._logger.debug(f'[tlsn] Notarizing innertube request for {video_id}')

            # Run tlsn-cli
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or 120,
            )

            if result.returncode != 0:
                raise TransportError(f'tlsn-cli failed: {result.stderr}')

            # Parse tlsn-cli output
            try:
                cli_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                cli_output = {}

            # Read the response body
            if not response_file.exists():
                raise TransportError('tlsn-cli did not create response file')

            response_body = response_file.read_bytes()

            # Store proof info for later retrieval
            self.proofs[video_id] = {
                'innertube_proof': str(proof_file),
                'innertube_response': str(response_file),
                'endpoint': 'player',
                'cli_output': cli_output,
            }

            if self._logger:
                self._logger.debug(f'[tlsn] Proof saved: {proof_file}')

            # Return Response object
            return Response(
                fp=io.BytesIO(response_body),
                url=request.url,
                headers={'Content-Type': 'application/json'},
                status=cli_output.get('status_code', 200),
            )

        except RequestError:
            raise
        except subprocess.TimeoutExpired as e:
            raise TransportError(f'tlsn-cli timed out after {timeout}s') from e
        except Exception as e:
            raise TransportError(f'TLSN notarization failed: {e}') from e

    def _extract_video_id(self, request: Request) -> str:
        """Extract video_id from the request body."""
        try:
            body_data = request.data
            if hasattr(body_data, 'read'):
                # Reset position if possible
                if hasattr(body_data, 'seek'):
                    body_data.seek(0)
                body_data = body_data.read()
                if hasattr(request.data, 'seek'):
                    request.data.seek(0)

            if isinstance(body_data, bytes):
                body_data = body_data.decode('utf-8')

            data = json.loads(body_data)
            return data.get('videoId', 'unknown')
        except Exception:
            return 'unknown'

    def get_proof(self, video_id: str) -> dict | None:
        """Get proof info for a video_id (for PostProcessor to pick up)."""
        return self.proofs.get(video_id)

    def close(self):
        """Cleanup."""
        pass


@register_preference(TLSNotaryRH)
def tlsn_preference(rh: TLSNotaryRH, request: Request) -> int:
    """
    Give TLSNotaryRH high priority for YouTube player API requests.

    Returns higher score = higher priority.
    Other handlers (urllib, requests) have base score of 0.
    """
    if not rh.tlsn_enabled or not rh.tlsn_cli:
        return 0

    parsed = urllib.parse.urlparse(request.url)

    # Highest priority for player endpoint (main video info)
    if '/youtubei/v1/player' in parsed.path:
        return 1000

    # Lower priority for other YouTube API endpoints
    if '/youtubei/v1/' in parsed.path:
        return 500

    return 0


def get_proofs() -> dict[str, dict]:
    """
    Get all collected proofs from the registered handler.

    Returns dict mapping video_id to proof info:
    {
        'VIDEO_ID': {
            'innertube_proof': '/path/to/proof.tlsn',
            'innertube_response': '/path/to/response.json',
            'endpoint': 'player',
        }
    }
    """
    from yt_dlp.networking.common import _REQUEST_HANDLERS
    handler = _REQUEST_HANDLERS.get('TLSNotary')
    if handler and hasattr(handler, 'proofs'):
        return handler.proofs
    return {}
