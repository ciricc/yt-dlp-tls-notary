from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

try:
    from .common import PostProcessor
except ImportError:
    from yt_dlp.postprocessor.common import PostProcessor


class TLSNotaryError(Exception):
    """TLS Notary error"""


class TLSNotaryCLI:
    """Wrapper for tlsn-cli binary"""

    def __init__(self, binary_path: str | None = None):
        self.binary = binary_path or self._find_binary()
        if not self.binary:
            raise TLSNotaryError('tlsn-cli binary not found. Build it with: cargo build --release')

    def _find_binary(self) -> str | None:
        # Check common locations
        candidates = [
            # Relative to yt-dlp
            Path(__file__).parent.parent.parent / 'tlsn-cli' / 'target' / 'release' / 'tlsn-cli',
            # In PATH
            'tlsn-cli',
        ]

        for candidate in candidates:
            candidate = str(candidate)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            # Check if in PATH
            try:
                result = subprocess.run(
                    ['which', candidate],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass

        return None

    def notarize(
        self,
        url: str,
        output_path: str,
        method: str = 'GET',
        headers: dict[str, str] | None = None,
        body: str | None = None,
        output_response: str | None = None,
        verbose: bool = False,
    ) -> dict:
        """
        Notarize an HTTP request

        Args:
            url: URL to request
            output_path: Path to save the proof file
            method: HTTP method
            headers: HTTP headers
            body: Request body
            output_response: Path to save response body
            verbose: Enable verbose output

        Returns:
            dict with notarization result
        """
        cmd = [
            self.binary,
            'notarize',
            '--url', url,
            '--method', method,
            '--output', output_path,
            '--json',
        ]

        if headers:
            for key, value in headers.items():
                cmd.extend(['--header', f'{key}: {value}'])

        if body:
            cmd.extend(['--body', body])

        if output_response:
            cmd.extend(['--output-response', output_response])

        if verbose:
            cmd.append('--verbose')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise TLSNotaryError(f'tlsn-cli failed: {result.stderr}')

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            raise TLSNotaryError('tlsn-cli timed out')
        except json.JSONDecodeError as e:
            raise TLSNotaryError(f'Failed to parse tlsn-cli output: {e}')

    def inspect(self, proof_path: str) -> dict:
        """Inspect a proof file"""
        cmd = [self.binary, 'inspect', '--proof', proof_path, '--format', 'json']

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise TLSNotaryError(f'Failed to inspect proof: {result.stderr}')

        return json.loads(result.stdout)

    def notarize_stream(
        self,
        url: str,
        output_dir: str,
        headers: dict[str, str] | None = None,
        output_file: str | None = None,
        chunk_size: int = 1024000,
        workers: int = 10,
        rps_limit: float | None = 2.0,
        verbose: bool = False,
        progress_callback=None,
    ) -> dict:
        """
        Notarize a stream/file download in chunks for full verification

        Args:
            url: URL to download
            output_dir: Directory to save proofs and manifest
            headers: HTTP headers
            output_file: Path to save the downloaded file
            chunk_size: Size of each chunk (default: 1MB)
            workers: Number of parallel workers (default: 10, max: 30)
            rps_limit: Rate limit for HTTP requests per second (default: 2.0)
            verbose: Enable verbose output
            progress_callback: Callback for progress updates

        Returns:
            dict with stream notarization result
        """
        cmd = [
            self.binary,
            'notarize-stream',
            '--url', url,
            '--output-dir', output_dir,
            '--chunk-size', str(chunk_size),
            '--workers', str(min(max(workers, 1), 30)),
            '--json',
        ]

        if rps_limit is not None:
            cmd.extend(['--rps-limit', str(rps_limit)])

        if headers:
            for key, value in headers.items():
                cmd.extend(['--header', f'{key}: {value}'])

        if output_file:
            cmd.extend(['--output-file', output_file])

        if verbose:
            cmd.append('--verbose')

        try:
            # For stream notarization, we need a longer timeout
            # Estimate: ~5 seconds per chunk
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour max
            )

            if result.returncode != 0:
                raise TLSNotaryError(f'tlsn-cli stream notarization failed: {result.stderr}')

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            raise TLSNotaryError('tlsn-cli stream notarization timed out (>1 hour)')
        except json.JSONDecodeError as e:
            raise TLSNotaryError(f'Failed to parse tlsn-cli output: {e}')

    def verify_stream(self, manifest_path: str, output: str | None = None) -> dict:
        """
        Verify a stream from its manifest and optionally reconstruct the file

        Args:
            manifest_path: Path to the manifest.json file
            output: Optional path to save reconstructed file

        Returns:
            dict with verification result
        """
        cmd = [
            self.binary,
            'verify-stream',
            '--manifest', manifest_path,
            '--json',
        ]

        if output:
            cmd.extend(['--output', output])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise TLSNotaryError(f'Failed to verify stream: {result.stderr}')

        return json.loads(result.stdout)


class TLSNotaryPP(PostProcessor):
    """
    PostProcessor that creates TLS Notary proofs for downloaded content.

    This creates cryptographic proofs that the video metadata was fetched
    from a specific server (e.g., YouTube), which can be verified by third parties.
    """

    def __init__(self, downloader=None, proof_dir: str | None = None, verbose: bool = False):
        super().__init__(downloader)
        self.proof_dir = proof_dir
        self.verbose = verbose
        self._cli = None

    @property
    def cli(self) -> TLSNotaryCLI:
        if self._cli is None:
            try:
                self._cli = TLSNotaryCLI()
            except TLSNotaryError as e:
                self.report_warning(f'TLS Notary not available: {e}')
                raise
        return self._cli

    def run(self, info):
        # Get the webpage URL to notarize
        webpage_url = info.get('webpage_url') or info.get('original_url')
        if not webpage_url:
            self.to_screen('No webpage URL to notarize')
            return [], info

        # Only notarize HTTPS URLs
        if not webpage_url.startswith('https://'):
            self.to_screen(f'Skipping non-HTTPS URL: {webpage_url}')
            return [], info

        # Determine proof output path
        if self.proof_dir:
            proof_dir = Path(self.proof_dir)
        else:
            # Save next to the video file
            filepath = info.get('filepath') or info.get('_filename')
            if filepath:
                proof_dir = Path(filepath).parent
            else:
                proof_dir = Path('.')

        proof_dir.mkdir(parents=True, exist_ok=True)

        video_id = info.get('id', 'unknown')
        proof_path = proof_dir / f'{video_id}.tlsn'

        self.to_screen(f'Creating TLS Notary proof for {webpage_url}')

        try:
            result = self.cli.notarize(
                url=webpage_url,
                output_path=str(proof_path),
                headers={'User-Agent': 'Mozilla/5.0 (compatible; yt-dlp)'},
                verbose=self.verbose,
            )

            self.to_screen(
                f'TLS Notary proof created: {proof_path} '
                f'(sent: {result["sent_bytes"]}B, recv: {result["recv_bytes"]}B)',
            )

            # Add proof info to the info dict
            info['__tlsnotary_proof'] = str(proof_path)
            info['__tlsnotary_result'] = result

        except TLSNotaryError as e:
            self.report_warning(f'Failed to create TLS Notary proof: {e}')

        return [], info


class TLSNotaryStreamPP(PostProcessor):
    """
    PostProcessor that creates TLS Notary proofs for the full video file.

    This downloads the video in chunks via notarized HTTPS requests,
    creating cryptographic proofs for each chunk. The complete video
    can be reconstructed and verified from these proofs.

    Performance: ~75 KB/s with default settings (10 workers, RPS limit 2).
    A 10MB video takes ~2 minutes.
    """

    def __init__(
        self,
        downloader=None,
        proof_dir: str | None = None,
        chunk_size: int | str = 1024000,
        workers: int | str = 10,
        rps_limit: float | str | None = 2.0,
        verbose: bool = False,
    ):
        super().__init__(downloader)
        self.proof_dir = proof_dir
        self.chunk_size = int(chunk_size)
        self.workers = min(max(int(workers), 1), 30)
        self.rps_limit = float(rps_limit) if rps_limit is not None else None
        self.verbose = verbose
        self._cli = None

    @property
    def cli(self) -> TLSNotaryCLI:
        if self._cli is None:
            try:
                self._cli = TLSNotaryCLI()
            except TLSNotaryError as e:
                self.report_warning(f'TLS Notary not available: {e}')
                raise
        return self._cli

    def run(self, info):
        # Get the direct video URL to notarize
        url = info.get('url')
        if not url:
            self.to_screen('No direct URL to notarize')
            return [], info

        # Only notarize HTTPS URLs
        if not url.startswith('https://'):
            self.to_screen(f'Skipping non-HTTPS URL for stream notarization: {url}')
            return [], info

        # Determine proof output directory
        if self.proof_dir:
            proof_dir = Path(self.proof_dir)
        else:
            filepath = info.get('filepath') or info.get('_filename')
            if filepath:
                proof_dir = Path(filepath).parent
            else:
                proof_dir = Path('.')

        video_id = info.get('id', 'unknown')
        stream_proof_dir = proof_dir / f'{video_id}_tlsn_stream'

        self.to_screen(f'Starting TLS Notary stream notarization for {video_id}')
        self.to_screen(f'  URL: {url[:80]}...' if len(url) > 80 else f'  URL: {url}')
        self.to_screen(f'  Workers: {self.workers}, RPS limit: {self.rps_limit}')

        # Check for innertube proof from extractor (proves video_id -> CDN URL)
        innertube_proof = None
        if hasattr(self._downloader, '_tlsn_proofs'):
            innertube_proof = self._downloader._tlsn_proofs.get(video_id)
            if innertube_proof:
                self.to_screen(f'  Innertube proof found: {innertube_proof["innertube_proof"]}')

        try:
            result = self.cli.notarize_stream(
                url=url,
                output_dir=str(stream_proof_dir),
                headers={'User-Agent': 'Mozilla/5.0 (compatible; yt-dlp)'},
                chunk_size=self.chunk_size,
                workers=self.workers,
                rps_limit=self.rps_limit,
                verbose=self.verbose,
            )

            self.to_screen(
                f'TLS Notary stream proof created: {result["manifest_path"]} '
                f'({result["chunks_count"]} chunks, {result["total_size"]} bytes, '
                f'{result["duration_secs"]:.1f}s)',
            )

            # Add proof info to the info dict
            info['__tlsnotary_stream_manifest'] = result['manifest_path']
            info['__tlsnotary_stream_result'] = result

            # If we have innertube proof, update manifest to include it
            if innertube_proof:
                self._add_innertube_to_manifest(
                    result['manifest_path'],
                    innertube_proof,
                    video_id,
                    url,
                )

        except TLSNotaryError as e:
            self.report_warning(f'Failed to create TLS Notary stream proof: {e}')

        return [], info

    def _add_innertube_to_manifest(self, manifest_path, innertube_proof, video_id, cdn_url):
        """Add innertube proof reference to the stream manifest"""
        import shutil

        try:
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)

            # Copy innertube proof to stream proof directory
            proof_dir = Path(manifest_path).parent
            innertube_dest = proof_dir / 'innertube.tlsn'
            shutil.copy(innertube_proof['innertube_proof'], innertube_dest)

            # Add metadata section to manifest
            manifest['metadata'] = {
                'video_id': video_id,
                'innertube_proof': 'innertube.tlsn',
                'cdn_url_verified': cdn_url in open(innertube_proof['innertube_response']).read(),
            }

            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)

            self.to_screen(f'  Added innertube proof to manifest (video_id: {video_id})')

        except Exception as e:
            self.report_warning(f'Failed to add innertube proof to manifest: {e}')
