"""
Deep file scanner for comprehensive secret detection via GitGuardian API.

This module provides API-based file scanning for the machine scan --deep mode,
using GitGuardian's 500+ secret detectors for comprehensive coverage.
"""

import concurrent.futures
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from pygitguardian import GGClient
from pygitguardian.models import Detail, MultiScanResult

from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import QuotaLimitReachedError, handle_api_error
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


logger = logging.getLogger(__name__)

# GitGuardian API does not accept paths longer than this
_API_PATH_MAX_LENGTH = 256

# Metadata overhead to account for in payload size calculations
_SIZE_METADATA_OVERHEAD = 10240  # 10 KB

# File extensions to scan in deep mode (text-based config files)
DEEP_SCAN_EXTENSIONS = frozenset(
    {
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".cfg",
        ".properties",
        ".xml",
    }
)

# Binary file extensions to skip entirely
BINARY_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".pyc",
        ".pyo",
        ".class",
        ".o",
        ".obj",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
    }
)


@dataclass
class DeepScanResult:
    """Result of a deep file scan."""

    secrets: List[GatheredSecret]
    files_scanned: int
    files_skipped: int
    errors: List[str]


# Type for progress callback: (files_scanned, total_files) -> None
DeepScanProgressCallback = Callable[[int, int], None]


class DeepFileScanner:
    """
    Scans files via GitGuardian API for comprehensive secret detection.

    Uses ThreadPoolExecutor for parallel batch processing, reusing patterns
    from the existing secret_scanner.py implementation.
    """

    def __init__(self, client: GGClient):
        """
        Initialise the deep file scanner.

        Args:
            client: Authenticated GitGuardian API client
        """
        self.client = client
        self.max_workers = MAX_WORKERS

        # Get limits from client preferences
        self.max_document_size = client.secret_scan_preferences.maximum_document_size
        self.max_documents_per_scan = (
            client.secret_scan_preferences.maximum_documents_per_scan
        )
        self.max_payload_size = client.maximum_payload_size - _SIZE_METADATA_OVERHEAD

    def scan_files(
        self,
        file_paths: List[Path],
        on_progress: Optional[DeepScanProgressCallback] = None,
    ) -> DeepScanResult:
        """
        Scan files via GitGuardian API for secrets.

        Args:
            file_paths: List of file paths to scan
            on_progress: Optional callback for progress updates

        Returns:
            DeepScanResult with secrets found and statistics
        """
        secrets: List[GatheredSecret] = []
        errors: List[str] = []
        files_scanned = 0
        files_skipped = 0

        # Filter out binary and oversized files
        scannable_paths: List[Path] = []
        for path in file_paths:
            if not self._is_scannable(path):
                files_skipped += 1
                continue
            scannable_paths.append(path)

        total_files = len(scannable_paths)

        if total_files == 0:
            return DeepScanResult(
                secrets=secrets,
                files_scanned=0,
                files_skipped=files_skipped,
                errors=errors,
            )

        # Create batches respecting document count and payload size limits
        batches = list(self._create_batches(scannable_paths))

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="deep_scan",
        ) as executor:
            # Submit all batches
            futures_to_batch = {
                executor.submit(self._scan_batch, batch): batch for batch in batches
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures_to_batch):
                batch = futures_to_batch[future]
                files_scanned += len(batch)

                if on_progress:
                    on_progress(files_scanned, total_files)

                try:
                    batch_secrets = self._process_future(future, batch)
                    secrets.extend(batch_secrets)
                except QuotaLimitReachedError:
                    # Re-raise quota errors - let caller handle
                    raise
                except Exception as e:
                    logger.warning("Deep scan batch failed: %s", str(e))
                    errors.append(f"Batch scan failed: {str(e)}")

        return DeepScanResult(
            secrets=secrets,
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            errors=errors,
        )

    def _is_scannable(self, path: Path) -> bool:
        """
        Check if a file should be scanned.

        Args:
            path: File path to check

        Returns:
            True if the file should be scanned
        """
        # Skip binary files
        suffix = path.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            return False

        # Skip files that are too large
        try:
            file_size = path.stat().st_size
            if file_size > self.max_document_size:
                logger.debug("Skipping oversized file: %s (%d bytes)", path, file_size)
                return False
            if file_size == 0:
                return False
        except OSError:
            return False

        return True

    def _create_batches(self, paths: List[Path]) -> Iterator[List[Path]]:
        """
        Create batches of files respecting API limits.

        Batches respect both document count and payload size limits.

        Args:
            paths: List of file paths to batch

        Yields:
            Batches of file paths
        """
        batch: List[Path] = []
        batch_size = 0

        for path in paths:
            try:
                file_size = path.stat().st_size
            except OSError:
                continue

            # Check if adding this file would exceed limits
            if (
                len(batch) >= self.max_documents_per_scan
                or batch_size + file_size > self.max_payload_size
            ):
                if batch:
                    yield batch
                batch = []
                batch_size = 0

            batch.append(path)
            batch_size += file_size

        if batch:
            yield batch

    def _scan_batch(self, paths: List[Path]) -> MultiScanResult:
        """
        Send a batch of files to the GitGuardian API.

        Args:
            paths: List of file paths to scan

        Returns:
            MultiScanResult from the API
        """
        documents = []
        for path in paths:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                documents.append(
                    {
                        "document": content,
                        "filename": str(path)[-_API_PATH_MAX_LENGTH:],
                    }
                )
            except Exception as e:
                logger.debug("Failed to read file %s: %s", path, e)
                # Include empty document to maintain alignment with paths
                documents.append(
                    {
                        "document": "",
                        "filename": str(path)[-_API_PATH_MAX_LENGTH:],
                    }
                )

        return self.client.multi_content_scan(
            documents,
            extra_headers={"GG-Scan-Context": "machine-deep"},
            all_secrets=True,
        )

    def _process_future(
        self,
        future: concurrent.futures.Future,
        paths: List[Path],
    ) -> List[GatheredSecret]:
        """
        Process a completed scan future and extract secrets.

        Args:
            future: Completed future from executor
            paths: Original file paths for this batch

        Returns:
            List of GatheredSecret objects found
        """
        exception = future.exception()
        if exception is not None:
            raise exception

        result = future.result()

        # Handle API error responses
        if isinstance(result, Detail):
            handle_api_error(result)
            return []

        if not isinstance(result, MultiScanResult):
            logger.warning("Unexpected result type: %s", type(result))
            return []

        secrets: List[GatheredSecret] = []

        for path, scan_result in zip(paths, result.scan_results):
            if not scan_result.policy_breaks:
                continue

            for policy_break in scan_result.policy_breaks:
                # Extract the secret value and field name from matches
                secret_value = ""
                match_name = None
                if policy_break.matches:
                    first_match = policy_break.matches[0]
                    secret_value = first_match.match
                    # match_type contains the field name (e.g., "api_key", "token")
                    match_name = first_match.match_type

                if not secret_value:
                    continue

                secrets.append(
                    GatheredSecret(
                        value=secret_value,
                        metadata=SecretMetadata(
                            source_type=SourceType.DEEP_SCAN,
                            source_path=str(path),
                            secret_name=policy_break.break_type,
                            # Store API response fields to avoid re-calling in analyze
                            detector_name=policy_break.detector_name,
                            validity=policy_break.validity,
                            known_secret=policy_break.known_secret,
                            incident_url=policy_break.incident_url,
                            match_name=match_name,
                        ),
                    )
                )

        return secrets


def is_candidate_for_deep_scan(filename: str) -> bool:
    """
    Check if a file is a candidate for deep scanning based on extension.

    This is used during filesystem traversal to collect files for deep scan.

    Args:
        filename: The filename to check

    Returns:
        True if the file should be collected for deep scanning
    """
    suffix = Path(filename).suffix.lower()
    return suffix in DEEP_SCAN_EXTENSIONS
