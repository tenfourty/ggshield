"""
Unit tests for DeepFileScanner.
"""

import concurrent.futures
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pygitguardian.models import Detail, Match, MultiScanResult, PolicyBreak, ScanResult

from ggshield.core.errors import QuotaLimitReachedError
from ggshield.verticals.machine.deep_scanner import (
    BINARY_EXTENSIONS,
    DEEP_SCAN_EXTENSIONS,
    DeepFileScanner,
    DeepScanResult,
    is_candidate_for_deep_scan,
)
from ggshield.verticals.machine.sources import SourceType


def make_mock_client(
    max_document_size: int = 1024 * 1024,
    max_documents_per_scan: int = 20,
    max_payload_size: int = 10 * 1024 * 1024,
) -> MagicMock:
    """Create a mock GGClient with secret_scan_preferences."""
    client = MagicMock()
    client.secret_scan_preferences.maximum_document_size = max_document_size
    client.secret_scan_preferences.maximum_documents_per_scan = max_documents_per_scan
    client.maximum_payload_size = max_payload_size
    return client


def make_policy_break(
    detector_name: str = "generic_api_key",
    break_type: str = "Generic API Key",
    match_value: str = "secret_value",
) -> PolicyBreak:
    """Create a test PolicyBreak."""
    return PolicyBreak(
        break_type=break_type,
        policy="Secrets detection",
        detector_name=detector_name,
        detector_group_name=break_type,
        validity="unknown",
        known_secret=False,
        incident_url=None,
        is_excluded=False,
        is_vaulted=False,
        exclude_reason=None,
        diff_kind=None,
        matches=[
            Match(
                match=match_value,
                match_type="api_key",
                index_start=0,
                index_end=len(match_value),
                line_start=0,
                line_end=0,
            )
        ],
    )


def make_scan_result(policy_breaks: list = None) -> ScanResult:
    """Create a test ScanResult."""
    if policy_breaks is None:
        policy_breaks = []
    return ScanResult(
        policy_break_count=len(policy_breaks),
        policy_breaks=policy_breaks,
        policies=["Secrets detection"],
    )


class TestDeepScanExtensions:
    """Tests for DEEP_SCAN_EXTENSIONS constant."""

    def test_includes_common_config_extensions(self):
        """Test that common config file extensions are included."""
        expected = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf"}
        assert expected.issubset(DEEP_SCAN_EXTENSIONS)

    def test_includes_xml(self):
        """Test that XML is included."""
        assert ".xml" in DEEP_SCAN_EXTENSIONS


class TestBinaryExtensions:
    """Tests for BINARY_EXTENSIONS constant."""

    def test_includes_executable_extensions(self):
        """Test that executable extensions are included."""
        expected = {".exe", ".dll", ".so", ".dylib"}
        assert expected.issubset(BINARY_EXTENSIONS)

    def test_includes_archive_extensions(self):
        """Test that archive extensions are included."""
        expected = {".zip", ".tar", ".gz", ".7z", ".rar"}
        assert expected.issubset(BINARY_EXTENSIONS)

    def test_includes_image_extensions(self):
        """Test that image extensions are included."""
        expected = {".png", ".jpg", ".jpeg", ".gif"}
        assert expected.issubset(BINARY_EXTENSIONS)


class TestIsCandidateForDeepScan:
    """Tests for is_candidate_for_deep_scan function."""

    def test_returns_true_for_json(self):
        """Test that .json files are candidates."""
        assert is_candidate_for_deep_scan("config.json") is True

    def test_returns_true_for_yaml(self):
        """Test that .yaml files are candidates."""
        assert is_candidate_for_deep_scan("settings.yaml") is True
        assert is_candidate_for_deep_scan("settings.yml") is True

    def test_returns_true_for_toml(self):
        """Test that .toml files are candidates."""
        assert is_candidate_for_deep_scan("pyproject.toml") is True

    def test_returns_false_for_python(self):
        """Test that .py files are not candidates."""
        assert is_candidate_for_deep_scan("script.py") is False

    def test_returns_false_for_env_files(self):
        """Test that .env files are not candidates (handled by dedicated matcher)."""
        assert is_candidate_for_deep_scan(".env") is False
        assert is_candidate_for_deep_scan(".env.local") is False

    def test_case_insensitive(self):
        """Test that extension matching is case insensitive."""
        assert is_candidate_for_deep_scan("CONFIG.JSON") is True
        assert is_candidate_for_deep_scan("Settings.YAML") is True


class TestDeepFileScannerInit:
    """Tests for DeepFileScanner initialization."""

    def test_init_with_client(self):
        """Test initialisation with a client."""
        client = make_mock_client(
            max_document_size=500000,
            max_documents_per_scan=10,
            max_payload_size=5000000,
        )

        scanner = DeepFileScanner(client)

        assert scanner.client is client
        assert scanner.max_document_size == 500000
        assert scanner.max_documents_per_scan == 10
        # Payload size should have overhead subtracted
        assert scanner.max_payload_size < 5000000


class TestDeepFileScannerIsScannable:
    """Tests for _is_scannable method."""

    def test_skips_binary_files(self, tmp_path: Path):
        """Test that binary files are skipped."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        for ext in [".exe", ".dll", ".png", ".zip"]:
            binary_file = tmp_path / f"file{ext}"
            binary_file.write_text("content")
            assert scanner._is_scannable(binary_file) is False

    def test_skips_oversized_files(self, tmp_path: Path):
        """Test that oversized files are skipped."""
        client = make_mock_client(max_document_size=100)
        scanner = DeepFileScanner(client)

        large_file = tmp_path / "large.json"
        large_file.write_text("x" * 200)

        assert scanner._is_scannable(large_file) is False

    def test_skips_empty_files(self, tmp_path: Path):
        """Test that empty files are skipped."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")

        assert scanner._is_scannable(empty_file) is False

    def test_skips_missing_files(self, tmp_path: Path):
        """Test that missing files are skipped."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        missing_file = tmp_path / "missing.json"

        assert scanner._is_scannable(missing_file) is False

    def test_accepts_valid_files(self, tmp_path: Path):
        """Test that valid files are accepted."""
        client = make_mock_client(max_document_size=1000)
        scanner = DeepFileScanner(client)

        valid_file = tmp_path / "config.json"
        valid_file.write_text('{"key": "value"}')

        assert scanner._is_scannable(valid_file) is True


class TestDeepFileScannerCreateBatches:
    """Tests for _create_batches method."""

    def test_creates_batches_by_document_count(self, tmp_path: Path):
        """Test that batches respect document count limit."""
        client = make_mock_client(
            max_documents_per_scan=3,
            max_payload_size=10 * 1024 * 1024,
        )
        scanner = DeepFileScanner(client)

        # Create 7 files
        paths = []
        for i in range(7):
            f = tmp_path / f"file{i}.json"
            f.write_text(f'{{"id": {i}}}')
            paths.append(f)

        batches = list(scanner._create_batches(paths))

        # Should create 3 batches: [3, 3, 1]
        assert len(batches) == 3
        assert len(batches[0]) == 3
        assert len(batches[1]) == 3
        assert len(batches[2]) == 1

    def test_creates_batches_by_payload_size(self, tmp_path: Path):
        """Test that batches respect payload size limit."""
        client = make_mock_client(
            max_documents_per_scan=100,
            max_payload_size=100 + 10240,  # 100 bytes + overhead
        )
        scanner = DeepFileScanner(client)

        # Create files that are 50 bytes each
        paths = []
        for i in range(5):
            f = tmp_path / f"file{i}.json"
            f.write_text("x" * 50)
            paths.append(f)

        batches = list(scanner._create_batches(paths))

        # Each batch should have at most 2 files (100 bytes payload)
        assert all(len(batch) <= 2 for batch in batches)

    def test_handles_empty_paths(self):
        """Test that empty paths list yields no batches."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        batches = list(scanner._create_batches([]))

        assert batches == []

    def test_skips_files_that_cannot_be_read(self, tmp_path: Path):
        """Test that files that cannot be stat'd are skipped."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        # Create one valid file
        valid = tmp_path / "valid.json"
        valid.write_text("content")

        # Include a non-existent file
        missing = tmp_path / "missing.json"

        batches = list(scanner._create_batches([valid, missing]))

        # Should only include the valid file
        assert len(batches) == 1
        assert batches[0] == [valid]


class TestDeepFileScannerScanBatch:
    """Tests for _scan_batch method."""

    def test_creates_documents_with_content(self, tmp_path: Path):
        """Test that documents are created with file content."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(scan_results=[])

        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text('{"api_key": "secret123"}')

        scanner._scan_batch([file1])

        call_args = client.multi_content_scan.call_args
        documents = call_args[0][0]
        assert len(documents) == 1
        assert documents[0]["document"] == '{"api_key": "secret123"}'

    def test_truncates_long_filenames(self, tmp_path: Path):
        """Test that long filenames are truncated."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(scan_results=[])

        scanner = DeepFileScanner(client)

        # Create a file with a very long path using nested directories
        deep_dir = tmp_path
        for i in range(30):
            deep_dir = deep_dir / f"subdir{i:02d}"
        deep_dir.mkdir(parents=True)
        file1 = deep_dir / "config.json"
        file1.write_text("content")

        # Verify the path is longer than 256
        assert len(str(file1)) > 256

        scanner._scan_batch([file1])

        call_args = client.multi_content_scan.call_args
        documents = call_args[0][0]
        assert len(documents[0]["filename"]) <= 256

    def test_passes_correct_headers(self, tmp_path: Path):
        """Test that the correct headers are passed to API."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(scan_results=[])

        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text("content")

        scanner._scan_batch([file1])

        call_args = client.multi_content_scan.call_args
        assert call_args.kwargs["extra_headers"] == {"GG-Scan-Context": "machine-deep"}
        assert call_args.kwargs["all_secrets"] is True

    def test_handles_unreadable_files(self, tmp_path: Path):
        """Test that unreadable files are handled gracefully."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(scan_results=[])

        scanner = DeepFileScanner(client)

        # Create a file then make it unreadable
        file1 = tmp_path / "unreadable.json"
        file1.write_text("content")
        file1.chmod(0o000)

        try:
            scanner._scan_batch([file1])

            # Should still call API with empty document
            call_args = client.multi_content_scan.call_args
            documents = call_args[0][0]
            assert len(documents) == 1
            assert documents[0]["document"] == ""
        finally:
            file1.chmod(0o644)


class TestDeepFileScannerProcessFuture:
    """Tests for _process_future method."""

    def test_extracts_secrets_from_policy_breaks(self, tmp_path: Path):
        """Test that secrets are extracted from policy breaks."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text('{"api_key": "secret123"}')

        # Create a future that returns a MultiScanResult with policy breaks
        future = concurrent.futures.Future()
        future.set_result(
            MultiScanResult(
                scan_results=[
                    make_scan_result([make_policy_break(match_value="secret123")])
                ]
            )
        )

        secrets = scanner._process_future(future, [file1])

        assert len(secrets) == 1
        assert secrets[0].value == "secret123"
        assert secrets[0].metadata.source_type == SourceType.DEEP_SCAN
        assert str(file1) in secrets[0].metadata.source_path

    def test_handles_no_policy_breaks(self, tmp_path: Path):
        """Test handling of results with no policy breaks."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text("clean content")

        future = concurrent.futures.Future()
        future.set_result(MultiScanResult(scan_results=[make_scan_result([])]))

        secrets = scanner._process_future(future, [file1])

        assert len(secrets) == 0

    def test_handles_api_error_detail(self, tmp_path: Path):
        """Test handling of API error responses."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text("content")

        future = concurrent.futures.Future()
        future.set_result(Detail(detail="Rate limited", status_code=429))

        with patch(
            "ggshield.verticals.machine.deep_scanner.handle_api_error"
        ) as mock_handle:
            secrets = scanner._process_future(future, [file1])

        mock_handle.assert_called_once()
        assert len(secrets) == 0

    def test_raises_exception_from_future(self, tmp_path: Path):
        """Test that exceptions from futures are raised."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        file1 = tmp_path / "config.json"
        file1.write_text("content")

        future = concurrent.futures.Future()
        future.set_exception(QuotaLimitReachedError())

        with pytest.raises(QuotaLimitReachedError):
            scanner._process_future(future, [file1])


class TestDeepFileScannerScanFiles:
    """Tests for scan_files method."""

    def test_scan_empty_file_list(self):
        """Test scanning an empty file list."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        result = scanner.scan_files([])

        assert result.secrets == []
        assert result.files_scanned == 0
        assert result.files_skipped == 0
        client.multi_content_scan.assert_not_called()

    def test_scan_all_unscannable_files(self, tmp_path: Path):
        """Test scanning when all files are unscannable."""
        client = make_mock_client()
        scanner = DeepFileScanner(client)

        # Create only binary files
        binary_file = tmp_path / "file.exe"
        binary_file.write_text("binary content")

        result = scanner.scan_files([binary_file])

        assert result.secrets == []
        assert result.files_scanned == 0
        assert result.files_skipped == 1
        client.multi_content_scan.assert_not_called()

    def test_scan_finds_secrets(self, tmp_path: Path):
        """Test that secrets are found in scanned files."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                make_scan_result([make_policy_break(match_value="api_key_12345")])
            ]
        )

        scanner = DeepFileScanner(client)

        config_file = tmp_path / "config.json"
        config_file.write_text('{"api_key": "api_key_12345"}')

        result = scanner.scan_files([config_file])

        assert len(result.secrets) == 1
        assert result.secrets[0].value == "api_key_12345"
        assert result.files_scanned == 1
        assert result.files_skipped == 0

    def test_scan_reports_progress(self, tmp_path: Path):
        """Test that progress callback is called."""
        client = make_mock_client()
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([])]
        )

        scanner = DeepFileScanner(client)

        config_file = tmp_path / "config.json"
        config_file.write_text("content")

        progress_calls = []

        def on_progress(scanned, total):
            progress_calls.append((scanned, total))

        _ = scanner.scan_files([config_file], on_progress=on_progress)

        assert len(progress_calls) >= 1
        # Last progress call should show 1 file scanned
        assert progress_calls[-1][0] == 1

    def test_scan_handles_quota_error(self, tmp_path: Path):
        """Test that QuotaLimitReachedError is propagated."""
        client = make_mock_client()
        client.multi_content_scan.side_effect = QuotaLimitReachedError()

        scanner = DeepFileScanner(client)

        config_file = tmp_path / "config.json"
        config_file.write_text("content")

        with pytest.raises(QuotaLimitReachedError):
            scanner.scan_files([config_file])

    def test_scan_handles_batch_error(self, tmp_path: Path):
        """Test that batch errors are captured in result."""
        client = make_mock_client()
        client.multi_content_scan.side_effect = Exception("Network error")

        scanner = DeepFileScanner(client)

        config_file = tmp_path / "config.json"
        config_file.write_text("content")

        result = scanner.scan_files([config_file])

        assert len(result.errors) == 1
        assert "Network error" in result.errors[0]
        assert result.files_scanned == 1

    def test_scan_multiple_batches(self, tmp_path: Path):
        """Test scanning across multiple batches."""
        client = make_mock_client(max_documents_per_scan=2)
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                make_scan_result([make_policy_break(match_value="secret1")]),
                make_scan_result([make_policy_break(match_value="secret2")]),
            ]
        )

        scanner = DeepFileScanner(client)

        # Create 4 files (will be split into 2 batches)
        paths = []
        for i in range(4):
            f = tmp_path / f"config{i}.json"
            f.write_text(f'{{"secret{i}": "value"}}')
            paths.append(f)

        result = scanner.scan_files(paths)

        # Should have called multi_content_scan twice (2 batches of 2 files)
        assert client.multi_content_scan.call_count == 2
        assert result.files_scanned == 4

    def test_scan_filters_binary_and_oversized(self, tmp_path: Path):
        """Test that binary and oversized files are filtered."""
        client = make_mock_client(max_document_size=50)
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([])]
        )

        scanner = DeepFileScanner(client)

        # Create mixed files
        valid_file = tmp_path / "valid.json"
        valid_file.write_text("small")

        binary_file = tmp_path / "file.exe"
        binary_file.write_text("binary")

        large_file = tmp_path / "large.json"
        large_file.write_text("x" * 100)

        result = scanner.scan_files([valid_file, binary_file, large_file])

        assert result.files_scanned == 1
        assert result.files_skipped == 2


class TestDeepScanResult:
    """Tests for DeepScanResult dataclass."""

    def test_default_values(self):
        """Test default values for DeepScanResult."""
        result = DeepScanResult(
            secrets=[],
            files_scanned=0,
            files_skipped=0,
            errors=[],
        )

        assert result.secrets == []
        assert result.files_scanned == 0
        assert result.files_skipped == 0
        assert result.errors == []
