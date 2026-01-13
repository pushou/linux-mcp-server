"""Tests for Suricata eve.json reader tools."""

from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import polars as pl
import pytest

from linux_mcp_server.tools import suricata


@pytest.fixture
def sample_eve_data():
    """Sample Suricata eve.json data."""
    return [
        {
            "timestamp": "2024-01-01T12:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.10",
            "src_port": 54321,
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET MALWARE Suspicious Download",
                "severity": 1,
                "category": "Malware",
            },
        },
        {
            "timestamp": "2024-01-01T12:00:01.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.20",
            "src_port": 12345,
            "dest_ip": "10.0.0.10",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Port Scan Detected",
                "severity": 2,
                "category": "Attempted Information Leak",
            },
        },
        {"timestamp": "2024-01-01T12:00:02.000000+0000", "event_type": "flow", "flow": {"state": "established"}},
        {"timestamp": "2024-01-01T12:00:03.000000+0000", "event_type": "dns", "dns": {"query": "example.com"}},
    ]


@pytest.mark.asyncio
class TestReadSuricataEveJson:
    """Tests for read_suricata_eve_json tool."""

    async def test_rejects_remote_execution(self):
        """Test that remote execution is rejected."""
        # Access the underlying function from the FunctionTool wrapper
        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/eve.json", host="remote-host")

        assert "Error: Remote execution not supported" in result

    @patch("linux_mcp_server.tools.suricata.Path")
    async def test_path_validation_rejects_unauthorized_path(self, mock_path_class):
        """Test that paths outside allowed directories are rejected."""
        # Create a mock that properly handles str() conversion
        mock_resolved = MagicMock(spec=Path)
        mock_resolved.__str__ = MagicMock(return_value="/etc/passwd")
        mock_resolved.exists.return_value = True
        mock_resolved.is_file.return_value = True

        mock_path = MagicMock(spec=Path)
        mock_path.resolve.return_value = mock_resolved
        mock_path_class.return_value = mock_path

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/etc/passwd")

        assert "Error: File path must be in /var/log/suricata/, /var/log/" in result

    @patch("pathlib.Path.exists")
    async def test_file_not_found(self, mock_exists):
        """Test handling of non-existent file."""
        mock_exists.return_value = False

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/eve.json")

        assert "Error: File not found" in result

    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_path_is_not_file(self, mock_exists, mock_is_file):
        """Test handling of non-file path."""
        mock_exists.return_value = True
        mock_is_file.return_value = False

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/file.json")

        assert "Error: Path is not a file" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_successful_read(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test successful reading of eve.json file."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/eve.json")

        assert "Total events: 4" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_filter_by_event_type(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test filtering by event_type."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/eve.json", event_type="alert")

        assert "Filtered by event_type: alert" in result
        assert "Total events: 2" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_limit_rows(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test limiting number of rows returned."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="/var/log/suricata/eve.json", limit=2)

        assert "Showing first 2 events" in result

    @patch("linux_mcp_server.tools.suricata._find_eve_json")
    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    async def test_auto_detect_eve_json(self, mock_read_ndjson, mock_find_eve, sample_eve_data):
        """Test auto-detection of eve.json when no path provided."""
        mock_find_eve.return_value = Path("/var/log/suricata/eve.json")

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="")

        assert "Total events: 4" in result
        mock_find_eve.assert_called_once()

    @patch("linux_mcp_server.tools.suricata._find_eve_json")
    async def test_auto_detect_no_file_found(self, mock_find_eve):
        """Test error when auto-detection finds no file."""
        mock_find_eve.return_value = None

        func = suricata.read_suricata_eve_json.fn
        result = await func(file_path="")

        assert "Error: No eve.json file found" in result


@pytest.mark.asyncio
class TestExtractSuricataAlerts:
    """Tests for extract_suricata_alerts tool."""

    async def test_rejects_remote_execution(self):
        """Test that remote execution is rejected."""
        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json", host="remote-host")

        assert "Error: Remote execution not supported" in result

    @patch("linux_mcp_server.tools.suricata.Path")
    async def test_path_validation_rejects_unauthorized_path(self, mock_path_class):
        """Test that paths outside allowed directories are rejected."""
        # Create a mock that properly handles str() conversion
        mock_resolved = MagicMock(spec=Path)
        mock_resolved.__str__ = MagicMock(return_value="/etc/passwd")
        mock_resolved.exists.return_value = True
        mock_resolved.is_file.return_value = True

        mock_path = MagicMock(spec=Path)
        mock_path.resolve.return_value = mock_resolved
        mock_path_class.return_value = mock_path

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/etc/passwd")

        assert "Error: File path must be in /var/log/suricata/, /var/log/" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_extract_all_alerts(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test extracting all alerts."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json")

        assert "Total alerts: 2" in result
        assert "Alert Statistics" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_filter_by_severity(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test filtering alerts by severity."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json", severity=1)

        assert "severity=1" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_filter_by_signature(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test filtering alerts by signature."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json", signature_contains="MALWARE")

        assert "signature contains 'MALWARE'" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_filter_by_ip(self, mock_exists, mock_is_file, mock_read_ndjson, sample_eve_data):
        """Test filtering alerts by IP address."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json", src_ip="192.168.1.10")

        assert "src_ip=192.168.1.10" in result

    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.exists")
    async def test_no_alerts_found(self, mock_exists, mock_is_file, mock_read_ndjson):
        """Test handling of file with no alerts."""
        mock_exists.return_value = True
        mock_is_file.return_value = True

        df = pl.DataFrame([{"event_type": "flow", "flow": {"state": "established"}}])
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="/var/log/suricata/eve.json")

        assert "No alerts found" in result

    @patch("linux_mcp_server.tools.suricata._find_eve_json")
    @patch("linux_mcp_server.tools.suricata.pl.read_ndjson")
    async def test_auto_detect_eve_json(self, mock_read_ndjson, mock_find_eve, sample_eve_data):
        """Test auto-detection of eve.json when no path provided."""
        mock_find_eve.return_value = Path("/var/log/suricata/eve.json")

        df = pl.DataFrame(sample_eve_data)
        mock_read_ndjson.return_value = df

        func = suricata.extract_suricata_alerts.fn
        result = await func(file_path="")

        assert "Total alerts: 2" in result
        mock_find_eve.assert_called_once()
