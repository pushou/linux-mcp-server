"""Suricata eve.json log analysis tools."""

import subprocess

from pathlib import Path
from typing import Optional

import polars as pl

from mcp.types import ToolAnnotations

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.commands import get_command
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.types import Host


# Constants for performance tuning
DEFAULT_TAIL_LINES = 1000  # Default number of lines to read from end of file
MAX_TAIL_LINES = 100000  # Maximum lines to prevent memory issues
ALERTS_TAIL_LINES = 10000  # Lines to read when extracting alerts


def _find_eve_json() -> Path | None:
    """Find eve.json in standard locations.

    Returns:
        Path to eve.json if found, None otherwise
    """
    search_paths = [
        Path("/var/log/suricata/eve.json"),
        Path("/home/tsec/tpotce/data/suricata/log/eve.json"),
        Path("/var/log/eve.json"),
    ]

    for path in search_paths:
        try:
            if path.exists() and path.is_file():
                return path
        except (PermissionError, OSError):
            # Skip paths we don't have permission to access
            continue

    return None


def _validate_path(file_path: str) -> tuple[Path, None] | tuple[None, str]:
    """Validate that file path is in allowed directories and is a valid file.

    Args:
        file_path: Path to validate (can be empty to auto-detect)

    Returns:
        Tuple of (resolved_path, None) if valid, or (None, error_message) if invalid.
    """
    # Auto-detect eve.json if no path provided
    if not file_path or file_path.strip() == "":
        auto_path = _find_eve_json()
        if auto_path:
            return auto_path, None
        return None, "Error: No eve.json file found in standard locations (or insufficient permissions)"

    path = Path(file_path).resolve()
    allowed_dirs = [
        Path("/var/log/suricata"),
        Path("/var/log"),
        Path("/home/tsec/tpotce/data/suricata/log"),
    ]

    if not any(str(path).startswith(str(allowed_dir)) for allowed_dir in allowed_dirs):
        return None, (
            f"Error: File path must be in /var/log/suricata/, /var/log/, "
            f"or /home/tsec/tpotce/data/suricata/log. Got: {file_path}"
        )

    try:
        if not path.exists():
            return None, f"Error: File not found: {file_path}"

        if not path.is_file():
            return None, f"Error: Path is not a file: {file_path}"
    except PermissionError:
        return None, f"Error: Permission denied accessing: {file_path}"
    except OSError as e:
        return None, f"Error: Cannot access file {file_path}: {str(e)}"

    return path, None


def _apply_alert_filters(
    df: pl.DataFrame, severity: int | None, signature_contains: str | None, src_ip: str | None, dest_ip: str | None
) -> tuple[pl.DataFrame, list[str]]:
    """Apply filters to alert DataFrame.

    Args:
        df: Input DataFrame with alerts
        severity: Optional severity filter
        signature_contains: Optional signature text filter
        src_ip: Optional source IP filter
        dest_ip: Optional destination IP filter

    Returns:
        Tuple of (filtered_df, filters_applied_list)
    """
    filters_applied = []

    if severity is not None and "alert" in df.columns:
        df = df.filter(pl.col("alert").struct.field("severity") == severity)
        filters_applied.append(f"severity={severity}")

    if signature_contains and "alert" in df.columns:
        df = df.filter(pl.col("alert").struct.field("signature").str.contains(signature_contains, literal=False))
        filters_applied.append(f"signature contains '{signature_contains}'")

    if src_ip and "src_ip" in df.columns:
        df = df.filter(pl.col("src_ip") == src_ip)
        filters_applied.append(f"src_ip={src_ip}")

    if dest_ip and "dest_ip" in df.columns:
        df = df.filter(pl.col("dest_ip") == dest_ip)
        filters_applied.append(f"dest_ip={dest_ip}")

    return df, filters_applied


@mcp.tool(
    title="Read Suricata eve.json",
    description="Read and parse Suricata eve.json log file (reads from end for large files)",
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def read_suricata_eve_json(
    file_path: str = "",
    event_type: Optional[str] = None,
    limit: Optional[int] = None,
    tail_lines: Optional[int] = None,
    host: Host = None,
) -> str:
    """Read and parse Suricata eve.json log file.

    Args:
        file_path: Path to the eve.json file (default: auto-detect in standard locations)
        event_type: Optional filter by event_type (e.g., 'alert', 'flow', 'dns', 'http')
        limit: Optional limit of rows to return in output (default: 50)
        tail_lines: Number of lines to read from end of file (default: 1000, max: 100000)
        host: Optional remote host to connect to via SSH

    Returns:
        Formatted output with Suricata events

    Security:
        - Read-only operation
        - Path restricted to /var/log/suricata/, /var/log/, and T-Pot CE paths
        - Uses tail to read only recent events from large files
        - Supports remote execution via SSH
    """
    # Validate and set tail_lines
    if tail_lines is None:
        tail_lines = DEFAULT_TAIL_LINES
    elif tail_lines > MAX_TAIL_LINES:
        return f"Error: tail_lines cannot exceed {MAX_TAIL_LINES} (requested: {tail_lines})"
    elif tail_lines < 1:
        return "Error: tail_lines must be at least 1"

    # For remote execution, use tail command
    if host:
        if not file_path or file_path.strip() == "":
            file_path = "/var/log/suricata/eve.json"

        validated_path, error = _validate_path(file_path)
        if error and "Permission denied" not in error and "File not found" not in error:
            return error

        cmd = get_command("read_log_file")
        returncode, stdout, stderr = await cmd.run(host=host, log_path=file_path, lines=tail_lines)

        if returncode != 0:
            # Check for common errors
            if "Permission denied" in stderr:
                return f"Error: Permission denied accessing {file_path} on {host}"
            elif "No such file" in stderr:
                return f"Error: File not found: {file_path} on {host}"
            elif "Device or resource busy" in stderr:
                return f"Error: File {file_path} is currently locked. Try again in a few seconds or reduce tail_lines."
            return f"Error reading remote file: {stderr}"

        # Parse NDJSON content
        try:
            import io

            df = pl.read_ndjson(io.StringIO(stdout))
        except Exception as e:
            return f"Error parsing remote eve.json: {str(e)}"
    else:
        # Local execution - use lazy loading for efficiency
        validated_path, error = _validate_path(file_path)
        if error:
            return error

        assert validated_path is not None

        try:
            # For local files, use tail-like behavior for large files
            file_size = validated_path.stat().st_size
            # If file is larger than 10MB, use tail approach
            if file_size > 10 * 1024 * 1024:
                # Read last N lines using subprocess (faster than Python)
                result = subprocess.run(
                    ["tail", "-n", str(tail_lines), str(validated_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    return f"Error reading file with tail: {result.stderr}"

                import io

                df = pl.read_ndjson(io.StringIO(result.stdout))
            else:
                # Small file - read directly
                df = pl.read_ndjson(validated_path)
        except subprocess.TimeoutExpired:
            return "Error: Timeout reading file. Try reducing tail_lines."
        except PermissionError:
            return f"Error: Permission denied accessing {file_path}"
        except OSError as e:
            if "Device or resource busy" in str(e):
                return f"Error: File {file_path} is currently locked. Try again in a few seconds or reduce tail_lines."
            return f"Error: Cannot access file {file_path}: {str(e)}"
        except Exception as e:
            return f"Error reading Suricata eve.json file: {str(e)}"

    try:
        # Filter by event_type if specified
        if event_type:
            if "event_type" in df.columns:
                df = df.filter(pl.col("event_type") == event_type)
            else:
                return f"Warning: 'event_type' column not found in {file_path}"

        total_rows = len(df)

        # Apply output limit (different from tail_lines)
        display_limit = limit if limit else 50
        df_display = df.head(display_limit)

        # Format output
        host_prefix = f" on {host}" if host else ""
        output_lines = [
            f"Suricata eve.json{host_prefix}: {file_path}",
            f"Read last {tail_lines} lines from file",
            f"Total events found: {total_rows}",
        ]

        if event_type:
            output_lines.append(f"Filtered by event_type: {event_type}")

        if total_rows > display_limit:
            output_lines.append(f"Showing first {display_limit} of {total_rows} events")

        output_lines.append("")
        output_lines.append(str(df_display))

        return "\n".join(output_lines)

    except Exception as e:
        return f"Error processing Suricata eve.json file: {str(e)}"


@mcp.tool(
    title="Extract Suricata alerts",
    description="Extract and analyze Suricata alerts from eve.json log file",
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
async def extract_suricata_alerts(
    file_path: str = "",
    severity: Optional[int] = None,
    signature_contains: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    limit: Optional[int] = None,
    tail_lines: Optional[int] = None,
    host: Host = None,
) -> str:
    """Extract and analyze Suricata alerts from eve.json log file.

    Args:
        file_path: Path to the eve.json file (default: auto-detect in standard locations)
        severity: Optional filter by severity level (1=high, 2=medium, 3=low)
        signature_contains: Optional filter alerts containing this text in signature
        src_ip: Optional filter by source IP address
        dest_ip: Optional filter by destination IP address
        limit: Optional limit of alerts to display (default: 50)
        tail_lines: Number of lines to read from end of file (default: 10000, max: 100000)
        host: Optional remote host to connect to via SSH

    Returns:
        Formatted output with Suricata alerts and statistics

    Security:
        - Read-only operation
        - Path restricted to /var/log/suricata/, /var/log/, and T-Pot CE paths
        - Uses tail to read only recent events from large files
        - Supports remote execution via SSH
    """
    # Validate and set tail_lines
    if tail_lines is None:
        tail_lines = ALERTS_TAIL_LINES
    elif tail_lines > MAX_TAIL_LINES:
        return f"Error: tail_lines cannot exceed {MAX_TAIL_LINES} (requested: {tail_lines})"
    elif tail_lines < 1:
        return "Error: tail_lines must be at least 1"

    # For remote execution, use tail command
    if host:
        if not file_path or file_path.strip() == "":
            file_path = "/var/log/suricata/eve.json"

        validated_path, error = _validate_path(file_path)
        if error and "Permission denied" not in error and "File not found" not in error:
            return error

        cmd = get_command("read_log_file")
        returncode, stdout, stderr = await cmd.run(host=host, log_path=file_path, lines=tail_lines)

        if returncode != 0:
            if "Permission denied" in stderr:
                return f"Error: Permission denied accessing {file_path} on {host}"
            elif "No such file" in stderr:
                return f"Error: File not found: {file_path} on {host}"
            elif "Device or resource busy" in stderr:
                return f"Error: File {file_path} is currently locked. Try again in a few seconds or reduce tail_lines."
            return f"Error reading remote file: {stderr}"

        # Parse NDJSON content
        try:
            import io

            df = pl.read_ndjson(io.StringIO(stdout))
        except Exception as e:
            return f"Error parsing remote eve.json: {str(e)}"
    else:
        # Local execution
        validated_path, error = _validate_path(file_path)
        if error:
            return error

        assert validated_path is not None

        try:
            file_size = validated_path.stat().st_size
            if file_size > 10 * 1024 * 1024:
                result = subprocess.run(
                    ["tail", "-n", str(tail_lines), str(validated_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode != 0:
                    return f"Error reading file with tail: {result.stderr}"

                import io

                df = pl.read_ndjson(io.StringIO(result.stdout))
            else:
                df = pl.read_ndjson(validated_path)
        except subprocess.TimeoutExpired:
            return "Error: Timeout reading file. Try reducing tail_lines."
        except PermissionError:
            return f"Error: Permission denied accessing {file_path}"
        except OSError as e:
            if "Device or resource busy" in str(e):
                return f"Error: File {file_path} is currently locked. Try again in a few seconds or reduce tail_lines."
            return f"Error: Cannot access file {file_path}: {str(e)}"
        except Exception as e:
            return f"Error reading Suricata eve.json file: {str(e)}"

    try:
        # Filter only alert events
        if "event_type" not in df.columns:
            return f"Error: 'event_type' column not found in {file_path}"

        df = df.filter(pl.col("event_type") == "alert")

        if len(df) == 0:
            host_prefix = f" on {host}" if host else ""
            return f"No alerts found{host_prefix} in last {tail_lines} lines of {file_path}"

        # Apply filters
        df, filters_applied = _apply_alert_filters(df, severity, signature_contains, src_ip, dest_ip)

        total_alerts = len(df)

        if total_alerts == 0:
            filter_desc = ", ".join(filters_applied) if filters_applied else "none"
            return f"No alerts found matching filters ({filter_desc}) in last {tail_lines} lines"

        # Apply display limit
        display_limit = limit if limit else 50
        df_limited = df.head(display_limit)

        # Extract relevant alert fields
        alerts_data = []
        for row in df_limited.iter_rows(named=True):
            alert_info = row.get("alert", {})
            alerts_data.append(
                {
                    "timestamp": row.get("timestamp", "N/A"),
                    "signature": alert_info.get("signature", "N/A") if isinstance(alert_info, dict) else "N/A",
                    "severity": alert_info.get("severity", "N/A") if isinstance(alert_info, dict) else "N/A",
                    "category": alert_info.get("category", "N/A") if isinstance(alert_info, dict) else "N/A",
                    "src_ip": row.get("src_ip", "N/A"),
                    "src_port": row.get("src_port", "N/A"),
                    "dest_ip": row.get("dest_ip", "N/A"),
                    "dest_port": row.get("dest_port", "N/A"),
                    "proto": row.get("proto", "N/A"),
                }
            )

        # Create summary statistics
        alerts_df = pl.DataFrame(alerts_data)

        host_prefix = f" on {host}" if host else ""
        output_lines = [
            f"Suricata Alerts Analysis{host_prefix}: {file_path}",
            f"Read last {tail_lines} lines from file",
            f"Total alerts found: {total_alerts}",
        ]

        if filters_applied:
            output_lines.append(f"Filters applied: {', '.join(filters_applied)}")

        if total_alerts > display_limit:
            output_lines.append(f"Showing first {display_limit} of {total_alerts} alerts")

        # Add statistics
        output_lines.append("\n=== Alert Statistics ===")

        if "signature" in alerts_df.columns and len(alerts_df) > 0:
            top_signatures = (
                alerts_df.group_by("signature").agg(pl.len().alias("count")).sort("count", descending=True).head(5)
            )
            output_lines.append("\nTop 5 Alert Signatures:")
            output_lines.append(str(top_signatures))

        if "severity" in alerts_df.columns and len(alerts_df) > 0:
            severity_counts = alerts_df.group_by("severity").agg(pl.len().alias("count")).sort("severity")
            output_lines.append("\nAlerts by Severity:")
            output_lines.append(str(severity_counts))

        # Add detailed alerts
        output_lines.append("\n=== Alert Details ===")
        output_lines.append(str(alerts_df))

        return "\n".join(output_lines)

    except Exception as e:
        return f"Error extracting Suricata alerts: {str(e)}"
