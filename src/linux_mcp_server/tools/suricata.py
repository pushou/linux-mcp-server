"""Suricata eve.json log analysis tools."""

from pathlib import Path
from typing import Optional

import polars as pl

from mcp.types import ToolAnnotations

from linux_mcp_server.audit import log_tool_call
from linux_mcp_server.server import mcp
from linux_mcp_server.utils.decorators import disallow_local_execution_in_containers
from linux_mcp_server.utils.types import Host


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
        if path.exists() and path.is_file():
            return path

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
        return None, "Error: No eve.json file found in standard locations"

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

    if not path.exists():
        return None, f"Error: File not found: {file_path}"

    if not path.is_file():
        return None, f"Error: Path is not a file: {file_path}"

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
    description="Read and parse Suricata eve.json log file",
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
@disallow_local_execution_in_containers
async def read_suricata_eve_json(
    file_path: str = "",
    event_type: Optional[str] = None,
    limit: Optional[int] = None,
    host: Host = None,
) -> str:
    """Read and parse Suricata eve.json log file.

    Args:
        file_path: Path to the eve.json file (default: auto-detect in standard locations)
        event_type: Optional filter by event_type (e.g., 'alert', 'flow', 'dns', 'http')
        limit: Optional limit of rows to return (default: None for all rows)
        host: Optional remote host (not supported for this tool)

    Returns:
        Formatted output with Suricata events

    Security:
        - Read-only operation
        - Path restricted to /var/log/suricata/, /var/log/, and T-Pot CE paths
        - Validates file exists and is readable
        - Auto-detects eve.json in standard locations if no path provided
    """
    if host:
        return "Error: Remote execution not supported for Suricata tools"

    validated_path, error = _validate_path(file_path)
    if error:
        return error

    # Type narrowing: at this point validated_path is Path, not None
    assert validated_path is not None

    try:
        # Read NDJSON (newline-delimited JSON) file with Polars
        df = pl.read_ndjson(validated_path)

        # Filter by event_type if specified
        if event_type:
            if "event_type" in df.columns:
                df = df.filter(pl.col("event_type") == event_type)
            else:
                return f"Warning: 'event_type' column not found in {file_path}"

        # Apply limit if specified
        if limit and limit > 0:
            df = df.head(limit)

        # Format output
        total_rows = len(df)
        output_lines = [
            f"Suricata eve.json: {file_path}",
            f"Total events: {total_rows}",
        ]

        if event_type:
            output_lines.append(f"Filtered by event_type: {event_type}")

        if limit:
            output_lines.append(f"Showing first {min(limit, total_rows)} events")

        output_lines.append("")
        output_lines.append(str(df.head(limit or 50)))

        return "\n".join(output_lines)

    except Exception as e:
        return f"Error reading Suricata eve.json file: {str(e)}"


@mcp.tool(
    title="Extract Suricata alerts",
    description="Extract and analyze Suricata alerts from eve.json log file",
    annotations=ToolAnnotations(readOnlyHint=True),
)
@log_tool_call
@disallow_local_execution_in_containers
async def extract_suricata_alerts(
    file_path: str = "",
    severity: Optional[int] = None,
    signature_contains: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    limit: Optional[int] = None,
    host: Host = None,
) -> str:
    """Extract and analyze Suricata alerts from eve.json log file.

    Args:
        file_path: Path to the eve.json file (default: auto-detect in standard locations)
        severity: Optional filter by severity level (1=high, 2=medium, 3=low)
        signature_contains: Optional filter alerts containing this text in signature
        src_ip: Optional filter by source IP address
        dest_ip: Optional filter by destination IP address
        limit: Optional limit of alerts to return (default: None for all alerts)
        host: Optional remote host (not supported for this tool)

    Returns:
        Formatted output with Suricata alerts and statistics

    Security:
        - Read-only operation
        - Path restricted to /var/log/suricata/, /var/log/, and T-Pot CE paths
        - Validates file exists and is readable
        - Auto-detects eve.json in standard locations if no path provided
    """
    if host:
        return "Error: Remote execution not supported for Suricata tools"

    validated_path, error = _validate_path(file_path)
    if error:
        return error

    # Type narrowing: at this point validated_path is Path, not None
    assert validated_path is not None

    try:
        # Read NDJSON file with Polars
        df = pl.read_ndjson(validated_path)

        # Filter only alert events
        if "event_type" not in df.columns:
            return f"Error: 'event_type' column not found in {file_path}"

        df = df.filter(pl.col("event_type") == "alert")

        if len(df) == 0:
            return f"No alerts found in {file_path}"

        # Apply filters
        df, filters_applied = _apply_alert_filters(df, severity, signature_contains, src_ip, dest_ip)

        # Apply limit if specified
        total_alerts = len(df)
        if limit and limit > 0:
            df = df.head(limit)

        # Extract relevant alert fields
        alerts_data = []
        for row in df.iter_rows(named=True):
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

        output_lines = [
            f"Suricata Alerts Analysis: {file_path}",
            f"Total alerts: {total_alerts}",
        ]

        if filters_applied:
            output_lines.append(f"Filters applied: {', '.join(filters_applied)}")

        if limit and total_alerts > limit:
            output_lines.append(f"Showing first {limit} of {total_alerts} alerts")

        # Add statistics
        output_lines.append("\n=== Alert Statistics ===")

        if "signature" in alerts_df.columns:
            top_signatures = (
                alerts_df.group_by("signature").agg(pl.len().alias("count")).sort("count", descending=True).head(5)
            )
            output_lines.append("\nTop 5 Alert Signatures:")
            output_lines.append(str(top_signatures))

        if "severity" in alerts_df.columns:
            severity_counts = alerts_df.group_by("severity").agg(pl.len().alias("count")).sort("severity")
            output_lines.append("\nAlerts by Severity:")
            output_lines.append(str(severity_counts))

        # Add detailed alerts
        output_lines.append("\n=== Alert Details ===")
        output_lines.append(str(alerts_df.head(limit or 50)))

        return "\n".join(output_lines)

    except Exception as e:
        return f"Error extracting Suricata alerts: {str(e)}"
