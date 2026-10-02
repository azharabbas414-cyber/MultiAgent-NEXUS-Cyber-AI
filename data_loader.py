"""
NEXUS Cyber AI — Milestone 2 Data Loader.

Responsibilities:
- Load CSV, Excel and JSON data from local uploads.
- Load supported public files from direct URLs.
- Convert common Google Drive file links to downloadable URLs.
- Inspect and validate datasets.
- Detect likely security/SOC columns.
- Standardize common column-name variations into NEXUS field names.

Google Sheets support is intentionally reserved for a later milestone.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd
import requests

from config import SECURITY_FIELDS, SUPPORTED_EXTENSIONS


COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "event_time", "event_timestamp"],
    "event_id": ["event_id", "eventid", "event", "log_id", "logid"],
    "event_type": ["event_type", "eventtype", "event_category", "category", "type"],
    "source_ip": ["source_ip", "src_ip", "srcip", "source_address", "source_ip_address", "client_ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "dstip", "destination_address", "server_ip"],
    "user": ["user", "username", "user_name", "usr", "account", "account_name"],
    "asset": ["asset", "hostname", "host", "host_name", "device", "device_name", "endpoint"],
    "severity": ["severity", "priority", "risk_level", "alert_severity", "level"],
    "action": ["action", "event_action", "activity", "result", "disposition"],
    "indicator": ["indicator", "ioc", "indicator_value", "observable"],
    "threat_type": ["threat_type", "threat", "attack_type", "malware_type", "technique"],
    "business_service": ["business_service", "service", "application", "business_application"],
    "business_criticality": ["business_criticality", "criticality", "asset_criticality", "business_priority"],
    "incident_id": ["incident_id", "incidentid", "case_id", "caseid", "ticket_id"],
}


def _clean_name(name: Any) -> str:
    value = str(name).strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
    return value


def detect_format(filename: str | None = None, content_type: str | None = None) -> str:
    """Detect supported file format from filename or HTTP content type."""
    name = (filename or "").lower()
    suffix = Path(name).suffix.lower()

    if suffix in {".xlsx", ".xls"}:
        return "Excel"
    if suffix == ".json":
        return "JSON"
    if suffix == ".csv":
        return "CSV"

    ctype = (content_type or "").lower()
    if "spreadsheet" in ctype or "excel" in ctype:
        return "Excel"
    if "json" in ctype:
        return "JSON"
    if "csv" in ctype or "text/plain" in ctype:
        return "CSV"

    return "Unknown"


def _read_bytes(data: bytes, filename: str, file_format: str = "Unknown") -> pd.DataFrame:
    fmt = file_format if file_format != "Unknown" else detect_format(filename)

    if fmt == "CSV":
        return pd.read_csv(io.BytesIO(data))
    if fmt == "Excel":
        return pd.read_excel(io.BytesIO(data))
    if fmt == "JSON":
        try:
            return pd.read_json(io.BytesIO(data))
        except ValueError:
            payload = json.loads(data.decode("utf-8"))
            if isinstance(payload, dict):
                for key in ("data", "records", "results", "items"):
                    if key in payload and isinstance(payload[key], list):
                        return pd.DataFrame(payload[key])
            if isinstance(payload, list):
                return pd.DataFrame(payload)
            raise ValueError("JSON does not contain a tabular list of records.")

    # Fallback for a file whose extension/content-type is unavailable.
    for reader in (
        lambda: pd.read_csv(io.BytesIO(data)),
        lambda: pd.read_excel(io.BytesIO(data)),
        lambda: pd.read_json(io.BytesIO(data)),
    ):
        try:
            return reader()
        except Exception:
            continue

    raise ValueError("Could not determine the file format. Use CSV, Excel, or JSON.")


def load_uploaded_file(uploaded_file) -> pd.DataFrame:
    """Load a Streamlit UploadedFile."""
    data = uploaded_file.getvalue()
    return _read_bytes(data, uploaded_file.name)


def google_drive_download_url(url: str) -> str:
    """Convert common public Google Drive file links to direct-download URLs."""
    patterns = [
        r"/file/d/([a-zA-Z0-9_-]+)",
        r"[?&]id=([a-zA-Z0-9_-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            file_id = match.group(1)
            return f"https://drive.google.com/uc?export=download&id={file_id}"
    return url


def _filename_from_url(url: str, content_type: str | None = None) -> str:
    clean = url.split("?", 1)[0].rstrip("/")
    name = Path(clean).name
    if name and "." in name:
        return name

    ctype = (content_type or "").lower()
    if "json" in ctype:
        return "download.json"
    if "spreadsheet" in ctype or "excel" in ctype:
        return "download.xlsx"
    return "download.csv"


def load_from_url(url: str, timeout: int = 30) -> tuple[pd.DataFrame, str]:
    """Download a public CSV/Excel/JSON file or common Google Drive file link."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")

    is_drive = "drive.google.com" in url
    download_url = google_drive_download_url(url) if is_drive else url

    response = requests.get(
        download_url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "NEXUS-Cyber-AI/1.0"},
    )
    response.raise_for_status()

    filename = _filename_from_url(response.url or url, response.headers.get("Content-Type"))
    file_format = detect_format(filename, response.headers.get("Content-Type"))

    # Google Drive can return a generic content type, so also use the original URL.
    if file_format == "Unknown" and is_drive:
        file_format = detect_format(url)

    df = _read_bytes(response.content, filename, file_format)
    return df, filename


def standardize_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """
    Standardize recognized security column names.

    Returns:
        standardized dataframe, mapping of original -> standardized names
    """
    rename_map: dict[str, str] = {}
    used_targets = set()

    normalized = {_clean_name(col): col for col in df.columns}

    for target, aliases in COLUMN_ALIASES.items():
        if target in df.columns:
            used_targets.add(target)
            continue

        candidates = [target] + aliases
        for alias in candidates:
            source = normalized.get(_clean_name(alias))
            if source is not None and source not in rename_map and target not in used_targets:
                rename_map[source] = target
                used_targets.add(target)
                break

    standardized = df.rename(columns=rename_map).copy()
    return standardized, {str(k): str(v) for k, v in rename_map.items()}


def _is_valid_ip_series(series: pd.Series) -> int:
    import ipaddress
    checked = series.dropna().astype(str).str.strip()
    invalid = 0
    for value in checked:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            invalid += 1
    return invalid


def inspect_dataset(df: pd.DataFrame) -> dict[str, Any]:
    """Create a deterministic, non-AI dataset inspection report."""
    if df is None:
        raise ValueError("No dataset supplied.")

    clean = df.copy()
    clean.columns = [str(c).strip() for c in clean.columns]

    standardized, mapping = standardize_columns(clean)
    normalized_columns = {_clean_name(c): c for c in standardized.columns}

    detected_fields = [field for field in SECURITY_FIELDS if field in standardized.columns]

    invalid_ips = 0
    for field in ("source_ip", "destination_ip"):
        if field in standardized.columns:
            invalid_ips += _is_valid_ip_series(standardized[field])

    invalid_timestamps = 0
    if "timestamp" in standardized.columns:
        parsed = pd.to_datetime(standardized["timestamp"], errors="coerce")
        invalid_timestamps = int(parsed.notna().sum() - parsed.count()) if False else int(
            standardized["timestamp"].notna().sum() - parsed.notna().sum()
        )

    duplicate_rows = int(standardized.duplicated().sum())
    missing_cells = int(standardized.isna().sum().sum())

    security_markers = {
        "timestamp", "source_ip", "destination_ip", "user", "asset",
        "severity", "indicator", "incident_id", "event_type", "threat_type"
    }
    marker_count = len(set(detected_fields) & security_markers)
    security_dataset = marker_count >= 3

    confidence = min(100, round((marker_count / 8) * 100))
    if security_dataset and confidence < 50:
        confidence = 50

    return {
        "rows": int(len(standardized)),
        "columns": int(len(standardized.columns)),
        "column_names": [str(c) for c in standardized.columns],
        "detected_security_fields": detected_fields,
        "missing_cells": missing_cells,
        "duplicate_rows": duplicate_rows,
        "invalid_ips": invalid_ips,
        "invalid_timestamps": invalid_timestamps,
        "security_dataset": security_dataset,
        "security_confidence": confidence,
        "column_mapping": mapping,
        "dtypes": {str(k): str(v) for k, v in standardized.dtypes.items()},
    }


def prepare_dataset(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Standardize columns and return both dataset and inspection results."""
    standardized, mapping = standardize_columns(df)
    report = inspect_dataset(standardized)
    report["column_mapping"] = mapping
    return standardized, report
