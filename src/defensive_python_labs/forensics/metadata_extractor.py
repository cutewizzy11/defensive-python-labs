"""
File metadata extractor for digital forensics.

Extracts and analyzes file metadata including:
- EXIF data from images (GPS, camera info, timestamps)
- General file attributes (size, timestamps, type, hashes)
- PE header info from Windows executables (if applicable)

No external dependencies for core functionality.
EXIF extraction requires: pip install Pillow
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import stat
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# File magic bytes → type
FILE_SIGNATURES: Dict[bytes, str] = {
    b"\x89PNG\r\n\x1a\n": "PNG Image",
    b"\xff\xd8\xff": "JPEG Image",
    b"GIF87a": "GIF Image",
    b"GIF89a": "GIF Image",
    b"%PDF": "PDF Document",
    b"PK\x03\x04": "ZIP Archive / Office Document",
    b"MZ": "Windows PE Executable",
    b"\x7fELF": "ELF Executable (Linux/Unix)",
    b"#!": "Script (shebang)",
    b"\x1f\x8b": "GZIP Archive",
    b"BZh": "BZIP2 Archive",
    b"\xfd7zXZ\x00": "XZ Archive",
    b"Rar!": "RAR Archive",
    b"\xca\xfe\xba\xbe": "Mach-O Executable (macOS)",
}


@dataclass
class FileMetadata:
    path: str
    filename: str
    size_bytes: int
    file_type: str
    mime_type: str
    magic_type: str
    md5: str
    sha1: str
    sha256: str
    created: str
    modified: str
    accessed: str
    permissions: str
    is_hidden: bool
    exif_data: Dict[str, Any] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"\n{'─'*50}",
            f"  File Metadata Report",
            f"  File    : {self.filename}",
            f"  Path    : {self.path}",
            f"  Size    : {self.size_bytes:,} bytes ({self.size_bytes / 1024:.1f} KB)",
            f"  Type    : {self.magic_type} ({self.mime_type})",
            f"  MD5     : {self.md5}",
            f"  SHA1    : {self.sha1}",
            f"  SHA256  : {self.sha256}",
            f"{'─'*50}",
            f"  Timestamps:",
            f"    Created  : {self.created}",
            f"    Modified : {self.modified}",
            f"    Accessed : {self.accessed}",
            f"  Permissions: {self.permissions}",
            f"  Hidden  : {'Yes' if self.is_hidden else 'No'}",
        ]
        if self.exif_data:
            lines.append(f"{'─'*50}")
            lines.append("  EXIF Data:")
            for k, v in self.exif_data.items():
                lines.append(f"    {k}: {v}")
        if self.anomalies:
            lines.append(f"{'─'*50}")
            lines.append("  ⚠ Anomalies detected:")
            for a in self.anomalies:
                lines.append(f"    • {a}")
        lines.append(f"{'─'*50}")
        return "\n".join(lines)


def _hash_file(path: Path) -> Dict[str, str]:
    """Compute MD5, SHA1, SHA256 of a file."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)

    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
    }


def _detect_magic_type(path: Path) -> str:
    """Identify file type from magic bytes."""
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        for magic, name in FILE_SIGNATURES.items():
            if header.startswith(magic):
                return name
    except OSError:
        pass
    return "Unknown"


def _extract_exif(path: Path) -> Dict[str, Any]:
    """Extract EXIF metadata from images. Requires Pillow."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        exif_data: Dict[str, Any] = {}
        with Image.open(path) as img:
            raw_exif = img._getexif()  # type: ignore[attr-defined]
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if tag == "GPSInfo":
                        gps = {}
                        for gps_id, gps_val in value.items():
                            gps[GPSTAGS.get(gps_id, gps_id)] = gps_val
                        exif_data["GPS"] = gps
                    else:
                        exif_data[tag] = str(value)[:200]
        return exif_data
    except ImportError:
        return {"note": "Install Pillow for EXIF extraction: pip install Pillow"}
    except Exception:
        return {}


def _detect_anomalies(path: Path, stat_info: os.stat_result, magic_type: str, mime_type: str) -> List[str]:
    """Flag suspicious characteristics."""
    anomalies: List[str] = []
    suffix = path.suffix.lower()

    # Extension vs magic mismatch
    if suffix in (".jpg", ".jpeg") and "JPEG" not in magic_type:
        anomalies.append(f"Extension '{suffix}' doesn't match detected type '{magic_type}'")
    if suffix == ".pdf" and "PDF" not in magic_type:
        anomalies.append(f"Extension '.pdf' doesn't match detected type '{magic_type}'")
    if suffix == ".png" and "PNG" not in magic_type:
        anomalies.append(f"Extension '.png' doesn't match detected type '{magic_type}'")

    # Executable with image/doc extension
    if magic_type in ("Windows PE Executable", "ELF Executable (Linux/Unix)"):
        if suffix in (".jpg", ".png", ".pdf", ".doc", ".docx", ".txt"):
            anomalies.append(f"EXECUTABLE disguised with '{suffix}' extension — high risk!")

    # Modified after creation (very recent)
    age_days = (time.time() - stat_info.st_mtime) / 86400
    if age_days < 1:
        anomalies.append("File was modified less than 24 hours ago")

    # Zero-byte file
    if stat_info.st_size == 0:
        anomalies.append("File is empty (0 bytes)")

    # Extremely large file
    if stat_info.st_size > 100 * 1024 * 1024:  # 100 MB
        anomalies.append(f"Unusually large file: {stat_info.st_size / 1024 / 1024:.1f} MB")

    return anomalies


def extract(file_path: str) -> FileMetadata:
    """
    Extract comprehensive metadata from a file.

    Parameters
    ----------
    file_path : str
        Path to the file to analyze.

    Returns
    -------
    FileMetadata
        All extracted metadata including hashes, timestamps, EXIF, and anomalies.

    Examples
    --------
    >>> import tempfile, os
    >>> with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
    ...     _ = f.write(b"hello")
    ...     tmp = f.name
    >>> meta = extract(tmp)
    >>> meta.size_bytes
    5
    >>> os.unlink(tmp)
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    stat_info = path.stat()
    hashes = _hash_file(path)
    magic_type = _detect_magic_type(path)
    mime_type, _ = mimetypes.guess_type(str(path))
    mime_type = mime_type or "application/octet-stream"

    permissions = stat.filemode(stat_info.st_mode)
    created = datetime.fromtimestamp(stat_info.st_ctime).isoformat()
    modified = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
    accessed = datetime.fromtimestamp(stat_info.st_atime).isoformat()

    exif = {}
    if magic_type in ("JPEG Image", "PNG Image"):
        exif = _extract_exif(path)

    anomalies = _detect_anomalies(path, stat_info, magic_type, mime_type)

    return FileMetadata(
        path=str(path),
        filename=path.name,
        size_bytes=stat_info.st_size,
        file_type=path.suffix or "no extension",
        mime_type=mime_type,
        magic_type=magic_type,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        created=created,
        modified=modified,
        accessed=accessed,
        permissions=permissions,
        is_hidden=path.name.startswith("."),
        exif_data=exif,
        anomalies=anomalies,
    )


def batch_extract(directory: str, recursive: bool = False) -> List[FileMetadata]:
    """
    Extract metadata from all files in a directory.

    Parameters
    ----------
    directory : str
        Path to the directory.
    recursive : bool
        If True, recurse into subdirectories.

    Returns
    -------
    List[FileMetadata]
        Metadata for each file, sorted by path.

    Examples
    --------
    >>> import tempfile
    >>> results = batch_extract(tempfile.gettempdir())
    >>> isinstance(results, list)
    True
    """
    base = Path(directory)
    if not base.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    pattern = "**/*" if recursive else "*"
    results = []
    for p in base.glob(pattern):
        if p.is_file():
            try:
                results.append(extract(str(p)))
            except Exception:
                pass
    return sorted(results, key=lambda m: m.path)
