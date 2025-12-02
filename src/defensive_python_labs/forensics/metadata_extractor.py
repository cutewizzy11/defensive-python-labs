"""Helpers for extracting simple metadata from image files.

Uses Pillow to access EXIF data where available.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from PIL import Image, ExifTags


def extract_exif_metadata(path: str | Path) -> Dict[str, Any]:
    """Return a dictionary of EXIF metadata for an image.

    If the file does not exist or contains no EXIF data, an empty dict
    is returned instead of raising.
    """
    img_path = Path(path)
    if not img_path.exists():
        return {}

    try:
        with Image.open(img_path) as img:
            exif_data = img.getexif()
            if not exif_data:
                return {}

            tag_map = {ExifTags.TAGS.get(tag, tag): value for tag, value in exif_data.items()}
            return tag_map
    except OSError:
        # Not an image or cannot be opened
        return {}
