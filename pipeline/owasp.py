"""
Source: OWASP Web Security Testing Guide (GitHub repo)
Fetches markdown files and chunks by section.
"""

import logging
import time
from datetime import datetime

import requests

from pipeline.shared import chunk_by_section, content_hash, save_chunks

log = logging.getLogger(__name__)

OWASP_REPO_API = "https://api.github.com/repos/OWASP/wstg/git/trees/master?recursive=1"
OWASP_RAW_BASE = "https://raw.githubusercontent.com/OWASP/wstg/master/"


def fetch_and_chunk(hashes: dict) -> tuple[dict, int]:
    """
    Fetch OWASP WSTG markdown files, chunk by section, and save.
    Returns updated hashes dict and count of new/updated items.
    """
    try:
        paths = _fetch_file_list()
    except Exception as e:
        log.error(f"Failed to fetch OWASP file list: {e}")
        return hashes, 0

    updated = 0
    for path in paths:
        try:
            text = _fetch_file(path)
            h = content_hash(text)
            source_id = "owasp_" + path.replace("/", "_").replace(".md", "")

            if hashes.get(source_id) == h:
                continue

            chunks = chunk_by_section(text, max_chunk_size=400)
            save_chunks(
                source_id=source_id,
                chunks=chunks,
                metadata={
                    "source": "owasp_wstg",
                    "path": path,
                    "url": OWASP_RAW_BASE + path,
                    "fetched_at": datetime.utcnow().isoformat(),
                },
            )
            hashes[source_id] = h
            updated += 1
            time.sleep(0.2)
        except Exception as e:
            log.warning(f"Failed to fetch {path}: {e}")

    log.info(f"OWASP: {updated} new/updated files")
    return hashes, updated


def _fetch_file_list() -> list[str]:
    resp = requests.get(OWASP_REPO_API, timeout=30)
    resp.raise_for_status()
    tree = resp.json().get("tree", [])
    return [
        item["path"]
        for item in tree
        if item["path"].endswith(".md") and "document/" in item["path"]
    ]


def _fetch_file(path: str) -> str:
    resp = requests.get(OWASP_RAW_BASE + path, timeout=30)
    resp.raise_for_status()
    return resp.text
