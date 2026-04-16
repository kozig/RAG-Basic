"""
Pentest RAG Ingestion Pipeline - MVP
Sources: NIST NVD API, OWASP Testing Guide (GitHub)
"""

import os
import json
import hashlib
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# --- Config ---
DATA_DIR = Path("./data")
HASH_STORE = DATA_DIR / "hashes.json"
CHUNKS_DIR = DATA_DIR / "chunks"
NVD_API_KEY = os.getenv("NVD", "")  # optional but raises rate limits
DAYS_BACK = 7  # how far back to fetch CVEs on each run


# --- Utilities ---

def load_hashes() -> dict:
    if HASH_STORE.exists():
        return json.loads(HASH_STORE.read_text())
    return {}


def save_hashes(hashes: dict):
    HASH_STORE.write_text(json.dumps(hashes, indent=2))


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def chunk_text(text: str, chunk_size: int = 400, overlap: int = 50) -> list[str]:
    """Simple word-level chunking with overlap."""
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i:i + chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


def save_chunks(source_id: str, chunks: list[str], metadata: dict):
    """Save chunks as JSONL for downstream embedding."""
    CHUNKS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = CHUNKS_DIR / f"{source_id}.jsonl"
    with out_file.open("w") as f:
        for i, chunk in enumerate(chunks):
            record = {
                "id": f"{source_id}_{i}",
                "text": chunk,
                "metadata": metadata,
            }
            f.write(json.dumps(record) + "\n")
    log.info(f"Saved {len(chunks)} chunks → {out_file}")


# --- NVD CVE Fetcher ---

def fetch_nvd_cves(days_back: int = 7) -> list[dict]:
    """
    Fetch recent CVEs from NIST NVD API.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resultsPerPage": 100,
    }
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    log.info(f"Fetching CVEs from NVD ({days_back} days back)...")
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params,
        headers=headers,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def process_nvd(hashes: dict) -> dict:
    cves = fetch_nvd_cves(DAYS_BACK)
    updated = 0

    for item in cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")

        # Extract description
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss_score = metrics[key][0]["cvssData"].get("baseScore")
                break

        # Extract CWEs
        weaknesses = cve.get("weaknesses", [])
        cwes = [
            d["value"]
            for w in weaknesses
            for d in w.get("description", [])
            if d["lang"] == "en"
        ]

        # Build indexable text
        text = f"{cve_id}\n\nDescription: {desc}\n\nCVSS Score: {cvss_score}\nCWEs: {', '.join(cwes)}"
        h = content_hash(text)

        if hashes.get(cve_id) == h:
            continue  # unchanged, skip

        chunks = chunk_text(text, chunk_size=300)
        save_chunks(
            source_id=cve_id.replace("-", "_"),
            chunks=chunks,
            metadata={
                "source": "nvd",
                "cve_id": cve_id,
                "cvss_score": cvss_score or 0.0,
                "cwes": ", ".join(cwes) if cwes else "none",
                "fetched_at": datetime.utcnow().isoformat(),
            },
        )
        hashes[cve_id] = h
        updated += 1

    log.info(f"NVD: {updated} new/updated CVEs out of {len(cves)} fetched")
    return hashes


# --- OWASP Testing Guide Fetcher ---

OWASP_REPO_API = "https://api.github.com/repos/OWASP/wstg/git/trees/master?recursive=1"
OWASP_RAW_BASE = "https://raw.githubusercontent.com/OWASP/wstg/master/"


def fetch_owasp_file_list() -> list[str]:
    """Get all markdown file paths from the OWASP WSTG repo."""
    resp = requests.get(OWASP_REPO_API, timeout=30)
    resp.raise_for_status()
    tree = resp.json().get("tree", [])
    return [
        item["path"]
        for item in tree
        if item["path"].endswith(".md") and "document/" in item["path"]
    ]


def fetch_owasp_file(path: str) -> str:
    url = OWASP_RAW_BASE + path
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.text


def process_owasp(hashes: dict) -> dict:
    log.info("Fetching OWASP WSTG file list...")
    try:
        paths = fetch_owasp_file_list()
    except Exception as e:
        log.error(f"Failed to fetch OWASP file list: {e}")
        return hashes

    updated = 0
    for path in paths:
        try:
            text = fetch_owasp_file(path)
            h = content_hash(text)
            source_id = "owasp_" + path.replace("/", "_").replace(".md", "")

            if hashes.get(source_id) == h:
                continue

            chunks = chunk_text(text, chunk_size=400)
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
            time.sleep(0.2)  # be polite to GitHub
        except Exception as e:
            log.warning(f"Failed to fetch {path}: {e}")

    log.info(f"OWASP: {updated} new/updated files")
    return hashes


# --- Main ---

def run():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    hashes = load_hashes()

    hashes = process_nvd(hashes)
    hashes = process_owasp(hashes)

    save_hashes(hashes)
    log.info("Pipeline complete. Chunks ready for embedding in ./data/chunks/")


if __name__ == "__main__":
    run()
