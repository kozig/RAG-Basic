"""
Source: NIST NVD CVE API
Fetches recent CVEs and normalises them to indexable text chunks.
"""

import logging
import os
import time
from datetime import datetime, timedelta

import requests

from pipeline.shared import chunk_text, content_hash, save_chunks

log = logging.getLogger(__name__)

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
DAYS_BACK = int(os.getenv("NVD_DAYS_BACK", "7"))


def fetch_and_chunk(hashes: dict) -> tuple[dict, int]:
    """
    Fetch recent CVEs from NVD, chunk, and save.
    Returns updated hashes dict and count of new/updated items.
    """
    cves = _fetch_cves(DAYS_BACK)
    updated = 0

    for item in cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "unknown")

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss_score = metrics[key][0]["cvssData"].get("baseScore")
                break

        weaknesses = cve.get("weaknesses", [])
        cwes = [
            d["value"]
            for w in weaknesses
            for d in w.get("description", [])
            if d["lang"] == "en"
        ]

        text = f"{cve_id}\n\nDescription: {desc}\n\nCVSS Score: {cvss_score}\nCWEs: {', '.join(cwes) if cwes else 'none'}"
        h = content_hash(text)

        if hashes.get(cve_id) == h:
            continue

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
    return hashes, updated


def _fetch_cves(days_back: int) -> list[dict]:
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resultsPerPage": 100,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params, headers=headers, timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
