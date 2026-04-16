"""
Pipeline Orchestrator
Runs all enabled sources, then saves the updated hash store.

Usage:
    python -m pipeline.run                    # run all sources
    python -m pipeline.run --sources nvd      # run one source
    python -m pipeline.run --sources nvd owasp pdf markdown
"""

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on path when run as a module
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.shared import load_hashes, save_hashes
from pipeline.sources import nvd, owasp, pdf_local, markdown_local

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

# Registry — add new sources here as you build them
SOURCES = {
    "nvd":      nvd.fetch_and_chunk,
    "owasp":    owasp.fetch_and_chunk,
    "pdf":      pdf_local.fetch_and_chunk,
    "markdown": markdown_local.fetch_and_chunk,
}


def run(sources: list[str] | None = None):
    Path("./data").mkdir(parents=True, exist_ok=True)
    hashes = load_hashes()
    total_updated = 0

    active = sources or list(SOURCES.keys())

    for name in active:
        if name not in SOURCES:
            log.warning(f"Unknown source '{name}', skipping. Available: {list(SOURCES.keys())}")
            continue
        log.info(f"--- Running source: {name} ---")
        hashes, updated = SOURCES[name](hashes)
        total_updated += updated

    save_hashes(hashes)
    log.info(f"Pipeline complete. {total_updated} total new/updated items. Chunks ready in ./data/chunks/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG ingestion pipeline")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=list(SOURCES.keys()),
        help="Which sources to run (default: all)",
    )
    args = parser.parse_args()
    run(args.sources)
