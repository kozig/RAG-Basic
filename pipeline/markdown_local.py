"""
Source: Local markdown files (blog posts, notes, documentation, exported web pages)
Drop .md files into ./data/input/markdown/ and run the pipeline.

Supports nested subdirectories — organise by topic:
    data/input/markdown/
        security/
            oauth-notes.md
            burp-tips.md
        django/
            deployment-checklist.md
        biomarkers/
            lab-reference.md
"""

import logging
from datetime import datetime
from pathlib import Path

from pipeline.shared import chunk_by_section, content_hash, save_chunks

log = logging.getLogger(__name__)

MARKDOWN_INPUT_DIR = Path("./data/input/markdown")


def fetch_and_chunk(hashes: dict, source_tag: str = "markdown") -> tuple[dict, int]:
    """
    Process all .md files in the input directory (recursive).
    Subdirectory name is used as a sub-tag for filtering, e.g. 'markdown_security'.
    Returns updated hashes dict and count of new/updated items.
    """
    MARKDOWN_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    md_files = list(MARKDOWN_INPUT_DIR.rglob("*.md"))

    if not md_files:
        log.info(f"Markdown: No files found in {MARKDOWN_INPUT_DIR}")
        return hashes, 0

    updated = 0
    for md_path in md_files:
        try:
            text = md_path.read_text(encoding="utf-8").strip()
            if not text:
                continue

            h = content_hash(text)

            # Build source_id from subdirectory + filename for organisation
            relative = md_path.relative_to(MARKDOWN_INPUT_DIR)
            parts = list(relative.parts)
            slug = "_".join(p.replace(" ", "_").lower() for p in parts)
            slug = slug.replace(".md", "")
            source_id = f"{source_tag}_{slug}"

            # Sub-tag from parent directory if nested (e.g. "markdown_security")
            sub_tag = f"{source_tag}_{parts[0]}" if len(parts) > 1 else source_tag

            if hashes.get(source_id) == h:
                log.info(f"Markdown: {md_path.name} unchanged, skipping")
                continue

            chunks = chunk_by_section(text, max_chunk_size=400)

            save_chunks(
                source_id=source_id,
                chunks=chunks,
                metadata={
                    "source": sub_tag,
                    "filename": md_path.name,
                    "relative_path": str(relative),
                    "fetched_at": datetime.utcnow().isoformat(),
                },
            )
            hashes[source_id] = h
            updated += 1
            log.info(f"Markdown: Indexed {relative} → {len(chunks)} chunks")

        except Exception as e:
            log.error(f"Markdown: Failed to process {md_path}: {e}")

    log.info(f"Markdown: {updated} new/updated files")
    return hashes, updated
