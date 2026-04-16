"""
Shared utilities — chunking, hashing, chunk persistence.
Used by all source modules and the run orchestrator.
"""

import hashlib
import json
from pathlib import Path

CHUNKS_DIR = Path("./data/chunks")
HASH_STORE = Path("./data/hashes.json")


# --- Hashing ---

def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def load_hashes() -> dict:
    if HASH_STORE.exists():
        return json.loads(HASH_STORE.read_text())
    return {}


def save_hashes(hashes: dict):
    HASH_STORE.write_text(json.dumps(hashes, indent=2))


# --- Chunking ---

def chunk_text(text: str, chunk_size: int = 400, overlap: int = 50) -> list[str]:
    """
    Sliding window word-level chunking with overlap.
    Overlap prevents important context from being split cleanly at boundaries.
    """
    words = text.split()
    if not words:
        return []
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i:i + chunk_size])
        if chunk.strip():
            chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


def chunk_by_section(text: str, max_chunk_size: int = 500) -> list[str]:
    """
    Section-aware chunking for markdown — splits on headers first,
    then falls back to word chunking if a section is too large.
    Better than blind word chunking for structured documents.
    """
    import re
    sections = re.split(r'\n(?=#{1,3} )', text)
    chunks = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        words = section.split()
        if len(words) <= max_chunk_size:
            chunks.append(section)
        else:
            # Section too large — fall back to sliding window
            chunks.extend(chunk_text(section, chunk_size=max_chunk_size))
    return chunks


# --- Persistence ---

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
    return len(chunks)
