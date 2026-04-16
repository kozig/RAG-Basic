"""
Embedding Layer
Reads chunks from ./data/chunks/*.jsonl
Embeds with sentence-transformers
Stores in ChromaDB (persistent local)
"""

import json
import logging
from pathlib import Path

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# --- Config ---
CHUNKS_DIR = Path("./data/chunks")
CHROMA_DIR = Path("./data/chroma")
COLLECTION_NAME = "pentest_rag"
EMBED_MODEL = "all-MiniLM-L6-v2"  # 384-dim, fast, good quality
BATCH_SIZE = 64


def load_chunks() -> list[dict]:
    """Load all JSONL chunk files from the chunks directory."""
    records = []
    for jsonl_file in CHUNKS_DIR.glob("*.jsonl"):
        with jsonl_file.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    log.info(f"Loaded {len(records)} total chunks from {CHUNKS_DIR}")
    return records


def get_existing_ids(collection) -> set[str]:
    """Fetch all IDs already stored in the collection."""
    result = collection.get(include=[])  # only fetch IDs, no embeddings/docs
    return set(result["ids"])


def embed_and_store(records: list[dict], collection, model: SentenceTransformer):
    """
    Filter to only new chunks, embed in batches, upsert into ChromaDB.
    ChromaDB upsert is idempotent but we pre-filter to avoid re-embedding.
    """
    existing_ids = get_existing_ids(collection)
    new_records = [r for r in records if r["id"] not in existing_ids]

    if not new_records:
        log.info("No new chunks to embed — collection is up to date.")
        return

    log.info(f"Embedding {len(new_records)} new chunks (skipping {len(records) - len(new_records)} existing)...")

    for i in range(0, len(new_records), BATCH_SIZE):
        batch = new_records[i:i + BATCH_SIZE]

        ids = [r["id"] for r in batch]
        texts = [r["text"] for r in batch]
        metadatas = [r["metadata"] for r in batch]

        embeddings = model.encode(texts, show_progress_bar=False).tolist()

        collection.upsert(
            ids=ids,
            embeddings=embeddings,
            documents=texts,
            metadatas=metadatas,
        )

        log.info(f"  Upserted batch {i // BATCH_SIZE + 1} ({len(batch)} chunks)")

    log.info(f"Done. Collection now has {collection.count()} total chunks.")


def query(collection, model: SentenceTransformer, query_text: str, top_k: int = 5) -> list[dict]:
    """
    Semantic search — convert query to vector, find top_k similar chunks.
    Returns list of dicts with text, metadata, and distance score.
    """
    query_vector = model.encode([query_text]).tolist()
    results = collection.query(
        query_embeddings=query_vector,
        n_results=top_k,
        include=["documents", "metadatas", "distances"],
    )

    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        hits.append({
            "text": doc,
            "metadata": meta,
            "score": round(1 - dist, 4),  # convert distance → similarity score
        })
    return hits


def print_results(hits: list[dict]):
    for i, hit in enumerate(hits, 1):
        print(f"\n--- Result {i} (score: {hit['score']}) ---")
        print(f"Source: {hit['metadata'].get('source')} | {hit['metadata'].get('cve_id', hit['metadata'].get('path', ''))}")
        print(hit["text"][:300] + "..." if len(hit["text"]) > 300 else hit["text"])


def build():
    """Run the full indexing pipeline."""
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)

    log.info(f"Loading embedding model: {EMBED_MODEL}")
    model = SentenceTransformer(EMBED_MODEL)

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        settings=Settings(anonymized_telemetry=False),
    )
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},  # cosine similarity
    )

    records = load_chunks()
    embed_and_store(records, collection, model)


def search(query_text: str, top_k: int = 5):
    """Standalone search — useful for testing retrieval quality."""
    log.info(f"Loading embedding model: {EMBED_MODEL}")
    model = SentenceTransformer(EMBED_MODEL)

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        settings=Settings(anonymized_telemetry=False),
    )
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    hits = query(collection, model, query_text, top_k)
    print_results(hits)
    return hits


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "search":
        # Usage: python embedder.py search "SQL injection bypass WAF"
        query_text = " ".join(sys.argv[2:])
        search(query_text)
    else:
        build()
