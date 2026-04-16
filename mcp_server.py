"""
Pentest RAG - MCP Server
Exposes semantic search over the pentest knowledge base as MCP tools.

Transport: stdio (Claude Code spawns this as a subprocess)
Framework: FastMCP (handles JSON-RPC, stdout buffering, tool registration)

Register with Claude Code:
    claude mcp add pentest-rag -- python /absolute/path/to/mcp_server.py
"""

from pathlib import Path

import sys
import logging
import os
import chromadb
from chromadb.config import Settings
from fastmcp import FastMCP
from sentence_transformers import SentenceTransformer

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
os.environ["TOKENIZERS_PARALLESIM"] = "false" # Suppress tokenizer warning
os.environ["CHROMA_TELEMETRY"] = "false"
os.environ["ANONYMIZED_TELEMETRY"] = "false"
# --- Config ---
CHROMA_DIR = Path(__file__).parent / "data" / "chroma"
COLLECTION_NAME = "pentest_rag"
EMBED_MODEL = "all-MiniLM-L6-v2"

# --- Lazy-loaded singletons (loaded once on first tool call) ---
_model = None
_collection = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        _model = SentenceTransformer(EMBED_MODEL, device="cpu")
    return _model


def get_collection():
    global _collection
    if _collection is None:
        client = chromadb.PersistentClient(
            path=str(CHROMA_DIR),
            settings=Settings(anonymized_telemetry=False),
        )
        _collection = client.get_or_create_collection(name=COLLECTION_NAME)
    return _collection


# --- MCP Server ---
mcp = FastMCP(name="pentest-rag")


@mcp.tool
def semantic_search(query: str, top_k: int = 5) -> list[dict]:
    """
    Search the pentest knowledge base (CVEs, OWASP, Burp docs) by meaning.

    Use this before answering questions about:
    - Specific CVEs or vulnerability classes
    - Attack techniques and payloads
    - OWASP testing methodology
    - Bypass techniques (WAF, auth, SSRF, etc.)

    Args:
        query:  Natural language search query, e.g. "SSRF bypass via DNS rebinding"
        top_k:  Number of results to return (default 5, max 10)

    Returns:
        List of relevant chunks with source metadata and similarity score.
    """
    top_k = min(top_k, 10)  # cap to avoid flooding context window
    model = get_model()
    collection = get_collection()

    query_vector = model.encode([query]).tolist()
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
            "source": meta.get("source", "unknown"),
            "reference": meta.get("cve_id") or meta.get("path") or meta.get("url", ""),
            "cvss_score": meta.get("cvss_score"),
            "score": round(1 - dist, 4),
        })

    return hits


@mcp.tool
def search_cves(query: str, top_k: int = 5) -> list[dict]:
    """
    Search specifically for CVEs matching a vulnerability description or keyword.

    Use when looking for known CVEs related to a specific technology,
    attack vector, or vulnerability class.

    Args:
        query:  e.g. "Apache HTTP Server path traversal" or "authentication bypass JWT"
        top_k:  Number of results to return (default 5)

    Returns:
        List of matching CVE chunks with CVSS scores.
    """
    model = get_model()
    collection = get_collection()

    query_vector = model.encode([query]).tolist()
    results = collection.query(
        query_embeddings=query_vector,
        n_results=top_k * 3,  # over-fetch then filter to CVEs only
        include=["documents", "metadatas", "distances"],
        where={"source": "nvd"},  # filter to NVD source only
    )

    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        hits.append({
            "cve_id": meta.get("cve_id", "unknown"),
            "text": doc,
            "cvss_score": meta.get("cvss_score"),
            "cwes": meta.get("cwes", "none"),
            "score": round(1 - dist, 4),
        })

    # Return top_k after filtering
    return hits[:top_k]


@mcp.tool
def search_owasp(query: str, top_k: int = 5) -> list[dict]:
    """
    Search the OWASP Web Security Testing Guide for methodology and techniques.

    Use when looking for:
    - Testing methodology for a specific vulnerability class
    - How to test for a specific OWASP category
    - Recommended tools and payloads for a test type

    Args:
        query:  e.g. "testing for SQL injection" or "OAuth authorization code flow testing"
        top_k:  Number of results to return (default 5)

    Returns:
        List of matching OWASP guide sections.
    """
    model = get_model()
    collection = get_collection()

    query_vector = model.encode([query]).tolist()
    results = collection.query(
        query_embeddings=query_vector,
        n_results=top_k,
        include=["documents", "metadatas", "distances"],
        where={"source": "owasp_wstg"},
    )

    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        hits.append({
            "text": doc,
            "path": meta.get("path", ""),
            "url": meta.get("url", ""),
            "score": round(1 - dist, 4),
        })

    return hits


@mcp.tool
def kb_status() -> dict:
    """
    Returns the current status of the knowledge base — total chunks, sources breakdown.
    Use to verify the RAG index is populated before running searches.
    """
    try:
        collection = get_collection()
        total = collection.count()

        nvd_results = collection.get(where={"source": "nvd"}, include=[])
        owasp_results = collection.get(where={"source": "owasp_wstg"}, include=[])

        return {
            "status": "ok",
            "total_chunks": total,
            "nvd_cve_chunks": len(nvd_results["ids"]),
            "owasp_chunks": len(owasp_results["ids"]),
            "chroma_path": str(CHROMA_DIR),
            "embed_model": EMBED_MODEL,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    mcp.run()  # FastMCP handles stdio transport + stdout buffering
