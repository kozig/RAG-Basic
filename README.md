## Simple RAG setup for use with any LLM
**Setup**
``` bash
git clone https://github.com/kozig/RAG-Basic.git
python -m venv venv
python -r requirements.txt
python pipeline.py
python embedder.py
```

### pipeline.py
#### Hashing
Uses SHA-256 content hashing to ensure only new or changed content gets added to data.
#### Chunking
Uses sliding window with overlap default of 50 words.

### embedder.py
Vector encoding using `all-MiniLM-L6-v2` instead of keyword matching. 
- ID-based deduplication before embedding fetches all existing IDs from ChromaDB and set-subtracts before embedding, avoiding re-computing expensive transformer inference on already-indexed chunks.
- Batch processing chunks are embedded in batches of 64 rather than one at a time. Sentence-transformers parallelises inference across the batch, significantly faster than sequential single-chunk calls.

### mcp_server.py
Semantic similarity search - encode the query to a vector, then ask ChromaDB for the top-k stored vectors by cosine similarity. Returns the original text alongside score.

- Over-fetch + filter pattern - the `where` metadata filter is applied after vector retrieval in ChromaDB, over-fetching compensates for results that get filtered out ensuring you get `top_k` results.
- Lazy singleton initialisation - Both the embedding model and ChromaDB client are initialised once on first tool call and reused for the lifetime of the server process. Avoids reloading model weights on every query.
- top_k capping - Guards against flooding the LLM context window with too many retrieved chunks, which degrades generation quality.conservatively set to max of 10

---

## Claude MCP registration
``` bash
# Register use the absolute path 
claude mcp add pentest-rag -- python /absolute/path/to/mcp_server.py 
# Verify it's connected inside Claude Code 
/mcp
# User scope available in ALL Claude Code sessions (any directory)
claude mcp add pentest-rag --scope user -- python /absolute/path/to/mcp_server.py

# Project scope only available when inside that specific directory (default)
claude mcp add pentest-rag --scope project -- python /absolute/path/to/mcp_server.py

# Local scope project-level but gitignored, not shared with teammates
claude mcp add pentest-rag --scope local -- python /absolute/path/to/mcp_server.py
```

A `--scope user` is usually the right call. A pentest RAG is a personal knowledge base tool you'd want available everywhere not tied to any specific project directory.
 While `--scope project` is useful if you are building an app-specific RAG (e.g. indexing Django home services codebase) and wanted teammates to share the same MCP config. `user` is right for a global pentest tool that lives on your machine.

## Pipeline Usage

```bash
# Run all sources
python -m pipeline.run

# Run specific sources only
python -m pipeline.run --sources pdf markdown
python -m pipeline.run --sources nvd owasp

# Then embed as before
python embedder.py
```

## Dropping in new content

**PDFs** drop files into `./data/input/pdfs/` and run:

```bash
python -m pipeline.run --sources pdf
```

**Markdown** organise by topic subdirectory:

``` bash
data/input/markdown/
    security/
        my-burp-notes.md
    django/
        deployment-tips.md
    biomarkers/
        lab-reference.md
```

The subdirectory name becomes the `source` tag in ChromaDB metadata, so you can search a specific domain with `where={"source": "markdown_security"}` in the MCP server.

## Adding a new source in future

Just create `pipeline/sources/your_source.py` with a `fetch_and_chunk(hashes)` function that returns `(hashes, count)`, then register it in the `SOURCES` dict in `run.py`. Nothing else changes.
