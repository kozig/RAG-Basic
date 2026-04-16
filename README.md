## Simple RAG setup for use with any LLM

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
