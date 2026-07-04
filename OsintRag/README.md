# OsintRag — OSINT-Optimized Hybrid RAG Memory (PowerShell 7.4+)

A native PowerShell persistent-state / retrieval layer for AI-driven OSINT work.
It performs structural chunking of tool output, dense embedding via a swappable
REST endpoint, a local BM25 sparse index, SIMD cosine similarity, and Reciprocal
Rank Fusion (RRF) of the dense + sparse rankings. **No Python dependency** — it
runs on a clean Kali Linux or Windows node with `pwsh` and .NET 8.

## Layout

```
OsintRag/
├── OsintRag.psd1                     # module manifest
├── OsintRag.psm1                     # loader + tensor backend probe
├── lib/System.Numerics.Tensors.dll   # vendored .NET 8 TensorPrimitives (fast path)
├── Public/
│   ├── Split-OsintData.ps1           # structural chunking (JSON / Nmap XML / text)
│   ├── Get-DenseVector.ps1           # embedding REST client (Ollama / OpenAI-compatible)
│   ├── Add-OsintMemory.ps1           # in-memory store (+ Get-/Clear-OsintMemory)
│   ├── Search-OsintIndex.ps1         # hybrid dense + BM25 + RRF engine
│   └── Export-OsintGraph.ps1         # entity/indicator graph (JSON or GraphViz DOT)
├── Private/
│   ├── Measure-CosineSimilarity.ps1  # TensorPrimitives fast path + managed fallback
│   ├── Invoke-BM25Scoring.ps1        # local Okapi BM25 (k1=1.5, b=0.75)
│   └── OsintRag.Common.ps1           # flatten / entity-type / indicator helpers
└── Tests/OsintRag.Tests.ps1          # Pester 5 suite (mocked embedding API)
```

## Quick start

```powershell
Import-Module ./OsintRag/OsintRag.psd1

# Point at your embedding endpoint (defaults to local Ollama).
$env:EMBEDDING_API_URL = 'http://localhost:11434/api/embeddings'
$env:EMBEDDING_MODEL   = 'nomic-embed-text'

# Ingest OSINT output -> chunk -> embed -> store.
$nmapJson | Split-OsintData -SourceAgent 'nmap' -DiscoveryTime (Get-Date) | Add-OsintMemory

# Hybrid retrieval.
Search-OsintIndex -Query '192.168.1.100' -TopK 5      # exact indicator -> BM25 leads
Search-OsintIndex -Query 'exposed remote access' -TopK 5  # concept -> dense leads

# Relationship graph.
Export-OsintGraph -Format Dot -Path ./graph.dot
```

## Retrieval model

* **Dense** — `Get-DenseVector` embeds text; `Measure-CosineSimilarity` scores the
  query against every stored vector. The fast path uses
  `System.Numerics.Tensors.TensorPrimitives::CosineSimilarity` (SIMD). A `[float[]]`
  is implicitly widened to `ReadOnlySpan<float>` at the call site (PowerShell cannot
  construct a `ReadOnlySpan` itself). If the Tensors assembly is unavailable, a
  strongly typed managed loop produces an identical result.
* **Sparse** — `Invoke-BM25Scoring` implements Okapi BM25 locally. Tokenisation keeps
  IPv4 addresses, domains, and hex hashes intact so exact indicators score strongly.
* **Fusion** — `RRF = 1/(k + DenseRank) + 1/(k + SparseRank)`, `k = 60`. A retriever
  that did not surface a chunk (score ≤ 0) contributes 0, so a chunk matched by both
  modalities outranks one matched by only one.

### The `System.Numerics.Tensors.dll` dependency

`TensorPrimitives` is **not** part of the pwsh shared framework; it ships in the
`System.Numerics.Tensors` NuGet package. The net8.0 assembly is vendored under
`lib/` so the accelerated path works out of the box. To use a different copy set
`OSINTRAG_TENSORS_DLL` to its path. If nothing resolves, the module logs a verbose
message and uses the managed fallback — it never fails to load.

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser   # once
Invoke-Pester ./OsintRag/Tests/OsintRag.Tests.ps1
```

The suite mocks the embedding API, so it runs offline and deterministically. It
verifies (among others) that an exact IP query is decided by BM25 — the IP chunk is
*not* the top dense hit yet wins overall — and that a conceptual query with zero
lexical overlap is decided by dense search.

## Integration with the KKI orchestrator

`OsintRag` is deliberately a **standalone importable module**, usable two ways:

1. **Python orchestrator calls it as a subprocess (recommended for this repo).**
   `orchestrator.py` already owns the governed execution pipeline (policy,
   attestation, consent, audit). Keep that in Python and treat `OsintRag` as the
   persistent-memory service it shells out to, e.g.:

   ```python
   subprocess.run(
       ["pwsh", "-NoProfile", "-Command",
        "Import-Module ./OsintRag/OsintRag.psd1;"
        "($input | Out-String) | Split-OsintData -SourceAgent 'nmap' -DiscoveryTime (Get-Date) | Add-OsintMemory;"
        "Search-OsintIndex -Query $env:QUERY -TopK 5 | ConvertTo-Json"],
       input=tool_output, capture_output=True, text=True)
   ```

   Every public function is JSON-friendly (`ConvertTo-Json` in / `ConvertFrom-Json`
   out), so the process boundary stays clean and the Python governance layer remains
   the single point of control.

2. **A native pwsh driver.** If you want an all-PowerShell swarm, wrap these
   functions in a loop that calls your reasoning CLI and pipes tool output straight
   into `Add-OsintMemory` / `Search-OsintIndex` — no serialization boundary.

Given the mature Python orchestrator and governance stack already in this repo,
option 1 keeps responsibilities where they are and avoids duplicating the
consent/audit controls in a second language.
