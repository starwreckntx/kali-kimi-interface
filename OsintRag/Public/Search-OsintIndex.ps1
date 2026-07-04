#Requires -Version 7.4
<#
.SYNOPSIS
    Hybrid dense + sparse retrieval over the in-memory store, fused with RRF.

.DESCRIPTION
    Workflow:
      1. Vectorise the query with Get-DenseVector.
      2. Dense search: cosine similarity of the query vector against every stored
         vector, then rank.
      3. Sparse search: local BM25 lexical scoring against every stored
         TextContent, then rank.
      4. Reciprocal Rank Fusion: for each chunk,
             RRF = 1 / (k + DenseRank) + 1 / (k + SparseRank)   (k = 60)
         A chunk that a retriever did not surface (score <= 0) contributes 0 from
         that retriever, so a chunk matched by *both* modalities outranks one
         matched by only one.
      5. Return the re-ranked top -TopK chunks.

.OUTPUTS
    [pscustomobject[]] — chunks augmented with DenseScore, SparseScore,
    DenseRank, SparseRank, and RrfScore.

.EXAMPLE
    Search-OsintIndex -Query '192.168.1.100' -TopK 5
#>
function Search-OsintIndex {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Query,

        [int]$TopK = 5,

        [int]$RrfK = 60
    )

    $store = $script:OsintMemory
    [int]$n = $store.Count
    if ($n -eq 0) {
        return [pscustomobject[]]@()
    }

    # --- Dense retrieval -----------------------------------------------------
    $queryVector = [float[]]@(Get-DenseVector -Text $Query)
    $denseScores = [double[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $vec = $store[$i].Vector
        if ($vec -and $vec.Length -gt 0 -and $vec.Length -eq $queryVector.Length) {
            $denseScores[$i] = [double](Measure-CosineSimilarity -Vector1 $queryVector -Vector2 $vec)
        }
        else {
            $denseScores[$i] = 0.0
        }
    }

    # --- Sparse (BM25) retrieval --------------------------------------------
    $documents = [string[]]@(for ($i = 0; $i -lt $n; $i++) { [string]$store[$i].TextContent })
    $sparseScores = Invoke-BM25Scoring -Documents $documents -Query $Query

    # --- Rank maps (only positive scores are "retrieved") -------------------
    $denseRank = Get-OsintRankMap -Scores $denseScores
    $sparseRank = Get-OsintRankMap -Scores $sparseScores

    # --- Reciprocal Rank Fusion ---------------------------------------------
    $fused = for ($i = 0; $i -lt $n; $i++) {
        [double]$rrf = 0.0
        [int]$dr = 0
        [int]$sr = 0
        if ($denseRank.ContainsKey($i)) {
            $dr = [int]$denseRank[$i]
            $rrf += 1.0 / ($RrfK + $dr)
        }
        if ($sparseRank.ContainsKey($i)) {
            $sr = [int]$sparseRank[$i]
            $rrf += 1.0 / ($RrfK + $sr)
        }

        $rec = $store[$i]
        [pscustomobject]@{
            Id            = $rec.Id
            TextContent   = $rec.TextContent
            EntityType    = $rec.EntityType
            DiscoveryTime = $rec.DiscoveryTime
            SourceAgent   = $rec.SourceAgent
            DenseScore    = [double]$denseScores[$i]
            SparseScore   = [double]$sparseScores[$i]
            DenseRank     = $dr
            SparseRank    = $sr
            RrfScore      = $rrf
        }
    }

    return [pscustomobject[]]@(
        $fused |
            Sort-Object -Property @{Expression = 'RrfScore'; Descending = $true },
                                  @{Expression = 'DenseScore'; Descending = $true },
                                  @{Expression = 'Id'; Descending = $false } |
            Select-Object -First $TopK
    )
}

function Get-OsintRankMap {
    # Builds { documentIndex -> 1-based rank } for strictly positive scores,
    # highest score = rank 1. Ties break deterministically by document index.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [double[]]$Scores
    )

    $indexed = for ($i = 0; $i -lt $Scores.Length; $i++) {
        if ($Scores[$i] -gt 0) {
            [pscustomobject]@{ Index = $i; Score = $Scores[$i] }
        }
    }

    $ranked = @($indexed |
        Sort-Object -Property @{Expression = 'Score'; Descending = $true },
                              @{Expression = 'Index'; Descending = $false })

    $map = @{}
    for ($r = 0; $r -lt $ranked.Count; $r++) {
        $map[[int]$ranked[$r].Index] = $r + 1
    }
    return $map
}
