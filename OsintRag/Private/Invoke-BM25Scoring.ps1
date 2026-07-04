#Requires -Version 7.4
<#
.SYNOPSIS
    Lightweight local BM25 lexical scoring, implemented natively in PowerShell.

.DESCRIPTION
    Scores each document in -Documents against -Query using the Okapi BM25
    ranking function with the standard defaults (k1 = 1.5, b = 0.75) and the
    log((N - n + 0.5) / (n + 0.5) + 1) IDF variant (non-negative IDF).

    Tokenisation is deliberately indicator-aware: it lower-cases and splits on
    runs of characters that are not [a-z0-9._-], which keeps IPv4 addresses,
    domains, and hex hashes intact as single terms so exact-indicator matches
    score strongly.

.OUTPUTS
    [double[]] — one score per input document, index-aligned with -Documents.

.EXAMPLE
    Invoke-BM25Scoring -Documents @('host 192.168.1.100 open', 'web server 443') -Query '192.168.1.100'
#>
function Invoke-BM25Scoring {
    [CmdletBinding()]
    [OutputType([double[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Documents,

        [Parameter(Mandatory)]
        [string]$Query,

        [double]$K1 = 1.5,

        [double]$B = 0.75
    )

    $tokenize = {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return [string[]]@() }
        $raw = $Text.ToLowerInvariant() -split '[^a-z0-9._-]+'
        $out = foreach ($t in $raw) {
            $trimmed = $t.Trim('.', '_', '-')
            if ($trimmed.Length -gt 0) { $trimmed }
        }
        return [string[]]@($out)
    }

    [int]$n = $Documents.Count
    if ($n -eq 0) { return [double[]]@() }

    # Tokenise every document once.
    $docTokens = [System.Collections.Generic.List[string[]]]::new()
    foreach ($d in $Documents) { $docTokens.Add((& $tokenize $d)) }

    $docLengths = foreach ($tok in $docTokens) { [int]$tok.Count }
    $docLengths = [int[]]@($docLengths)
    $avgdl = ($docLengths | Measure-Object -Average).Average
    if (-not $avgdl -or $avgdl -le 0) { $avgdl = 1.0 }

    # Document frequency: number of documents containing each term.
    $df = @{}
    foreach ($tok in $docTokens) {
        foreach ($term in ($tok | Select-Object -Unique)) {
            $df[$term] = [int]$df[$term] + 1
        }
    }

    $queryTerms = @((& $tokenize $Query) | Select-Object -Unique)

    $scores = [double[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) {
        $tokens = $docTokens[$i]
        [double]$dl = $docLengths[$i]

        # Term frequencies for this document.
        $tf = @{}
        foreach ($term in $tokens) { $tf[$term] = [int]$tf[$term] + 1 }

        [double]$score = 0.0
        foreach ($qt in $queryTerms) {
            [int]$f = [int]$tf[$qt]
            if ($f -le 0) { continue }
            [int]$nq = [int]$df[$qt]
            [double]$idf = [math]::Log((($n - $nq + 0.5) / ($nq + 0.5)) + 1.0)
            [double]$denom = $f + ($K1 * (1.0 - $B + ($B * ($dl / $avgdl))))
            $score += $idf * (($f * ($K1 + 1.0)) / $denom)
        }
        $scores[$i] = $score
    }

    return $scores
}
