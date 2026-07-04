#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Pester 5 tests for the OsintRag module.

    The embedding API is mocked (Get-DenseVector / Invoke-RestMethod) so the
    suite runs offline and deterministically. The mock implements a tiny
    concept-space embedding (threat / network / web / credential / bias) so the
    hybrid-search assertions are reproducible:

      * an exact IP query is decided by BM25 (the IP chunk is NOT the top dense
        hit yet wins overall),
      * a conceptual query with zero lexical overlap is decided by dense search.
#>

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:ModuleRoot 'OsintRag.psd1') -Force

    # Deterministic concept-space embedding used by every mock in this suite.
    $script:MockEmbedding = {
        param([string]$Text)
        $t = $Text.ToLowerInvariant()
        $threat  = @('trojan', 'ransomware', 'payload', 'compromised', 'malware', 'malicious', 'infection')
        $network = @('host', 'port', 'ssh', 'subnet', 'sweep', 'open', 'scan')
        $web     = @('web', 'application', 'https', 'http', 'frontend', 'portal')
        $cred    = @('credential', 'password', 'hash', 'leaked', 'database', 'dump', 'login')
        [float]$d0 = 0; [float]$d1 = 0; [float]$d2 = 0; [float]$d3 = 0
        foreach ($tok in ($t -split '[^a-z0-9._-]+' | Where-Object { $_ })) {
            if ($threat  -contains $tok) { $d0 += 1 }
            if ($network -contains $tok) { $d1 += 1 }
            if ($web     -contains $tok) { $d2 += 1 }
            if ($cred    -contains $tok) { $d3 += 1 }
            if ($tok -match '^(?:\d{1,3}\.){3}\d{1,3}$') { $d1 += 1 }
        }
        return [float[]]@($d0, $d1, $d2, $d3, 0.1)
    }

    # Corpus. D0 holds the target IP but is web-heavy (low dense rank for the IP
    # query); D1 is the purest network doc (top dense) but lacks the IP.
    $script:Corpus = @(
        'Endpoint 192.168.1.100 web application login portal https frontend',
        'Host scan found open port ssh subnet sweep across the perimeter',
        'Gateway 10.0.0.5 answered on port 80 http during the sweep',
        'Trojan ransomware payload identified on a compromised endpoint workstation',
        'Leaked credential password hash recovered from an exposed database dump'
    )
}

Describe 'Measure-CosineSimilarity (private math)' {
    It 'returns ~1 for parallel vectors' {
        InModuleScope OsintRag {
            $r = Measure-CosineSimilarity -Vector1 ([float[]]@(1, 2, 3)) -Vector2 ([float[]]@(2, 4, 6))
            [math]::Abs($r - 1.0) | Should -BeLessThan 1e-4
        }
    }

    It 'returns 0 for orthogonal vectors' {
        InModuleScope OsintRag {
            Measure-CosineSimilarity -Vector1 ([float[]]@(1, 0)) -Vector2 ([float[]]@(0, 1)) | Should -Be 0
        }
    }

    It 'throws on length mismatch' {
        InModuleScope OsintRag {
            { Measure-CosineSimilarity -Vector1 ([float[]]@(1, 2)) -Vector2 ([float[]]@(1)) } | Should -Throw
        }
    }

    It 'fast path and managed fallback agree' {
        InModuleScope OsintRag {
            $a = [float[]]@(0.2, 0.5, 0.9, 0.1)
            $b = [float[]]@(0.3, 0.4, 0.8, 0.6)
            $orig = $script:OsintTensorBackend
            try {
                $script:OsintTensorBackend = $true
                $fast = Measure-CosineSimilarity -Vector1 $a -Vector2 $b
                $script:OsintTensorBackend = $false
                $slow = Measure-CosineSimilarity -Vector1 $a -Vector2 $b
                [math]::Abs($fast - $slow) | Should -BeLessThan 1e-5
            }
            finally {
                $script:OsintTensorBackend = $orig
            }
        }
    }
}

Describe 'Invoke-BM25Scoring (private sparse)' {
    It 'scores the document with the exact IP highest' {
        InModuleScope OsintRag {
            $docs = @(
                'host 192.168.1.100 open port ssh',
                'web server on port 443 https',
                'trojan ransomware payload endpoint'
            )
            $scores = Invoke-BM25Scoring -Documents $docs -Query '192.168.1.100'
            $scores[0] | Should -BeGreaterThan 0
            $scores[1] | Should -Be 0
            $scores[2] | Should -Be 0
        }
    }

    It 'returns an empty array for empty document sets' {
        InModuleScope OsintRag {
            @(Invoke-BM25Scoring -Documents @() -Query 'anything').Count | Should -Be 0
        }
    }
}

Describe 'Split-OsintData (chunking)' {
    It 'requires a DiscoveryTime parameter' {
        (Get-Command Split-OsintData).Parameters['DiscoveryTime'].Attributes.Mandatory |
            Should -Contain $true
    }

    It 'flattens a JSON object into one chunk with the mandated schema' {
        $chunks = Split-OsintData -InputData '{"domain":"target.com","ip":"192.168.1.100"}' -DiscoveryTime ([datetime]'2026-01-01') -SourceAgent 'amass'
        $chunks.Count | Should -Be 1
        $chunks[0].PSObject.Properties.Name | Should -Be @('Id', 'TextContent', 'EntityType', 'DiscoveryTime', 'SourceAgent')
        $chunks[0].TextContent | Should -Match 'target\.com'
        $chunks[0].TextContent | Should -Match '192\.168\.1\.100'
        $chunks[0].SourceAgent | Should -Be 'amass'
        $chunks[0].DiscoveryTime | Should -BeOfType [datetime]
    }

    It 'produces one chunk per element of a JSON array' {
        $chunks = Split-OsintData -InputData '[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}]' -DiscoveryTime (Get-Date)
        $chunks.Count | Should -Be 2
    }

    It 'produces one chunk per non-empty line of plain text' {
        $chunks = Split-OsintData -InputData "line one`n`nline two" -DiscoveryTime (Get-Date)
        $chunks.Count | Should -Be 2
        $chunks[0].EntityType | Should -Be 'text'
    }

    It 'tags an IP-bearing record as a host entity' {
        $chunks = Split-OsintData -InputData '{"asset":"192.168.5.5"}' -DiscoveryTime (Get-Date)
        $chunks[0].EntityType | Should -Be 'host'
    }

    It 'parses an Nmap XML host into a host chunk' {
        $xml = '<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/><hostnames><hostname name="db.local"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>'
        $chunks = Split-OsintData -InputData $xml -DiscoveryTime (Get-Date) -SourceAgent 'nmap'
        $chunks[0].EntityType | Should -Be 'host'
        $chunks[0].TextContent | Should -Match '10\.0\.0\.9'
        $chunks[0].TextContent | Should -Match '22/tcp open ssh'
    }

    It 'parses an Nmap port that is missing the optional <service> element' {
        # Regression: a service-less port must not throw and fall through to text.
        $xml = '<nmaprun><host><address addr="10.0.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>'
        $chunks = Split-OsintData -InputData $xml -DiscoveryTime (Get-Date) -SourceAgent 'nmap'
        $chunks[0].EntityType | Should -Be 'host'
        $chunks[0].TextContent | Should -Match '22/tcp open'
    }
}

Describe 'Get-DenseVector (embedding client)' {
    It 'parses an Ollama-style response into a float[]' {
        Mock -ModuleName OsintRag Invoke-RestMethod { [pscustomobject]@{ embedding = @(0.1, 0.2, 0.3) } }
        $v = Get-DenseVector -Text 'sample'
        $v | Should -BeOfType [float]
        $v.Count | Should -Be 3
        Should -Invoke -ModuleName OsintRag Invoke-RestMethod -Times 1
    }

    It 'parses an OpenAI-style response into a float[]' {
        Mock -ModuleName OsintRag Invoke-RestMethod { [pscustomobject]@{ data = @([pscustomobject]@{ embedding = @(1.0, 2.0) }) } }
        (Get-DenseVector -Text 'sample').Count | Should -Be 2
    }

    It 'throws a clear error (not a null reference) when the response is null' {
        Mock -ModuleName OsintRag Invoke-RestMethod { $null }
        { Get-DenseVector -Text 'sample' } | Should -Throw -ExpectedMessage '*did not contain a recognizable vector*'
    }
}

Describe 'Add-OsintMemory / store accessors' {
    BeforeEach {
        Clear-OsintMemory -Confirm:$false | Out-Null
        Mock -ModuleName OsintRag Get-DenseVector { [float[]]@(0.5, 0.5) }
    }

    It 'embeds and stores a chunk' {
        Split-OsintData -InputData '{"ip":"1.2.3.4"}' -DiscoveryTime (Get-Date) | Add-OsintMemory
        $mem = Get-OsintMemory
        $mem.Count | Should -Be 1
        $mem[0].Vector.Count | Should -Be 2
        Should -Invoke -ModuleName OsintRag Get-DenseVector -Times 1
    }

    It 'Clear-OsintMemory empties the store' {
        Split-OsintData -InputData 'a line' -DiscoveryTime (Get-Date) | Add-OsintMemory
        (Clear-OsintMemory -Confirm:$false) | Should -Be 1
        (Get-OsintMemory).Count | Should -Be 0
    }

    It 'does not throw on a custom chunk missing DiscoveryTime' {
        # Regression: casting a null/absent DiscoveryTime to [datetime] must not crash.
        $custom = [pscustomobject]@{ Id = 'x1'; TextContent = 'note'; EntityType = 'text'; SourceAgent = 'manual' }
        { $custom | Add-OsintMemory } | Should -Not -Throw
        (Get-OsintMemory)[0].DiscoveryTime | Should -Be ([datetime]::MinValue)
    }
}

Describe 'Search-OsintIndex (hybrid RRF engine)' {
    BeforeEach {
        Clear-OsintMemory -Confirm:$false | Out-Null
        $emb = $script:MockEmbedding
        Mock -ModuleName OsintRag Get-DenseVector {
            param([string]$Text, $Model, $ApiUrl, $TimeoutSec)
            & $emb $Text
        }.GetNewClosure()

        $i = 0
        foreach ($doc in $script:Corpus) {
            Split-OsintData -InputData $doc -DiscoveryTime ([datetime]'2026-01-01').AddMinutes($i) -SourceAgent 'test' | Add-OsintMemory
            $i++
        }
    }

    It 'returns the exact-IP chunk first, and BM25 (not dense) is decisive' {
        $results = Search-OsintIndex -Query '192.168.1.100' -TopK 5
        $results[0].TextContent | Should -Match '192\.168\.1\.100'
        $results[0].SparseRank  | Should -Be 1          # exact lexical hit
        $results[0].SparseScore | Should -BeGreaterThan 0
        $results[0].DenseRank   | Should -BeGreaterThan 1  # dense alone would NOT pick it
    }

    It 'returns the conceptual chunk first via dense search with zero lexical overlap' {
        $results = Search-OsintIndex -Query 'malware infection outbreak breach' -TopK 5
        $results[0].TextContent | Should -Match 'ransomware'
        $results[0].DenseRank   | Should -Be 1
        $results[0].SparseScore | Should -Be 0            # no lexical overlap -> dense drove it
    }

    It 'honours -TopK' {
        (Search-OsintIndex -Query 'port' -TopK 2).Count | Should -Be 2
    }

    It 'returns nothing when the store is empty' {
        Clear-OsintMemory -Confirm:$false | Out-Null
        (Search-OsintIndex -Query 'anything').Count | Should -Be 0
    }
}

Describe 'Export-OsintGraph' {
    BeforeEach {
        Clear-OsintMemory -Confirm:$false | Out-Null
        Mock -ModuleName OsintRag Get-DenseVector { [float[]]@(0.1, 0.2) }
        Split-OsintData -InputData '{"domain":"target.com","ip":"192.168.1.100"}' -DiscoveryTime (Get-Date) | Add-OsintMemory
    }

    It 'emits JSON nodes and edges including the extracted indicators' {
        $graph = Export-OsintGraph -Format Json | ConvertFrom-Json
        ($graph.nodes | Where-Object { $_.kind -eq 'chunk' }).Count | Should -Be 1
        ($graph.nodes | Where-Object { $_.kind -eq 'indicator' }).Count | Should -BeGreaterThan 0
        ($graph.edges | Where-Object { $_.relation -eq 'mentions' }).Count | Should -BeGreaterThan 0
    }

    It 'emits GraphViz DOT' {
        Export-OsintGraph -Format Dot | Should -Match 'digraph OsintGraph'
    }

    It 'produces deterministic indicator node ids across calls' {
        $ids1 = (Export-OsintGraph -Format Json | ConvertFrom-Json).nodes |
            Where-Object { $_.kind -eq 'indicator' } | ForEach-Object { $_.id } | Sort-Object
        $ids2 = (Export-OsintGraph -Format Json | ConvertFrom-Json).nodes |
            Where-Object { $_.kind -eq 'indicator' } | ForEach-Object { $_.id } | Sort-Object
        ($ids1 -join ',') | Should -Be ($ids2 -join ',')
        $ids1[0] | Should -Match '^ind_[0-9a-f]{12}$'
    }
}
