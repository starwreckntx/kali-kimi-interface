#Requires -Version 7.4
<#
.SYNOPSIS
    Exports the in-memory store as an entity/indicator relationship graph.

.DESCRIPTION
    Builds a graph where every stored chunk is a node and every distinct
    indicator (IPv4, domain, URL, hash, email) extracted from chunk text is an
    indicator node. A "mentions" edge links a chunk to each indicator it
    references, so shared indicators connect otherwise separate chunks.

    Output is JSON ({ nodes, edges }) by default, or GraphViz DOT with
    -Format Dot. If -Path is given the content is written there and the file is
    returned; otherwise the serialized string is returned.

.EXAMPLE
    Export-OsintGraph -Format Dot -Path ./graph.dot
#>
function Export-OsintGraph {
    [CmdletBinding()]
    [OutputType([string], [System.IO.FileInfo])]
    param(
        [string]$Path,

        [ValidateSet('Json', 'Dot')]
        [string]$Format = 'Json'
    )

    $store = $script:OsintMemory

    $nodes = [System.Collections.Generic.List[pscustomobject]]::new()
    $edges = [System.Collections.Generic.List[pscustomobject]]::new()
    $indicatorIds = @{}

    foreach ($rec in $store) {
        $nodes.Add([pscustomobject]@{
            id            = $rec.Id
            kind          = 'chunk'
            entityType    = $rec.EntityType
            label         = if ($rec.TextContent.Length -gt 60) { $rec.TextContent.Substring(0, 60) + '...' } else { $rec.TextContent }
            sourceAgent   = $rec.SourceAgent
            discoveryTime = ([datetime]$rec.DiscoveryTime).ToString('o')
        })

        foreach ($indicator in (Get-OsintIndicator -Text $rec.TextContent)) {
            $key = "$($indicator.Type):$($indicator.Value)"
            if (-not $indicatorIds.ContainsKey($key)) {
                $nid = 'ind_' + [Math]::Abs($key.GetHashCode()).ToString('x')
                $indicatorIds[$key] = $nid
                $nodes.Add([pscustomobject]@{
                    id         = $nid
                    kind       = 'indicator'
                    entityType = $indicator.Type
                    label      = $indicator.Value
                })
            }
            $edges.Add([pscustomobject]@{
                source   = $rec.Id
                target   = $indicatorIds[$key]
                relation = 'mentions'
            })
        }
    }

    if ($Format -eq 'Dot') {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('digraph OsintGraph {')
        [void]$sb.AppendLine('  rankdir=LR;')
        [void]$sb.AppendLine('  node [style=filled, fontname="Helvetica"];')
        foreach ($node in $nodes) {
            $shape = if ($node.kind -eq 'indicator') { 'box' } else { 'ellipse' }
            $color = if ($node.kind -eq 'indicator') { '"#ffe0b2"' } else { '"#bbdefb"' }
            $label = ($node.label -replace '"', '\"')
            [void]$sb.AppendLine("  `"$($node.id)`" [label=`"$label`", shape=$shape, fillcolor=$color];")
        }
        foreach ($edge in $edges) {
            [void]$sb.AppendLine("  `"$($edge.source)`" -> `"$($edge.target)`" [label=`"$($edge.relation)`"];")
        }
        [void]$sb.AppendLine('}')
        $output = $sb.ToString()
    }
    else {
        $output = [pscustomobject]@{
            nodes = [pscustomobject[]]@($nodes)
            edges = [pscustomobject[]]@($edges)
        } | ConvertTo-Json -Depth 6
    }

    if ($Path) {
        $output | Set-Content -Path $Path -Encoding utf8
        return (Get-Item -Path $Path)
    }
    return $output
}
