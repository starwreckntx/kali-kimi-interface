#Requires -Version 7.4
<#
.SYNOPSIS
    Structural chunking of raw OSINT tool output into canonical chunk objects.

.DESCRIPTION
    Detects the shape of -InputData and produces one or more [pscustomobject]
    chunks, each strictly carrying: Id, TextContent, EntityType, DiscoveryTime,
    SourceAgent.

      * JSON  — parsed and recursively flattened into "key: value | key: value"
                text. A top-level JSON array yields one chunk per element; a
                single object yields one chunk.
      * Nmap XML — each <host> becomes a chunk (address, hostname, open ports).
      * Text  — each non-empty line becomes a chunk.

    A mandatory [datetime] -DiscoveryTime tags every chunk with temporal
    provenance for downstream time-aware ranking.

.EXAMPLE
    '{"domain":"target.com","ip":"192.168.1.100"}' |
        Split-OsintData -SourceAgent 'amass' -DiscoveryTime (Get-Date)
#>
function Split-OsintData {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [AllowEmptyString()]
        [string]$InputData,

        [Parameter(Mandatory)]
        [datetime]$DiscoveryTime,

        [string]$SourceAgent = 'unknown'
    )

    process {
        $chunks = [System.Collections.Generic.List[pscustomobject]]::new()

        if ([string]::IsNullOrWhiteSpace($InputData)) {
            return
        }

        # 1) Try JSON.
        $json = $null
        try {
            $json = $InputData | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $json = $null
        }

        if ($null -ne $json) {
            $records = if ($json -is [System.Collections.IEnumerable] -and $json -isnot [string]) {
                @($json)
            }
            else {
                @(, $json)
            }

            foreach ($record in $records) {
                $pairs = @(ConvertTo-OsintFlatText -Node $record)
                if ($pairs.Count -eq 0) { continue }
                $text = ($pairs -join ' | ')
                $chunks.Add((New-OsintChunk -TextContent $text -DiscoveryTime $DiscoveryTime -SourceAgent $SourceAgent))
            }
            return [pscustomobject[]]@($chunks)
        }

        # 2) Try Nmap XML.
        $trimmed = $InputData.TrimStart()
        if ($trimmed.StartsWith('<') -and $InputData -match '<nmaprun|<host\b') {
            try {
                [xml]$xml = $InputData
                foreach ($hostNode in $xml.SelectNodes('//host')) {
                    $addr = $hostNode.SelectNodes('address') |
                        Where-Object { $_.addrtype -in 'ipv4', 'ipv6' } |
                        ForEach-Object { $_.addr } |
                        Select-Object -First 1
                    $hostname = $hostNode.SelectNodes('hostnames/hostname') |
                        ForEach-Object { $_.name } |
                        Select-Object -First 1
                    $ports = foreach ($p in $hostNode.SelectNodes('ports/port')) {
                        # <state>/<service> are optional on a port; guard the null case
                        # so a service-less port does not throw under Set-StrictMode.
                        $stateNode = $p.SelectSingleNode('state')
                        $svcNode = $p.SelectSingleNode('service')
                        $state = if ($stateNode) { $stateNode.state } else { '' }
                        $svc = if ($svcNode) { $svcNode.name } else { '' }
                        "$($p.portid)/$($p.protocol) $state $svc".Trim()
                    }
                    $parts = [System.Collections.Generic.List[string]]::new()
                    if ($addr)     { $parts.Add("IP: $addr") }
                    if ($hostname) { $parts.Add("Hostname: $hostname") }
                    if ($ports)    { $parts.Add("Ports: $($ports -join ', ')") }
                    if ($parts.Count -eq 0) { continue }
                    $text = ($parts -join ' | ')
                    $chunks.Add((New-OsintChunk -TextContent $text -DiscoveryTime $DiscoveryTime -SourceAgent $SourceAgent -EntityType 'host'))
                }
                if ($chunks.Count -gt 0) {
                    return [pscustomobject[]]@($chunks)
                }
            }
            catch {
                # Fall through to plain-text handling on malformed XML.
            }
        }

        # 3) Plain text — one chunk per non-empty line.
        foreach ($line in ($InputData -split '\r?\n')) {
            $ln = $line.Trim()
            if ($ln.Length -eq 0) { continue }
            $chunks.Add((New-OsintChunk -TextContent $ln -DiscoveryTime $DiscoveryTime -SourceAgent $SourceAgent -EntityType 'text'))
        }

        return [pscustomobject[]]@($chunks)
    }
}
