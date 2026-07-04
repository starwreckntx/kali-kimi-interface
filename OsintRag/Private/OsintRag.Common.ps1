#Requires -Version 7.4
<#
.SYNOPSIS
    Shared private helpers for the OsintRag module (JSON flattening, entity-type
    inference, indicator extraction, chunk construction).

.DESCRIPTION
    These functions are not exported. They back Split-OsintData and
    Export-OsintGraph so the flattening/typing logic lives in exactly one place.
#>

# Indicator patterns reused by chunking, typing, and graph extraction.
$script:OsintIndicatorPatterns = @{
    IPv4   = '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    Domain = '\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    Hash   = '\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b'
    Url    = '\bhttps?://[^\s|]+'
    Email  = '\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b'
}

function ConvertTo-OsintFlatText {
    # Recursively flattens a value decoded from JSON into "key: value" leaf pairs.
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Node,

        [string]$Prefix = ''
    )

    $pairs = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Node) {
        if ($Prefix) { $pairs.Add("${Prefix}: null") }
    }
    elseif ($Node -is [string] -or $Node -is [valuetype]) {
        $label = if ($Prefix) { $Prefix } else { 'value' }
        $pairs.Add("${label}: $Node")
    }
    elseif ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $child = if ($Prefix) { "$Prefix.$key" } else { [string]$key }
            $pairs.AddRange([string[]]@(ConvertTo-OsintFlatText -Node $Node[$key] -Prefix $child))
        }
    }
    elseif ($Node -is [pscustomobject]) {
        foreach ($prop in $Node.PSObject.Properties) {
            $child = if ($Prefix) { "$Prefix.$($prop.Name)" } else { $prop.Name }
            $pairs.AddRange([string[]]@(ConvertTo-OsintFlatText -Node $prop.Value -Prefix $child))
        }
    }
    elseif ($Node -is [System.Collections.IEnumerable]) {
        $idx = 0
        foreach ($item in $Node) {
            $child = if ($Prefix) { "$Prefix[$idx]" } else { "[$idx]" }
            $pairs.AddRange([string[]]@(ConvertTo-OsintFlatText -Node $item -Prefix $child))
            $idx++
        }
    }
    else {
        $label = if ($Prefix) { $Prefix } else { 'value' }
        $pairs.Add("${label}: $Node")
    }

    return [string[]]@($pairs)
}

function Get-OsintEntityType {
    # Coarse entity classification from a chunk's text content.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [string]$Default = 'record'
    )

    $lower = $Text.ToLowerInvariant()
    if ($lower -match $script:OsintIndicatorPatterns.Hash)   { return 'hash' }
    if ($lower -match $script:OsintIndicatorPatterns.Url)    { return 'url' }
    if ($lower -match $script:OsintIndicatorPatterns.Email)  { return 'email' }
    if ($lower -match $script:OsintIndicatorPatterns.IPv4)   { return 'host' }
    if ($lower -match $script:OsintIndicatorPatterns.Domain) { return 'domain' }
    return $Default
}

function Get-OsintIndicator {
    # Extracts distinct indicators of compromise from a block of text.
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    $found = [System.Collections.Generic.List[pscustomobject]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $lower = $Text.ToLowerInvariant()

    # Order matters: match URLs/hashes/emails before the broader domain pattern.
    foreach ($kind in 'Url', 'Email', 'Hash', 'IPv4', 'Domain') {
        foreach ($m in [regex]::Matches($lower, $script:OsintIndicatorPatterns[$kind])) {
            $value = $m.Value
            if ($seen.Add($value)) {
                $found.Add([pscustomobject]@{ Type = $kind; Value = $value })
            }
        }
    }
    return [pscustomobject[]]@($found)
}

function New-OsintChunk {
    # Constructs a canonical chunk object with the mandated schema.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$TextContent,

        [Parameter(Mandatory)]
        [datetime]$DiscoveryTime,

        [string]$SourceAgent = 'unknown',

        [string]$EntityType
    )

    if (-not $EntityType) {
        $EntityType = Get-OsintEntityType -Text $TextContent
    }

    return [pscustomobject]@{
        Id            = [guid]::NewGuid().ToString('n').Substring(0, 12)
        TextContent   = $TextContent
        EntityType    = $EntityType
        DiscoveryTime = $DiscoveryTime
        SourceAgent   = $SourceAgent
    }
}
