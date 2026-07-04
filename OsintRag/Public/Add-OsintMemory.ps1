#Requires -Version 7.4
<#
.SYNOPSIS
    Adds structural chunks (and their dense vectors) to the in-memory store.

.DESCRIPTION
    Maintains the module-scoped session state
    [System.Collections.Generic.List[pscustomobject]] that holds each chunk plus
    its [float[]] embedding. If no -Vector is supplied and -SkipEmbedding is not
    set, the vector is fetched via Get-DenseVector.

    Chunks are normally produced by Split-OsintData and piped straight in.

.EXAMPLE
    Split-OsintData -InputData $json -DiscoveryTime (Get-Date) -SourceAgent 'nmap' |
        Add-OsintMemory
#>
function Add-OsintMemory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject]$Chunk,

        [float[]]$Vector,

        [switch]$SkipEmbedding,

        [switch]$PassThru
    )

    process {
        [float[]]$vector = @()
        if ($Vector) {
            $vector = [float[]]@($Vector)
        }
        if ($vector.Length -eq 0 -and -not $SkipEmbedding) {
            $vector = [float[]]@(Get-DenseVector -Text $Chunk.TextContent)
        }

        # DiscoveryTime is mandatory on chunks from Split-OsintData, but guard the
        # custom/malformed case: casting $null (or a missing property) to the
        # [datetime] value type is a terminating error.
        $discoveryTime = [datetime]::MinValue
        if ($Chunk.PSObject.Properties['DiscoveryTime'] -and $null -ne $Chunk.DiscoveryTime) {
            $discoveryTime = [datetime]$Chunk.DiscoveryTime
        }

        $record = [pscustomobject]@{
            Id            = $Chunk.Id
            TextContent   = $Chunk.TextContent
            EntityType    = $Chunk.EntityType
            DiscoveryTime = $discoveryTime
            SourceAgent   = $Chunk.SourceAgent
            Vector        = if ($vector) { [float[]]$vector } else { [float[]]@() }
        }

        $script:OsintMemory.Add($record)

        if ($PassThru) { $record }
    }
}

function Get-OsintMemory {
    <#
    .SYNOPSIS
        Returns the current in-memory chunk/vector store (session state).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param()
    return [pscustomobject[]]@($script:OsintMemory)
}

function Clear-OsintMemory {
    <#
    .SYNOPSIS
        Empties the in-memory store. Returns the number of records removed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param()
    $count = $script:OsintMemory.Count
    if ($PSCmdlet.ShouldProcess('OsintRag session memory', "Clear $count record(s)")) {
        $script:OsintMemory.Clear()
    }
    return $count
}
