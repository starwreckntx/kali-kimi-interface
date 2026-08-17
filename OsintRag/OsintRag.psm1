#Requires -Version 7.4
<#
.SYNOPSIS
    OsintRag — an OSINT-optimized hybrid RAG memory module, native to PowerShell 7.4+.

.DESCRIPTION
    Provides the persistent-state / retrieval layer for an AI-driven OSINT swarm:
    structural chunking of tool output, dense embedding via a swappable REST
    endpoint, a local BM25 sparse index, SIMD cosine similarity, and Reciprocal
    Rank Fusion of the dense + sparse rankings. Standard library / .NET only — no
    Python dependencies.

.EXAMPLE
    Import-Module ./OsintRag/OsintRag.psd1
    '{"domain":"target.com","ip":"192.168.1.100"}' |
        Split-OsintData -SourceAgent 'amass' -DiscoveryTime (Get-Date) |
        Add-OsintMemory
    Search-OsintIndex -Query '192.168.1.100' -TopK 5
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# --- Module-scoped session state ---------------------------------------------
$script:OsintMemory = [System.Collections.Generic.List[pscustomobject]]::new()
$script:OsintTensorBackend = $false

function Test-OsintTensorType {
    # Non-throwing probe: returns $true if TensorPrimitives is resolvable in any
    # currently loaded assembly. A bare [type] literal *throws* when the type is
    # absent (even with '-as [type]'), so we scan the AppDomain instead.
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $asm = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq 'System.Numerics.Tensors' } |
        Select-Object -First 1
    if ($null -eq $asm) { return $false }
    return ($null -ne $asm.GetType('System.Numerics.Tensors.TensorPrimitives'))
}

function Initialize-OsintTensorBackend {
    <#
    .SYNOPSIS
        Attempts to make System.Numerics.Tensors.TensorPrimitives available.

    .DESCRIPTION
        TensorPrimitives lives in the System.Numerics.Tensors assembly, which is
        NOT part of the pwsh shared framework. We probe, in order: an already
        loaded copy, $env:OSINTRAG_TENSORS_DLL, the vendored lib/ copy, then the
        assembly name (GAC/framework). Sets $script:OsintTensorBackend to $true on
        success so Measure-CosineSimilarity uses the SIMD fast path; otherwise the
        managed fallback is used. Returns the resolved state.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (Test-OsintTensorType) {
        $script:OsintTensorBackend = $true
        return $true
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($env:OSINTRAG_TENSORS_DLL) { $candidates.Add($env:OSINTRAG_TENSORS_DLL) }
    $candidates.Add((Join-Path $PSScriptRoot 'lib/System.Numerics.Tensors.dll'))

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            try {
                [void][System.Reflection.Assembly]::LoadFrom($candidate)
            }
            catch {
                Write-Verbose "OsintRag: failed to load '$candidate': $($_.Exception.Message)"
            }
            if (Test-OsintTensorType) {
                $script:OsintTensorBackend = $true
                return $true
            }
        }
    }

    try {
        Add-Type -AssemblyName System.Numerics.Tensors -ErrorAction Stop
    }
    catch {
        Write-Verbose "OsintRag: System.Numerics.Tensors not resolvable by name; using managed cosine fallback."
    }
    $script:OsintTensorBackend = [bool](Test-OsintTensorType)
    return $script:OsintTensorBackend
}

[void](Initialize-OsintTensorBackend)

# --- Dot-source private helpers, then public functions -----------------------
$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$publicFiles  = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in ($privateFiles + $publicFiles)) {
    . $file.FullName
}

# Export every public function plus the two store accessors that live alongside
# Add-OsintMemory.
$exported = @($publicFiles.BaseName) + @('Get-OsintMemory', 'Clear-OsintMemory')
Export-ModuleMember -Function ($exported | Select-Object -Unique)
