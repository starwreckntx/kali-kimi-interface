#Requires -Version 7.4
<#
.SYNOPSIS
    Cosine similarity between two dense vectors.

.DESCRIPTION
    Fast path: .NET 8 System.Numerics.Tensors.TensorPrimitives::CosineSimilarity,
    which operates over ReadOnlySpan<float> and is SIMD-accelerated. PowerShell
    cannot *construct* a ReadOnlySpan (it is a ByRef-like type), but a [float[]]
    argument is implicitly converted to the span at the call site, so we pass the
    typed arrays straight through.

    Fallback path: a strongly typed managed loop, used when the Tensors assembly
    is not available on the node (see Initialize-OsintTensorBackend in the .psm1).
    Both paths return an identical result so callers never branch.

.EXAMPLE
    Measure-CosineSimilarity -Vector1 ([float[]]@(1,2,3)) -Vector2 ([float[]]@(2,4,6))
    # 0.9999999  (parallel vectors)
#>
function Measure-CosineSimilarity {
    [CmdletBinding()]
    [OutputType([float])]
    param(
        [Parameter(Mandatory)]
        [float[]]$Vector1,

        [Parameter(Mandatory)]
        [float[]]$Vector2
    )

    if ($Vector1.Length -ne $Vector2.Length) {
        throw "Vector length mismatch: $($Vector1.Length) vs $($Vector2.Length)."
    }
    if ($Vector1.Length -eq 0) {
        return [float]0
    }

    if ($script:OsintTensorBackend) {
        # SIMD fast path — array is implicitly widened to ReadOnlySpan<float>.
        return [float][System.Numerics.Tensors.TensorPrimitives]::CosineSimilarity($Vector1, $Vector2)
    }

    # Managed fallback: accumulate in double for numerical stability, return float.
    [double]$dot = 0.0
    [double]$mag1 = 0.0
    [double]$mag2 = 0.0
    for ($i = 0; $i -lt $Vector1.Length; $i++) {
        [double]$a = $Vector1[$i]
        [double]$b = $Vector2[$i]
        $dot  += $a * $b
        $mag1 += $a * $a
        $mag2 += $b * $b
    }
    if ($mag1 -eq 0.0 -or $mag2 -eq 0.0) {
        return [float]0
    }
    return [float]($dot / ([math]::Sqrt($mag1) * [math]::Sqrt($mag2)))
}
