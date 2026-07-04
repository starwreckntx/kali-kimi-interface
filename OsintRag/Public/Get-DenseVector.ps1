#Requires -Version 7.4
<#
.SYNOPSIS
    Retrieves a dense embedding vector for a string from an embedding endpoint.

.DESCRIPTION
    A thin REST client over Invoke-RestMethod. Defaults target a local Ollama
    server (http://localhost:11434/api/embeddings) but the endpoint is fully
    swappable via -ApiUrl or $env:EMBEDDING_API_URL, and works against any
    OpenAI-compatible /v1/embeddings service. The request body carries both the
    Ollama ('prompt') and OpenAI ('input') field names, and the response parser
    accepts .embedding, .data[0].embedding, or .embeddings[0].

.OUTPUTS
    [float[]] — the embedding vector.

.EXAMPLE
    Get-DenseVector -Text 'exposed RDP service on the perimeter'
#>
function Get-DenseVector {
    [CmdletBinding()]
    [OutputType([float[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [string]$Text,

        [string]$Model = $(if ($env:EMBEDDING_MODEL) { $env:EMBEDDING_MODEL } else { 'nomic-embed-text' }),

        [string]$ApiUrl = $(if ($env:EMBEDDING_API_URL) { $env:EMBEDDING_API_URL } else { 'http://localhost:11434/api/embeddings' }),

        [int]$TimeoutSec = 60
    )

    process {
        $body = @{
            model  = $Model
            prompt = $Text   # Ollama field
            input  = $Text   # OpenAI field
        } | ConvertTo-Json -Compress

        $headers = @{ 'Content-Type' = 'application/json' }
        if ($env:EMBEDDING_API_KEY) {
            $headers['Authorization'] = "Bearer $($env:EMBEDDING_API_KEY)"
        }

        $response = Invoke-RestMethod -Method Post -Uri $ApiUrl -Headers $headers -Body $body -TimeoutSec $TimeoutSec

        $vector = $null
        $names = @($response.PSObject.Properties.Name)
        if ($names -contains 'embedding') {
            $vector = $response.embedding
        }
        elseif ($names -contains 'data' -and $response.data) {
            $vector = $response.data[0].embedding
        }
        elseif ($names -contains 'embeddings' -and $response.embeddings) {
            $vector = $response.embeddings[0]
        }

        if ($null -eq $vector) {
            throw "Embedding response from '$ApiUrl' did not contain a recognizable vector (expected .embedding, .data[0].embedding, or .embeddings[0])."
        }

        return [float[]]$vector
    }
}
