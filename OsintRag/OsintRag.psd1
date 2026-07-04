@{
    RootModule        = 'OsintRag.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b2f3c7a1-9d4e-4c8a-8e1b-3a6f5c2d7e90'
    Author            = 'Kali Kimi Interface'
    CompanyName       = 'Kali Kimi Interface'
    Copyright         = '(c) Kali Kimi Interface. All rights reserved.'
    Description       = 'OSINT-optimized hybrid RAG memory module: structural chunking, dense embeddings, local BM25, SIMD cosine similarity, and Reciprocal Rank Fusion. Native PowerShell 7.4+ / .NET 8, no Python dependencies.'
    PowerShellVersion = '7.4'

    FunctionsToExport = @(
        'Split-OsintData',
        'Get-DenseVector',
        'Add-OsintMemory',
        'Get-OsintMemory',
        'Clear-OsintMemory',
        'Search-OsintIndex',
        'Export-OsintGraph'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('OSINT', 'RAG', 'BM25', 'Embeddings', 'Security', 'RRF', 'HybridSearch')
            ProjectUri = 'https://github.com/starwreckntx/kali-kimi-interface'
        }
    }
}
