<#
.SYNOPSIS  Batch Authenticode verification.
.PARAMETER InputFile   JSON array of file paths.
.PARAMETER OutputFile  JSON array of { path, status, signer }.
#>
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
$parsed = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
# Windows PowerShell 5.1 does not unroll JSON arrays - piping the variable does.
$paths = @($parsed | ForEach-Object { $_ })
$results = foreach ($p in $paths) {
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $p
        $subject = $null
        if ($s.SignerCertificate) { $subject = $s.SignerCertificate.Subject }
        [pscustomobject]@{ path = $p; status = [string]$s.Status; signer = $subject }
    } catch {
        [pscustomobject]@{ path = $p; status = 'Error'; signer = $null }
    }
}
ConvertTo-Json -InputObject @($results) -Compress | Out-File -LiteralPath $OutputFile -Encoding UTF8
