<#
.SYNOPSIS  Resolve .lnk shortcut targets (Startup-folder items).
.PARAMETER InputFile   JSON array of .lnk paths.
.PARAMETER OutputFile  JSON array of { path, target, arguments }.
#>
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)
$ErrorActionPreference = 'SilentlyContinue'
$parsed = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$paths = @($parsed | ForEach-Object { $_ })
$shell = New-Object -ComObject WScript.Shell
$rows = foreach ($p in $paths) {
    $lnk = $shell.CreateShortcut($p)
    [pscustomobject]@{ path = $p; target = $lnk.TargetPath; arguments = $lnk.Arguments }
}
ConvertTo-Json -InputObject @($rows) -Compress | Out-File -LiteralPath $OutputFile -Encoding UTF8
