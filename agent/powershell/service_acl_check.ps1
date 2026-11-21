<#
.SYNOPSIS  Detect services whose binary, folder or registry key is writable by standard users.
.PARAMETER InputFile   JSON array of { name, exe }.
.PARAMETER OutputFile  JSON array of { name, exe, file_writable_by, dir_writable_by, key_writable_by }.
#>
param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'

# Low-privilege principals (SIDs, so this works on any Windows language)
$lowPriv = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-32-545' = 'Users'
}
# FileSystem: WriteData/CreateFiles(0x2) AppendData(0x4) Delete(0x10000) ChangePerms(0x40000) TakeOwner(0x80000)
$writeMask = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000

function Get-LowPrivWriters($acl) {
    $found = @()
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if (-not $lowPriv.ContainsKey($sid)) { continue }
        $rights = 0
        if ($rule.PSObject.Properties.Name -contains 'FileSystemRights') { $rights = [int]$rule.FileSystemRights }
        elseif ($rule.PSObject.Properties.Name -contains 'RegistryRights') { $rights = [int]$rule.RegistryRights }
        if (($rights -band $writeMask) -ne 0) { $found += $lowPriv[$sid] }
    }
    return @($found | Select-Object -Unique)
}

$parsed = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
# Windows PowerShell 5.1 does not unroll JSON arrays - piping the variable does.
$items = @($parsed | ForEach-Object { $_ })
$cache = @{}   # many services share one binary (svchost.exe) - audit each path once
function Get-CachedWriters([string]$target) {
    if (-not $cache.ContainsKey($target)) {
        try { $cache[$target] = Get-LowPrivWriters (Get-Acl -LiteralPath $target) } catch { $cache[$target] = @() }
    }
    return $cache[$target]
}
$results = foreach ($item in $items) {
    $file = @(); $dir = @(); $key = @()
    try {
        if ($item.exe -and (Test-Path -LiteralPath $item.exe)) {
            $file = Get-CachedWriters $item.exe
            $dir  = Get-CachedWriters (Split-Path -Parent $item.exe)
        }
    } catch { }
    try {
        $key = Get-LowPrivWriters (Get-Acl -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $item.name))
    } catch { }
    [pscustomobject]@{
        name = $item.name; exe = $item.exe
        file_writable_by = @($file); dir_writable_by = @($dir); key_writable_by = @($key)
    }
}
ConvertTo-Json -InputObject @($results) -Depth 4 -Compress | Out-File -LiteralPath $OutputFile -Encoding UTF8
