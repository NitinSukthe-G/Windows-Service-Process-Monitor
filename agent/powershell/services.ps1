<#
.SYNOPSIS  Enumerate Windows services (Win32_Service) as JSON on stdout.
#>
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rows = Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId, Description
ConvertTo-Json -InputObject @($rows) -Compress
