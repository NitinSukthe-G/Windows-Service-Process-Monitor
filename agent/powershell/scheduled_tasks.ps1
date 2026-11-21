<#
.SYNOPSIS  Enumerate scheduled-task actions as JSON on stdout.
#>
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$rows = foreach ($t in Get-ScheduledTask) {
    foreach ($a in $t.Actions) {
        [pscustomobject]@{
            name      = $t.TaskName
            path      = $t.TaskPath
            state     = [string]$t.State
            execute   = $a.Execute
            arguments = $a.Arguments
            user      = $t.Principal.UserId
        }
    }
}
ConvertTo-Json -InputObject @($rows) -Compress
