<#
.SYNOPSIS
    Real-time top CPU consumers (process + owning service, if any).
.DESCRIPTION
    Read-only diagnostic. Locale-independent: does NOT use Get-Counter (whose
    counter set names are localized, e.g. Spanish Windows lacks the English
    '% Processor Time' path, which caused this script to silently hang).
    Instead samples Process.TotalProcessorTime twice and computes the delta.
.PARAMETER IntervalSeconds
    Sampling window in seconds. Default 2.
.PARAMETER Top
    Number of processes to show. Default 15.
#>

param(
    [int]$IntervalSeconds = 2,
    [int]$Top = 15
)

$logicalCores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

function Get-ServiceMap {
    # Map ProcessId -> Service display name (svchost hosts multiple services; this only
    # resolves the first match per PID, which is enough to spot the offender).
    $map = @{}
    Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ($_.ProcessId -and -not $map.ContainsKey($_.ProcessId)) {
                $map[$_.ProcessId] = $_.DisplayName
            }
        }
    return $map
}

Write-Host "Monitor de CPU en vivo. Ctrl+C para salir. Ventana: ${IntervalSeconds}s | Nucleos logicos: $logicalCores`n"

while ($true) {
    $before = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, Name, TotalProcessorTime
    Start-Sleep -Seconds $IntervalSeconds
    $after  = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, Name, TotalProcessorTime

    $beforeLookup = @{}
    foreach ($p in $before) { $beforeLookup[$p.Id] = $p.TotalProcessorTime }

    $serviceMap = Get-ServiceMap

    $rows = foreach ($p in $after) {
        $prev = $beforeLookup[$p.Id]
        if (-not $prev) { continue }

        $deltaSeconds = ($p.TotalProcessorTime - $prev).TotalSeconds
        if ($deltaSeconds -le 0) { continue }

        $cpuPct = [math]::Round(($deltaSeconds / $IntervalSeconds / $logicalCores) * 100, 1)
        $svcName = $serviceMap[$p.Id]

        [PSCustomObject]@{
            Proceso  = $p.Name
            PID      = $p.Id
            'CPU %'  = $cpuPct
            Servicio = if ($svcName) { $svcName } else { '-' }
        }
    }

    Clear-Host
    Write-Host "=== Top $Top procesos por CPU (norm. $logicalCores nucleos) - $(Get-Date -Format 'HH:mm:ss') ===`n"
    $rows | Sort-Object 'CPU %' -Descending | Select-Object -First $Top | Format-Table -AutoSize
}