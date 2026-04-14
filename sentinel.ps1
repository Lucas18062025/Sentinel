<#
.SYNOPSIS
    Sentinel V5 "Apex" - Motor de Mantenimiento Unificado.
.DESCRIPTION
    Combinación de streaming de bajo consumo, progreso optimizado por bloques,
    manejo de concurrencia de logs y auditoría de seguridad real.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [int]$MinFileAgeMinutes = 15,
    [switch]$DetailedLog,
    [switch]$Force
)

# --- 1. Configuración de Entorno (Optimización Inicial) ---
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir     = Join-Path $env:SystemDrive "Logs\Sentinel"
$LogFile    = Join-Path $LogDir "Sentinel_$Timestamp.log"
$Targets    = @($env:TEMP, "C:\Windows\Temp")

# Exclusiones Optimizadas (Regex Unificado)
$ExclusionRegex = '(\.log$|\.etl$|\.evtx$|\.dat$|\.tmp$|\.cache$|\.bak$|-lock-)'

# Inicialización de Contadores
$Script:DeletedCount = 0
$Script:LockedCount  = 0
$Script:TotalAnalyzed = 0
$DiskBefore = (Get-PSDrive C).Free

# Pre-validación del Directorio de Logs (Fuera de la función para ganar velocidad)
if (-not (Test-Path $LogDir)) {
    try { New-Item $LogDir -ItemType Directory -Force | Out-Null } catch {}
}

# Configuración de Confirmación (Tu mejora de automatización)
if ($Force) { $ConfirmPreference = 'None' }

# --- 2. Logger de Alto Rendimiento ---
function Write-SentinelLog {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "HH:mm:ss"
    $Entry = "[$Time] [$Level] $Message"
    
    $Color = switch($Level){ "ERROR"{"Red"}; "WARN"{"Yellow"}; "SUCCESS"{"Green"}; Default{"Gray"} }
    Write-Host $Entry -ForegroundColor $Color

    # Escritura directa sin validaciones redundantes de carpeta
    try { $Entry | Add-Content $LogFile -ErrorAction SilentlyContinue } catch {}
}

# --- 3. Validación de Privilegios ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "CRÍTICO: Debes ejecutar como Administrador."
    return
}

Write-SentinelLog "SENTINEL V5 APEX - INICIANDO" "SUCCESS"

# --- 4. Motor de Limpieza (Streaming de 2 Etapas) ---
foreach ($Path in $Targets) {
    if (Test-Path $Path) {
        Write-SentinelLog "Analizando: $Path" "WARN"
        $PathCounter = 0

        # Pipeline Optimizado: Get -> ForEach (Evitamos el pipe extra de Where-Object)
        Get-ChildItem -Path $Path -Recurse -Force -Attributes !ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object {
            $PathCounter++
            $Script:TotalAnalyzed++

            # Progreso optimizado: Actualiza la UI cada 100 archivos para ahorrar CPU
            if ($PathCounter % 100 -eq 0) {
                Write-Progress -Activity "Limpiando $Path" -Status "Procesados: $PathCounter archivos"
            }

            # Lógica de Filtrado Interna (Más rápida que un pipe extra)
            $IsOld = $_.LastWriteTime -lt (Get-Date).AddMinutes(-$MinFileAgeMinutes)
            $IsExcluded = $_.Name -match $ExclusionRegex

            if (-not $_.PSIsContainer -and $IsOld -and -not $IsExcluded) {
                try {
                    $ItemPath = $_.FullName
                    if ($PSCmdlet.ShouldProcess($ItemPath, "Eliminar archivo")) {
                        Remove-Item $ItemPath -Force -ErrorAction Stop
                        $Script:DeletedCount++
                        if ($DetailedLog) { Write-SentinelLog "OK: $($_.Name)" "INFO" }
                    }
                } catch {
                    $Script:LockedCount++
                }
            }
        }
    }
}

# --- 5. Auditoría de Seguridad ---
Write-SentinelLog "Verificando Seguridad de Red..." "INFO"
try {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        $Status = if ($_.Enabled) { "ACTIVO" } else { "VULNERABLE (OFF)" }
        $Lvl = if ($_.Enabled) { "INFO" } else { "ERROR" }
        Write-SentinelLog "Firewall [$($_.Name)]: $Status" $Lvl
    }
} catch { Write-SentinelLog "Error en auditoría de red" "WARN" }

# --- 6. Métricas y Resumen Final ---
$DiskAfter = (Get-PSDrive C).Free
$SavedMB = [Math]::Round(($DiskAfter - $DiskBefore) / 1MB, 2)
if ($SavedMB -lt 0) { $SavedMB = 0 }

Write-Host "`n" + ("="*50) -ForegroundColor Cyan
Write-SentinelLog "RESUMEN EJECUTIVO" "SUCCESS"
Write-SentinelLog "Total Analizados:  $Script:TotalAnalyzed"
Write-SentinelLog "Total Eliminados:  $Script:DeletedCount"
Write-SentinelLog "Bloqueados/Uso:    $Script:LockedCount"
Write-SentinelLog "Espacio Recuperado: $SavedMB MB" "SUCCESS"
Write-SentinelLog "Evidencia: $LogFile"
Write-Host ("="*50) -ForegroundColor Cyan