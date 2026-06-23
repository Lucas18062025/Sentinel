<#
.SYNOPSIS
    Sentinel V5 "Apex" - Motor de Mantenimiento Unificado.
.DESCRIPTION
    Combinacion de streaming de bajo consumo, progreso optimizado por bloques,
    manejo de concurrencia de logs, auditoria de seguridad real
    y resguardo de instaladores activos del sistema.
.NOTES
    v5.1 - Optimizaciones aplicadas:
      [FIX-1] Get-Date pre-computado fuera del pipeline (elimina N instancias de DateTime)
      [FIX-2] -File en Get-ChildItem (elimina chequeo PSIsContainer por archivo)
      [FIX-3] Write-Progress -Completed al cerrar cada path (barra fantasma eliminada)
      [FIX-4] InstallerActive.Name flatten correcto (array join para log coherente)
      [NEW-1] $Script:GuardedMode flag para trazabilidad en resumen ejecutivo
    v5.2 - Audio Stack Watchdog integrado:
      [NEW-3] $Script:AudioRestarted flag para trazabilidad del watchdog de audio
      [5c]    Seccion Audio Stack Watchdog - DPC storm prevention (incidente 20/06/2026)
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [int]$MinFileAgeMinutes = 15,
    [switch]$DetailedLog,
    [switch]$Force
)

# --- 1. Configuracion de Entorno (Optimizacion Inicial) ---
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $env:SystemDrive "Logs\Sentinel"
$LogFile = Join-Path $LogDir "Sentinel_$Timestamp.log"
$Targets = @($env:TEMP, "C:\Windows\Temp")

# Exclusiones Optimizadas (Regex Unificado)
$ExclusionRegex = '(\.log$|\.etl$|\.evtx$|\.dat$|\.tmp$|\.cache$|\.bak$|-lock-)'

# Inicializacion de Contadores
$Script:DeletedCount = 0
$Script:LockedCount = 0
$Script:TotalAnalyzed = 0
$Script:GuardedMode = $false     # [NEW-1] Flag de trazabilidad para resguardo de instaladores
$Script:UpdateRepaired = $false  # [NEW-2] Flag: auto-reparacion de DataStore ejecutada
$Script:AudioRestarted = $false  # [NEW-3] Flag: audio stack watchdog triggered
$DiskBefore = (Get-PSDrive C).Free

# Pre-validacion del Directorio de Logs (Fuera de la funcion para ganar velocidad)
if (-not (Test-Path $LogDir)) {
    try { New-Item $LogDir -ItemType Directory -Force | Out-Null } catch {}
}

# Configuracion de Confirmacion
if ($Force) { $ConfirmPreference = 'None' }

# --- 2. Logger de Alto Rendimiento ---
function Write-SentinelLog {
    param([string]$Message, [string]$Level = "INFO")
    $Time = Get-Date -Format "HH:mm:ss"
    $Entry = "[$Time] [$Level] $Message"

    $Color = switch ($Level) { "ERROR" { "Red" }; "WARN" { "Yellow" }; "SUCCESS" { "Green" }; Default { "Gray" } }
    Write-Host $Entry -ForegroundColor $Color

    # Escritura directa sin validaciones redundantes de carpeta
    try { $Entry | Add-Content $LogFile -ErrorAction SilentlyContinue } catch {}
}

# --- 3. Validacion de Privilegios ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "CRITICO: Debes ejecutar como Administrador."
    return
}

Write-SentinelLog "SENTINEL V5 APEX - INICIANDO" "SUCCESS"

# --- 4. Motor de Limpieza (Streaming de 2 Etapas con Resguardo de Instaladores) ---

# [NEW-1] Guard: detectar instaladores activos antes de iniciar el pipeline de limpieza
# TiWorker / TrustedInstaller = Windows Update/Installer workers
# SetupHost = Feature update / in-place upgrade process
$InstallerActive = Get-Process -Name "TiWorker", "TrustedInstaller", "SetupHost" -ErrorAction SilentlyContinue

if ($InstallerActive) {
    # [FIX-4] Flatten correcto: array de nombres -> string legible para el log
    $ActiveNames = ($InstallerActive | Select-Object -ExpandProperty Name -Unique) -join ", "
    Write-SentinelLog "Instalador activo detectado: [$ActiveNames]. Modo restringido: solo TEMP de usuario." "WARN"

    # Reducir targets: C:\Windows\Temp puede tener archivos en uso por el instalador
    $Targets = @($env:TEMP)
    $Script:GuardedMode = $true   # [NEW-1] Marcar para resumen ejecutivo
}

# [FIX-1] Pre-computar el umbral de antiguedad UNA sola vez fuera del pipeline
# Evita instanciar DateTime por cada archivo analizado (potencialmente miles)
$Cutoff = (Get-Date).AddMinutes(-$MinFileAgeMinutes)

foreach ($Path in $Targets) {
    if (Test-Path $Path) {
        Write-SentinelLog "Analizando: $Path" "WARN"
        $PathCounter = 0

        # [FIX-2] -File filtra solo archivos a nivel de API del FileSystem
        # Elimina el chequeo (-not $_.PSIsContainer) dentro del pipeline
        # Pipeline: Get-ChildItem -File -> ForEach (sin Where-Object extra)
        Get-ChildItem -Path $Path -Recurse -Force -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object {
            $PathCounter++
            $Script:TotalAnalyzed++

            # Progreso optimizado: actualiza UI cada 100 archivos para ahorrar CPU
            if ($PathCounter % 100 -eq 0) {
                Write-Progress -Activity "Limpiando $Path" -Status "Procesados: $PathCounter archivos"
            }

            # [FIX-1] Usar $Cutoff pre-computado (no mas Get-Date por iteracion)
            $IsOld = $_.LastWriteTime -lt $Cutoff
            $IsExcluded = $_.Name -match $ExclusionRegex

            # PSIsContainer ya no es necesario: -File garantiza que son archivos
            if ($IsOld -and -not $IsExcluded) {
                try {
                    $ItemPath = $_.FullName
                    if ($PSCmdlet.ShouldProcess($ItemPath, "Eliminar archivo")) {
                        Remove-Item $ItemPath -Force -ErrorAction Stop
                        $Script:DeletedCount++
                        if ($DetailedLog) { Write-SentinelLog "OK: $($_.Name)" "INFO" }
                    }
                }
                catch {
                    $Script:LockedCount++
                }
            }
        }

        # [FIX-3] Cerrar explicitamente la barra de progreso al terminar cada path
        # Sin esto queda una barra "fantasma" congelada en pantalla
        Write-Progress -Activity "Limpiando $Path" -Completed
    }
}

# --- 5. Auditoria de Seguridad ---
Write-SentinelLog "Verificando Seguridad de Red..." "INFO"
try {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object {
        $Status = if ($_.Enabled) { "ACTIVO" } else { "VULNERABLE (OFF)" }
        $Lvl = if ($_.Enabled) { "INFO" } else { "ERROR" }
        Write-SentinelLog "Firewall [$($_.Name)]: $Status" $Lvl
    }
}
catch { Write-SentinelLog "Error en auditoria de red" "WARN" }

# --- 5b. Auditoria de Salud de Windows Update (Prevencion de bucles DataStore) ---
# Detecta exactamente el problema del 22/05/2026 antes de que explote:
#   LastTaskResult != 0 en tareas criticas del orquestador = indice roto en DataStore.edb
Write-SentinelLog "Verificando salud de Windows Update Orchestrator..." "INFO"
try {
    # Las 3 tareas que fallaron el 22/05 - son las que hay que vigilar siempre
    $WatchedTasks = @("Schedule Scan", "Schedule Scan Static Task", "UIEOrchestrator")

    $TaskResults = Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" |
    Get-ScheduledTaskInfo |
    Where-Object { $_.TaskName -in $WatchedTasks }

    # Codigo de exito en Windows = 0
    # Cualquier otro numero = fallo que puede convertirse en bucle
    $FailedTasks = $TaskResults | Where-Object { $_.LastTaskResult -ne 0 }

    if ($FailedTasks) {
        foreach ($t in $FailedTasks) {
            # Convertir el codigo numerico a hex para que sea legible (ej: 0x80070002)
            $HexCode = "0x{0:X8}" -f $t.LastTaskResult
            Write-SentinelLog "ALERTA Update: [$($t.TaskName)] fallo con $HexCode el $($t.LastRunTime)" "WARN"
        }

        # Verificar si el DataStore existe - si no existe, Windows ya esta en bucle activo
        $DataStorePath = "C:\Windows\SoftwareDistribution\DataStore\DataStore.edb"
        if (-not (Test-Path $DataStorePath)) {
            Write-SentinelLog "CRITICO: DataStore.edb no encontrado - bucle activo detectado." "ERROR"
        }

        # Auto-reparacion: solo si se ejecuto con -Force, para no interrumpir el sistema solo
        if ($Force) {
            Write-SentinelLog "Modo -Force activo: iniciando reparacion automatica del orquestador..." "WARN"

            # Paso 1: Detener el ecosistema de actualizaciones
            Stop-Service -Name "UsoSvc", "wuauserv", "cryptsvc" -Force -ErrorAction SilentlyContinue

            # Paso 2: Aislar el DataStore corrupto (mismo procedimiento del 22/05)
            $OldStore = "C:\Windows\SoftwareDistribution\DataStore.old"
            if (Test-Path $OldStore) { Remove-Item $OldStore -Recurse -Force -ErrorAction SilentlyContinue }
            Rename-Item -Path "C:\Windows\SoftwareDistribution\DataStore" `
                -NewName "DataStore.old" -ErrorAction SilentlyContinue

            # Paso 3: Reiniciar servicios - Windows reconstruye DataStore.edb automaticamente
            Start-Service -Name "cryptsvc" -ErrorAction SilentlyContinue
            Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue
            Start-Service -Name "UsoSvc"   -ErrorAction SilentlyContinue

            # Paso 4: Forzar re-escaneo limpio del orquestador
            Start-Sleep -Seconds 3
            usoclient StartScan

            Write-SentinelLog "Reparacion completada. DataStore regenerado por Windows." "SUCCESS"
            $Script:UpdateRepaired = $true
        }
        else {
            # Sin -Force: solo avisar, no tocar nada
            Write-SentinelLog "Accion requerida: ejecuta Sentinel con -Force para auto-reparar, o corre manualmente:" "WARN"
            Write-SentinelLog "  Stop-Service UsoSvc,wuauserv,cryptsvc -Force" "WARN"
            Write-SentinelLog "  Rename-Item C:\Windows\SoftwareDistribution\DataStore DataStore.old" "WARN"
            Write-SentinelLog "  Start-Service cryptsvc,wuauserv,UsoSvc" "WARN"
        }
    }
    else {
        # Todas las tareas con codigo 0 = orquestador saludable
        Write-SentinelLog "Windows Update Orchestrator: OK (todas las tareas con codigo 0)" "INFO"
    }
}
catch {
    Write-SentinelLog "No se pudo auditar el Orquestador de actualizaciones" "WARN"
}

# --- 5c. Audio Stack Watchdog (KB5094126 DPC Storm Prevention) ---
# Detects System/DWM CPU anomaly caused by Windows Update kernel interactions.
# Auto-restarts audio stack if threshold exceeded. Incident: 20/06/2026.
Write-SentinelLog "Verificando Audio Stack..." "INFO"
try {
    $systemCPU = (Get-Process -Name "System" -ErrorAction SilentlyContinue).CPU
    $dwmCPU = (Get-Process -Name "dwm"    -ErrorAction SilentlyContinue).CPU

    if ($systemCPU -gt 500 -or $dwmCPU -gt 300) {
        Write-SentinelLog "ALERTA Audio: System=$([Math]::Round($systemCPU,1)) / DWM=$([Math]::Round($dwmCPU,1)) - reiniciando stack..." "WARN"

        # Restart audio stack - safe, reversible, no data loss
        Stop-Service  "AudioEndpointBuilder" -Force -ErrorAction SilentlyContinue
        Stop-Service  "Audiosrv"             -Force -ErrorAction SilentlyContinue
        Start-Sleep   -Seconds 2
        Start-Service "AudioEndpointBuilder"        -ErrorAction SilentlyContinue
        Start-Service "Audiosrv"                    -ErrorAction SilentlyContinue

        # Dedicated watchdog log for incident traceability
        $WatchdogLog = Join-Path $LogDir "audio_watchdog.log"
        $WatchdogMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | System=$systemCPU | DWM=$dwmCPU | Audio stack restarted"
        Add-Content $WatchdogLog $WatchdogMsg -ErrorAction SilentlyContinue

        Write-SentinelLog "Audio Stack reiniciado. Log: $WatchdogLog" "SUCCESS"
        $Script:AudioRestarted = $true
    }
    else {
        Write-SentinelLog "Audio Stack OK - System=$([Math]::Round($systemCPU,1)) / DWM=$([Math]::Round($dwmCPU,1))" "INFO"
        $Script:AudioRestarted = $false
    }
}
catch {
    Write-SentinelLog "No se pudo auditar el Audio Stack" "WARN"
}

# --- 6. Metricas y Resumen Final ---
$DiskAfter = (Get-PSDrive C).Free
$SavedMB = [Math]::Round(($DiskAfter - $DiskBefore) / 1MB, 2)
if ($SavedMB -lt 0) { $SavedMB = 0 }

Write-Host "`n$("="*50)" -ForegroundColor Cyan
Write-SentinelLog "RESUMEN EJECUTIVO" "SUCCESS"
Write-SentinelLog "Total Analizados:   $Script:TotalAnalyzed"
Write-SentinelLog "Total Eliminados:   $Script:DeletedCount"
Write-SentinelLog "Bloqueados/Uso:     $Script:LockedCount"
Write-SentinelLog "Espacio Recuperado: $SavedMB MB" "SUCCESS"

# [NEW-1] Reportar modo de ejecucion en el log de auditoria
if ($Script:GuardedMode) {
    Write-SentinelLog "Modo Ejecucion:     RESTRINGIDO (instalador activo detectado)" "WARN"
}
else {
    Write-SentinelLog "Modo Ejecucion:     COMPLETO" "INFO"
}

# [NEW-2] Reportar si se reparo el orquestador de actualizaciones
if ($Script:UpdateRepaired) {
    Write-SentinelLog "Windows Update:     REPARADO (DataStore regenerado)" "SUCCESS"
}

# [NEW-3] Reportar estado del Audio Stack Watchdog
if ($Script:AudioRestarted) {
    Write-SentinelLog "Audio Stack:        REINICIADO (DPC storm detectado)" "WARN"
}
else {
    Write-SentinelLog "Audio Stack:        OK" "INFO"
}

Write-SentinelLog "Evidencia: $LogFile"
Write-Host ("=" * 50) -ForegroundColor Cyan
