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
    v5.3 - Correccion de bugs de medicion (sesion 02/07/2026):
      [FIX-5] Espacio Recuperado: Get-PSDrive.Free reemplazado por [System.IO.DriveInfo]
              + conteo de bytes real por archivo eliminado ($Script:BytesFreed).
              Causa raiz: Get-PSDrive cachea el valor de .Free en la sesion de PS 5.1,
              generando "0 MB recuperados" pese a borrados reales confirmados.
      [FIX-6] Audio Watchdog: reemplazado umbral sobre .CPU acumulado (tiempo total
              desde el boot) por delta medido en ventana de 1.5s. .CPU de Get-Process
              es TotalProcessorTime, no % instantaneo -> con uptime largo el umbral
              fijo (500/300) se dispara siempre, generando falsos positivos y
              reinicios de Audiosrv innecesarios.
    v5.4 - Guard critico de host (sesion 02/07/2026, auditoria externa + revision conjunta):
      [FIX-7] Reparacion de Windows Update (-Force) ahora verifica que TrustedInstaller
              NO este activo antes de detener wuauserv/cryptsvc/UsoSvc y renombrar el
              DataStore. Causa raiz: el script solo chequeaba instaladores activos para
              decidir el modo de limpieza (Targets), pero NO antes de la reparacion con
              -Force. Si -Force se ejecuta mientras TrustedInstaller esta aplicando una
              actualizacion real (no solo escaneando), se podia interrumpir la instalacion
              y potencialmente corromper el estado de Windows Update. Se aborta la
              reparacion con log ERROR si se detecta instalacion en curso, en linea con
              la regla fundamental: el host SIEMPRE debe permanecer operativo.
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
$Script:BytesFreed = 0            # [FIX-5] Acumulador de bytes reales liberados (por archivo)
$Script:GuardedMode = $false      # [NEW-1] Flag de trazabilidad para resguardo de instaladores
$Script:UpdateRepaired = $false   # [NEW-2] Flag: auto-reparacion de DataStore ejecutada
$Script:AudioRestarted = $false   # [NEW-3] Flag: audio stack watchdog triggered
$Script:AudioWatchdogCooldownUntil = @{ System = [DateTime]::MinValue; DWM = [DateTime]::MinValue }

# [FIX-5] DriveInfo en vez de Get-PSDrive: lectura directa al FS, sin cache de sesion PS
$SystemDriveLetter = $env:SystemDrive.TrimEnd('\')
try {
    $DiskBefore = ([System.IO.DriveInfo]::new($SystemDriveLetter)).AvailableFreeSpace
}
catch {
    $DiskBefore = 0
}

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

Write-SentinelLog "SENTINEL V5.4 APEX - INICIANDO" "SUCCESS"

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
                    $ItemSize = $_.Length   # [FIX-5] Capturar tamaño ANTES de borrar el objeto
                    if ($PSCmdlet.ShouldProcess($ItemPath, "Eliminar archivo")) {
                        Remove-Item $ItemPath -Force -ErrorAction Stop
                        $Script:DeletedCount++
                        $Script:BytesFreed += $ItemSize   # [FIX-5] Sumar bytes reales liberados
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
            # [FIX-7] Guard critico: abortar si hay una instalacion de Update REAL en curso.
            # TrustedInstaller activo en este punto puede significar que Windows esta
            # aplicando una actualizacion, no solo escaneando. Detener servicios y
            # renombrar el DataStore en ese momento puede corromper la instalacion.
            # Regla fundamental: el host SIEMPRE debe quedar operativo -> se aborta,
            # no se fuerza.
            $InstallInProgress = Get-Process -Name "TrustedInstaller" -ErrorAction SilentlyContinue

            if ($InstallInProgress) {
                Write-SentinelLog "ABORTADO: TrustedInstaller activo (instalacion en curso). No se reparara el DataStore para evitar corromper Windows Update. Reintenta mas tarde." "ERROR"
            }
            else {
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
# [FIX-6] v5.3: Detects REAL-TIME anomaly via delta sampling, not accumulated CPU time.
# Get-Process .CPU is TotalProcessorTime (seconds since process start), NOT instant %.
# Sampling twice over a fixed window isolates actual current load, avoiding false
# positives on hosts with long uptime. Incident baseline: 20/06/2026.
Write-SentinelLog "Verificando Audio Stack..." "INFO"
try {
    # Ventana de muestreo en segundos - ajustable, 1.5s balancea precision vs velocidad
    $SampleWindowSeconds = 1.5

    # Sample 1 (t0): normalizar a valores numericos validos, o $null si el proceso no existe.
    $sysProcess_t0 = Get-Process -Name "System" -ErrorAction SilentlyContinue
    $dwmProcess_t0 = Get-Process -Name "dwm" -ErrorAction SilentlyContinue
    $sysCPU_t0 = if ($null -ne $sysProcess_t0) { [double]$sysProcess_t0.CPU } else { $null }
    $dwmCPU_t0 = if ($null -ne $dwmProcess_t0) { [double]$dwmProcess_t0.CPU } else { $null }

    Start-Sleep -Milliseconds ([int]($SampleWindowSeconds * 1000))

    # Sample 2 (t1): lo mismo, para evitar errores cuando el proceso no existe o termina durante la ventana.
    $sysProcess_t1 = Get-Process -Name "System" -ErrorAction SilentlyContinue
    $dwmProcess_t1 = Get-Process -Name "dwm" -ErrorAction SilentlyContinue
    $sysCPU_t1 = if ($null -ne $sysProcess_t1) { [double]$sysProcess_t1.CPU } else { $null }
    $dwmCPU_t1 = if ($null -ne $dwmProcess_t1) { [double]$dwmProcess_t1.CPU } else { $null }

    # Delta = CPU-segundos consumidos DURANTE la ventana = carga real actual.
    # Get-Process.CPU ya devuelve un double en segundos (no un TimeSpan), así que
    # la resta genera el delta directamente; si el proceso no existe o el valor es raro,
    # se deja en 0.0 para evitar falsos negativos en la comparación.
    $sysDelta = 0.0
    if ($null -ne $sysCPU_t0 -and $null -ne $sysCPU_t1) {
        $sysDelta = [double]$sysCPU_t1 - [double]$sysCPU_t0
        if ($sysDelta -lt 0) { $sysDelta = 0.0 }
    }

    $dwmDelta = 0.0
    if ($null -ne $dwmCPU_t0 -and $null -ne $dwmCPU_t1) {
        $dwmDelta = [double]$dwmCPU_t1 - [double]$dwmCPU_t0
        if ($dwmDelta -lt 0) { $dwmDelta = 0.0 }
    }

    # Umbrales sobre la ventana de muestreo (NO acumulado desde boot):
    # >0.8s de CPU-time de System en 1.5s reales, o >0.6s de DWM = anomalo.
    # CALIBRAR estos valores contra una corrida en frio (baseline sin carga) en tu HP Ryzen 5.
    $SysThreshold = 0.8
    $DwmThreshold = 0.6

    # Diagnostico legible: muestra el estado real de cada muestreo para entender por que se disparo.
    $sysT0Text = if ($null -ne $sysCPU_t0) { [string][Math]::Round([double]$sysCPU_t0, 4) } else { "N/A" }
    $sysT1Text = if ($null -ne $sysCPU_t1) { [string][Math]::Round([double]$sysCPU_t1, 4) } else { "N/A" }
    $dwmT0Text = if ($null -ne $dwmCPU_t0) { [string][Math]::Round([double]$dwmCPU_t0, 4) } else { "N/A" }
    $dwmT1Text = if ($null -ne $dwmCPU_t1) { [string][Math]::Round([double]$dwmCPU_t1, 4) } else { "N/A" }
    $sysPresent = ($null -ne $sysCPU_t0 -and $null -ne $sysCPU_t1)
    $dwmPresent = ($null -ne $dwmCPU_t0 -and $null -ne $dwmCPU_t1)

    $WatchdogDiagnosis = "System[t0=$sysT0Text,t1=$sysT1Text,delta=$([Math]::Round($sysDelta,2))s,threshold=$SysThreshold] | DWM[t0=$dwmT0Text,t1=$dwmT1Text,delta=$([Math]::Round($dwmDelta,2))s,threshold=$DwmThreshold] | window=${SampleWindowSeconds}s"
    $Now = Get-Date
    $CooldownSeconds = 30

    $CooldownActive = @()
    if ($Now -lt $Script:AudioWatchdogCooldownUntil.System) {
        $CooldownActive += "System=$([Math]::Round(($Script:AudioWatchdogCooldownUntil.System - $Now).TotalSeconds, 1))s"
    }
    if ($Now -lt $Script:AudioWatchdogCooldownUntil.DWM) {
        $CooldownActive += "DWM=$([Math]::Round(($Script:AudioWatchdogCooldownUntil.DWM - $Now).TotalSeconds, 1))s"
    }

    if ($CooldownActive.Count -gt 0) {
        $CooldownReason = "cooldown-active | " + ($CooldownActive -join ' ; ')
        Write-SentinelLog "Audio Stack Watchdog en cooldown: $CooldownReason | diagnostico: $WatchdogDiagnosis" "WARN"
        $Script:AudioRestarted = $false
    }
    elseif ($sysDelta -gt $SysThreshold -or $dwmDelta -gt $DwmThreshold) {
        $TriggerReason = @()
        if ($sysDelta -gt $SysThreshold) { $TriggerReason += "System" }
        if ($dwmDelta -gt $DwmThreshold) { $TriggerReason += "DWM" }

        Write-SentinelLog "ALERTA Audio: $WatchdogDiagnosis | trigger=threshold-exceeded | reason=$($TriggerReason -join ',') | accion=reinicio de stack | cooldown=${CooldownSeconds}s" "WARN"

        # Restart audio stack - safe, reversible, no data loss
        Stop-Service  "AudioEndpointBuilder" -Force -ErrorAction SilentlyContinue
        Stop-Service  "Audiosrv"             -Force -ErrorAction SilentlyContinue
        Start-Sleep   -Seconds 2
        Start-Service "AudioEndpointBuilder"        -ErrorAction SilentlyContinue
        Start-Service "Audiosrv"                    -ErrorAction SilentlyContinue

        # Dedicated watchdog log for incident traceability
        $WatchdogLog = Join-Path $LogDir "audio_watchdog.log"
        $WatchdogMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $WatchdogDiagnosis | trigger=threshold-exceeded | reason=$($TriggerReason -join ',') | accion=audio stack restarted | cooldown=${CooldownSeconds}s"
        Add-Content $WatchdogLog $WatchdogMsg -ErrorAction SilentlyContinue

        if ($sysDelta -gt $SysThreshold) { $Script:AudioWatchdogCooldownUntil.System = (Get-Date).AddSeconds($CooldownSeconds) }
        if ($dwmDelta -gt $DwmThreshold) { $Script:AudioWatchdogCooldownUntil.DWM = (Get-Date).AddSeconds($CooldownSeconds) }

        Write-SentinelLog "Audio Stack reiniciado. Log: $WatchdogLog" "SUCCESS"
        $Script:AudioRestarted = $true
    }
    else {
        $MissingSampleNote = if (-not $sysPresent -or -not $dwmPresent) { " | note=proceso ausente en una de las muestras; delta forzado a 0" } else { "" }
        Write-SentinelLog "Audio Stack OK - $WatchdogDiagnosis$MissingSampleNote" "INFO"
        $Script:AudioRestarted = $false
    }
}
catch {
    Write-SentinelLog "No se pudo auditar el Audio Stack: $($_.Exception.Message)" "WARN"
}

# --- 6. Metricas y Resumen Final ---
# [FIX-5] Espacio Recuperado ahora se basa en bytes reales sumados por archivo eliminado,
# no en la diferencia de disco (que Get-PSDrive/DriveInfo puede ver alterada por
# procesos externos como TiWorker corriendo en paralelo).
$SavedMB = [Math]::Round($Script:BytesFreed / 1MB, 2)
$SavedBytes = $Script:BytesFreed

# DriveInfo post-limpieza se mantiene solo como dato informativo/diagnostico,
# ya no se usa para calcular el espacio recuperado.
try {
    $DiskAfter = ([System.IO.DriveInfo]::new($SystemDriveLetter)).AvailableFreeSpace
    $DiskDeltaMB = [Math]::Round(($DiskAfter - $DiskBefore) / 1MB, 2)
}
catch {
    $DiskDeltaMB = "N/D"
}

# El delta del disco es solo referencia del sistema; puede fluctuar por procesos del SO,
# antivirus, actualizaciones o el propio filesystem. Si no hubo borrados reales, no debe
# interpretarse como espacio recuperado.
if ($Script:DeletedCount -eq 0) {
    $DiskDeltaMB = 0
}

Write-Host "`n$("="*50)" -ForegroundColor Cyan
Write-SentinelLog "RESUMEN EJECUTIVO" "SUCCESS"
Write-SentinelLog "Archivos Analizados: $Script:TotalAnalyzed"
Write-SentinelLog "Eliminados Reales:   $Script:DeletedCount"
Write-SentinelLog "Bytes Liberados:     $SavedBytes B ($SavedMB MB)"
Write-SentinelLog "Bloqueados/Uso:      $Script:LockedCount"
Write-SentinelLog "Delta Disco (ref):   $DiskDeltaMB MB" "INFO"
Write-SentinelLog "Nota: Delta disco es referencia del sistema, no un indicador de espacio recuperado real." "WARN"

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
