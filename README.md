# 🛡️ Sentinel V5 "Apex" ⚡

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=for-the-badge&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-5.0%20Apex-red?style=for-the-badge)](CHANGELOG.md)
[![Security](https://img.shields.io/badge/Security-Audit%20Ready-orange?style=for-the-badge&logo=shield)](README.md)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge)](https://github.com/Lucas18062025)

> **Motor de Mantenimiento y Auditoría de Seguridad para Windows 11**  
> Desarrollado con enfoque en rendimiento, seguridad y trazabilidad forense.

---

## 📋 Tabla de Contenidos

- [¿Qué hace Sentinel?](#-qué-hace-sentinel)
- [Características Técnicas](#-características-técnicas)
- [Requisitos](#-requisitos)
- [Instalación y Uso](#-instalación-y-uso)
- [Parámetros](#-parámetros)
- [Salida y Evidencia](#-salida-y-evidencia)
- [Arquitectura del Script](#-arquitectura-del-script)
- [Roadmap](#-roadmap)
- [Autor](#-autor)

---

## 🔍 ¿Qué hace Sentinel?

Sentinel es un script PowerShell de producción que combina **limpieza inteligente de archivos temporales** con **auditoría de seguridad activa** en un solo motor unificado. Diseñado para entornos Windows 11 donde la estabilidad y la trazabilidad son prioridad absoluta.

**Problema que resuelve:**  
Los sistemas Windows acumulan archivos temporales y logs redundantes que degradan el rendimiento. Al mismo tiempo, el estado del firewall puede cambiar sin alertas visibles. Sentinel ataca ambos vectores en una sola ejecución con evidencia forense de cada acción.

---

## ⚙️ Características Técnicas

| Característica | Detalle |
|---|---|
| **Motor de streaming** | Pipeline de 2 etapas sin carga en RAM |
| **Progreso optimizado** | Actualización de UI cada 100 archivos (ahorro de CPU) |
| **Exclusión inteligente** | Regex unificado protege `.log`, `.etl`, `.evtx`, `.dat`, `.tmp`, `.cache`, `.bak` y archivos en uso (`-lock-`) |
| **Filtro de edad** | Solo elimina archivos con más de N minutos de antigüedad (configurable) |
| **Auditoría de firewall** | Verifica estado de los 3 perfiles (Domain, Private, Public) en tiempo real |
| **Log forense** | Cada ejecución genera un archivo `Sentinel_YYYYMMDD_HHmmss.log` en `C:\Logs\Sentinel\` |
| **Métricas de disco** | Calcula MB recuperados comparando estado antes/después |
| **Soporte -WhatIf** | Modo simulación nativo via `SupportsShouldProcess` |
| **Validación de privilegios** | El script se detiene si no tiene permisos de Administrador |

---

## 📦 Requisitos

- Windows 10 / Windows 11
- PowerShell 5.1 o superior
- Permisos de **Administrador** (obligatorio)
- Módulo `NetSecurity` disponible (incluido por defecto en Windows 10/11)

---

## 🚀 Instalación y Uso

### 1. Clonar el repositorio

```powershell
git clone https://github.com/Lucas18062025/Sentinel.git
cd Sentinel
```

### 2. Habilitar ejecución de scripts (si es necesario)

```powershell
# Solo para esta sesión, sin modificar la política global
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### 3. Ejecutar Sentinel

```powershell
# Ejecución estándar (requiere PowerShell como Administrador)
.\sentinel.ps1

# Modo simulación — NO elimina nada, solo muestra qué haría
.\sentinel.ps1 -WhatIf

# Modo silencioso, sin confirmaciones
.\sentinel.ps1 -Force

# Con log detallado de cada archivo procesado
.\sentinel.ps1 -DetailedLog

# Cambiar antigüedad mínima de archivos (por defecto: 15 minutos)
.\sentinel.ps1 -MinFileAgeMinutes 60
```

---

## 🎛️ Parámetros

| Parámetro | Tipo | Default | Descripción |
|---|---|---|---|
| `-MinFileAgeMinutes` | `int` | `15` | Antigüedad mínima en minutos para considerar un archivo eliminable |
| `-DetailedLog` | `switch` | `false` | Activa el registro individual de cada archivo eliminado |
| `-Force` | `switch` | `false` | Suprime confirmaciones interactivas (modo automático / CI) |
| `-WhatIf` | `switch` | `false` | Modo simulación: muestra acciones sin ejecutarlas |

---

## 📁 Salida y Evidencia

Cada ejecución genera automáticamente:

```
C:\Logs\Sentinel\
└── Sentinel_20260327_150929.log
```

**Contenido del log:**
```
[15:09:29] [SUCCESS] SENTINEL V5 APEX - INICIANDO
[15:09:30] [WARN]    Analizando: C:\Users\...\AppData\Local\Temp
[15:09:31] [INFO]    Firewall [Domain]: ACTIVO
[15:09:31] [INFO]    Firewall [Private]: ACTIVO
[15:09:31] [ERROR]   Firewall [Public]: VULNERABLE (OFF)
[15:09:31] [SUCCESS] RESUMEN EJECUTIVO
[15:09:31] [INFO]    Total Analizados:  1247
[15:09:31] [INFO]    Total Eliminados:  389
[15:09:31] [INFO]    Bloqueados/Uso:    12
[15:09:31] [SUCCESS] Espacio Recuperado: 142.5 MB
```

---

## 🏗️ Arquitectura del Script

```
sentinel.ps1
│
├── [1] Configuración de Entorno
│       Timestamps, rutas de log, targets, regex de exclusión
│
├── [2] Logger de Alto Rendimiento (Write-SentinelLog)
│       Escritura directa sin validaciones redundantes
│       Output coloreado por nivel (ERROR/WARN/SUCCESS/INFO)
│
├── [3] Validación de Privilegios
│       Detiene ejecución si no hay permisos de Administrador
│
├── [4] Motor de Limpieza — Streaming de 2 Etapas
│       Stage 1: Get-ChildItem con atributos filtrados
│       Stage 2: ForEach con lógica interna (sin pipe extra)
│       Progreso visual cada 100 archivos
│
├── [5] Auditoría de Seguridad
│       Get-NetFirewallProfile → estado de los 3 perfiles
│       Log diferenciado: INFO (activo) vs ERROR (vulnerable)
│
└── [6] Métricas y Resumen Final
        Comparación de disco Before/After
        Resumen ejecutivo en consola + log
```

---

## 🗺️ Roadmap

- [ ] **V6** — Auditoría de servicios con estado anómalo
- [ ] **V6** — Integración con Event Viewer (errores críticos últimas 24hs)
- [ ] **V7** — Módulo de detección de conexiones de red sospechosas (`Get-NetTCPConnection`)
- [ ] **V7** — Export de resumen en formato HTML para reportes
- [ ] **V8** — Integración con Telegram Bot para alertas remotas

---

## 👤 Autor

**Lucas Villagra**  
Cybersecurity Analyst | Ethical Hacker | SOC Analyst (en formación)  
📍 San Miguel de Tucumán, Argentina

[![LinkedIn](https://img.shields.io/badge/LinkedIn-lucas--villagra--cybersecurity-0A66C2?style=flat&logo=linkedin)](https://linkedin.com/in/lucas-villagra-cybersecurity)
[![GitHub](https://img.shields.io/badge/GitHub-Lucas18062025-181717?style=flat&logo=github)](https://github.com/Lucas18062025)
[![Portfolio](https://img.shields.io/badge/Portfolio-lucas18062025.github.io-00D4FF?style=flat&logo=githubpages)](https://lucas18062025.github.io/Portafolio/)

---

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Podés usarlo, modificarlo y distribuirlo libremente con atribución.  
Ver archivo [LICENSE](LICENSE) para más detalles.

---

> *"La seguridad no es un producto, es un proceso."* — Bruce Schneier
