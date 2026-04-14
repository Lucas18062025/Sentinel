# Changelog — Sentinel

Todas las versiones siguen el estándar [Semantic Versioning](https://semver.org/).

---

## [5.0] — 2026-03-27 — "Apex"

### Añadido
- Motor de streaming de 2 etapas (sin carga en RAM)
- Progreso visual optimizado: actualización cada 100 archivos
- Auditoría en tiempo real de los 3 perfiles del Firewall de Windows
- Logger `Write-SentinelLog` con niveles y colores diferenciados
- Métricas de disco Before/After con cálculo de MB recuperados
- Soporte nativo para `-WhatIf` via `SupportsShouldProcess`
- Parámetro `-Force` para modo automático sin confirmaciones
- Parámetro `-DetailedLog` para trazabilidad forense completa
- Validación de privilegios de Administrador al inicio

### Mejorado
- Regex de exclusión unificado (antes: múltiples condiciones separadas)
- Pre-validación del directorio de logs fuera de funciones (ganancia de velocidad)
- Lógica de filtrado interna en ForEach (eliminado pipe extra de Where-Object)

### Arquitectura
- Separación clara en 6 módulos funcionales comentados
- Manejo de concurrencia de logs con `-ErrorAction SilentlyContinue`

---

## [4.0] — Versión anterior

- Motor básico de limpieza de temporales
- Log simple sin niveles diferenciados

---

## [3.0] — Versión anterior

- Primera versión con auditoría de red

---

*Desarrollado por Lucas Villagra — Tucumán, Argentina*
