# Requisitos filtrados — Tema 4: PowerShell y logging de seguridad

Resumen del enunciado (ISW-612, Unidad III) con solo lo que aplica a este tema.

## Datos generales

- Vale **20 %** del curso, en parejas. Se califica sobre 100 puntos.
- Pregunta: **¿Qué visibilidad dan los eventos y el logging de PowerShell para detectar fuerza bruta y abuso de scripts?**
- Arquitectura obligatoria: **script PowerShell → JSON (contrato documentado) → app web** que lo explica a alguien no técnico.

## Fechas

| Fecha | Hito | Qué se entrega | Estado |
|---|---|---|---|
| 12 oct | Entregable 0 (en clase) | Ficha de proyecto (10 pts) | Hecho |
| **19 oct** | **Seguimiento** | **Repositorio con un primer script funcionando y un JSON de ejemplo** | **Este paquete** |
| 26 oct | Entrega final y defensa | Documento APA (PDF), PPTX, repositorio completo, bitácora de IA, demo en vivo | Pendiente |

## Qué investigar (Anexo A.4)

- Política de auditoría avanzada (`auditpol`) y los eventos 4624, 4625, 4688 y 4104.
- Registro de bloques de script, de módulos y transcripción de PowerShell, y su riesgo (pueden guardar contraseñas).
- Tamaño y retención de los registros.
- Cómo se ve la fuerza bruta: muchos 4625 contra la misma cuenta o desde el mismo origen en poco tiempo.

## Script

| Requisito | Cubierto por |
|---|---|
| Activar auditoría y logging de PowerShell, mostrando el estado anterior | `Configurar-Auditoria.ps1 -Accion Estado / Activar` |
| Reversible, con confirmación | `-Accion Revertir`, confirmación y respaldo automático |
| Recolector con `Get-WinEvent -FilterHashtable` que normaliza a JSON (hora, ID, cuenta, origen, tipo de logon, resumen) | `Recolectar-Eventos.ps1` |
| Intentos fallidos controlados contra una cuenta de prueba propia | Paso manual en `guia-entrega-19oct.md` |

## JSON — campos mínimos

`hora`, `id_evento`, `cuenta`, `origen`, `tipo_logon`, `resumen`. Documentados en `datos/esquema.md`.

## App web (26 oct)

- Línea de tiempo con filtros por ID, cuenta y origen.
- Reglas de detección configurables (p. ej. 5 fallos en 2 minutos) con panel de alertas.
- Explicación simple de cada tipo de evento.
- Reglas generales: HTML+JS sin servidor, datos solo en el navegador, semáforo/nivel de riesgo, exportar JSON o PDF, botón "Cargar datos de ejemplo", contenido mostrado con `textContent`, no romperse con JSON vacío o dañado.
- Pantallas mínimas: Inicio, Carga, Resumen, Detalle, Exportar, Acerca de.

## Evidencia para el documento

- Qué **no** se ve con la configuración por defecto frente a lo que **sí** se ve con la auditoría activa.
- La alerta disparada por la regla durante la simulación.

## Para nota destacada

- Mapear alertas a técnicas de MITRE ATT&CK (p. ej. T1110 fuerza bruta, T1059.001 PowerShell).
- Filtrar datos sensibles antes de exportar (ya hay una primera versión en el recolector).

## Rúbrica

| Criterio | Pts |
|---|---|
| Ficha | 10 |
| Documento APA (10-15 págs., ≥ 8 fuentes, ≥ 4 oficiales/académicas) | 25 |
| Script PowerShell (funciona, comentado, seguro, reversible, JSON documentado) | 20 |
| App web | 15 |
| Presentación y defensa (12 min + 5 de preguntas, ambos participan, cambio en vivo posible) | 10 |
| Bitácora de IA (lo más valorado: errores de la IA y cómo se detectaron) | 10 |
| Repositorio reproducible | 10 |

## Reglas de ética que aplican

- Solo VM propias y aisladas; nada de malware real; ataques simulados con medios propios e inofensivos.
- No subir credenciales ni datos reales; citar y respetar licencias de lo que sea de terceros.
- Ante la duda sobre si una prueba es segura, consultar al profesor antes.
