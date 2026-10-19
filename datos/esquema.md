# Esquema del JSON de eventos (contrato script → app web)

Versión del esquema: **0.2.0** (0.2.0 agrega el evento 4740; el recolector v0.2.1 usa el mismo esquema) (coincide con `version_script` del recolector).

El archivo lo genera `script/Recolectar-Eventos.ps1`. Está en UTF-8 sin BOM y tiene dos bloques: `metadatos` y `eventos`.

```json
{
  "metadatos": { ... },
  "eventos": [ { ... }, { ... } ]
}
```

## 1. `metadatos`

| Campo | Tipo | Descripción |
|---|---|---|
| `equipo` | texto | Nombre del equipo donde se ejecutó el script. |
| `generado` | texto (ISO 8601) | Fecha y hora de la ejecución, con zona horaria. |
| `version_script` | texto | Versión del recolector que produjo el archivo. |
| `perfil` | texto | Etiqueta para comparar ejecuciones: `por_defecto`, `auditoria_activa`, `simulacion` u `otro`. |
| `ventana_horas` | número | Cuántas horas hacia atrás se leyeron. |
| `desde` / `hasta` | texto (ISO 8601) | Inicio y fin de la ventana. |
| `ids_solicitados` | arreglo de números | `[4624, 4625, 4688, 4104, 4740]` (en 0.1.0 no incluía 4740). |
| `cuentas_sistema_incluidas` | booleano | `false` si se filtraron SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-* y cuentas de equipo (`…$`). |
| `total_eventos` | número | Cantidad de elementos en `eventos`. |
| `conteo_por_id` | objeto | Cantidad exportada por ID, p. ej. `{"4624": 12, "4625": 6, "4688": 40, "4104": 9}`. |
| `advertencias` | arreglo de texto | Avisos legibles (p. ej. "No hay eventos 4688: la auditoría… está desactivada"). Puede estar vacío. |
| `nota` | texto (opcional) | Comentario libre pasado con `-Nota`. |

## 2. `eventos[]` — campos mínimos (exigidos por el enunciado)

| Campo | Tipo | Descripción | Ejemplo |
|---|---|---|---|
| `hora` | texto (ISO 8601) | Momento del evento, con zona horaria. | `"2026-10-18T19:42:05.1234567-06:00"` |
| `id_evento` | número | 4624, 4625, 4688, 4104 o 4740. | `4625` |
| `cuenta` | texto | `DOMINIO\usuario` afectado. En 4688 es quien lanzó el proceso; en 4104 quien ejecutó el script. `(desconocida)` si no viene. | `"VM-ISW612\prueba_isw612"` |
| `origen` | texto | De dónde vino. 4624/4625: IP, o nombre del equipo, o `local`. 4688: ruta del proceso padre. 4104: ruta del script o `(consola interactiva)`. | `"127.0.0.1"` |
| `tipo_logon` | número o `null` | Tipo de inicio de sesión (solo 4624/4625). `null` en 4688 y 4104. | `3` |
| `resumen` | texto | Una frase en lenguaje simple, pensada para mostrarse tal cual. | `"Inicio de sesión FALLIDO para …"` |

## 3. `eventos[]` — campos adicionales

| Campo | Tipo | Descripción |
|---|---|---|
| `log` | texto | Registro de Windows de origen: `Security` o `Microsoft-Windows-PowerShell/Operational`. |
| `detalle` | objeto | Datos propios de cada tipo de evento (ver abajo). |

### `detalle` según el evento

**4624 / 4625**

| Campo | Tipo | Descripción |
|---|---|---|
| `tipo_logon_desc` | texto | Traducción de `tipo_logon` (p. ej. "Red (carpeta compartida, autenticación remota)"). |
| `proceso` | texto | Proceso que pidió el inicio de sesión (puede venir vacío o `-`). |
| `sid` | texto | SID de la cuenta (en 4625 suele ser `S-1-0-0`, "SID nulo"). |
| `codigo` | texto | Solo 4625: código NTSTATUS en minúsculas (SubStatus si no es `0x0`; si no, Status). |
| `motivo` | texto | Solo 4625: traducción del código (p. ej. "Contraseña incorrecta"). |

**4688**

| Campo | Tipo | Descripción |
|---|---|---|
| `proceso` | texto | Ruta completa del programa que se inició. |
| `proceso_padre` | texto | Ruta del programa que lo lanzó. |
| `linea_comandos` | texto | Comando completo, recortado a 300 caracteres y con secretos ocultos (`[OCULTO]`). Vacío si la auditoría de línea de comandos está desactivada. |
| `elevacion` | texto | `TokenElevationType` tal como lo registra Windows (`%%1936` completo, `%%1937` elevado, `%%1938` limitado). |

**4104**

| Campo | Tipo | Descripción |
|---|---|---|
| `sospechoso` | booleano | `true` si PowerShell lo registró con nivel Advertencia (lo marcó como sospechoso por su cuenta). |
| `script_block_id` | texto | GUID del bloque; los scripts largos se parten en varios eventos con el mismo ID. |
| `parte` | texto | `n/total` de ese bloque. |

**4740** (cuenta bloqueada)

| Campo | Tipo | Descripción |
|---|---|---|
| `equipo_llamador` | texto | Equipo desde donde llegaron los intentos (campo *Caller Computer Name*). También se copia en `origen`. |
| `sid` | texto | SID de la cuenta bloqueada. |

## 4. Valores de `tipo_logon`

| Valor | Significado |
|---|---|
| 2 | Interactivo (teclado y pantalla del equipo) |
| 3 | Red (carpeta compartida, autenticación remota) |
| 4 | Lote (tarea programada) |
| 5 | Servicio |
| 7 | Desbloqueo de pantalla |
| 8 | Red con contraseña en texto claro |
| 9 | Credenciales nuevas (runas /netonly) |
| 10 | Remoto interactivo (RDP) |
| 11 | Interactivo con credenciales en caché |

## 5. Reglas para quien consume el JSON (app web)

- Tratar todo el contenido como **texto no confiable**: mostrarlo con `textContent`, nunca con `innerHTML`.
- Si falta `eventos` o no es un arreglo, mostrar un error claro.
- Los campos de `detalle` son opcionales: comprobar que existan antes de usarlos.
- `tipo_logon` puede ser `null`.

## 6. Archivos de este directorio

| Archivo | Qué es |
|---|---|
| `ejemplo.json` | Salida **real** de la VM W11-WM el 18-oct-2026 (recolector v0.2.0, ventana 16:45–17:45, 340 eventos). Análisis en `evidencia/resultados-19oct.md`. |
| `ejemplo-ilustrativo.json` | Ejemplo **ficticio** escrito a mano para mostrar la forma del contrato y probar la app sin VM. No es evidencia. |
| `salida/` | Salidas sin revisar del recolector. Está en `.gitignore`. |
