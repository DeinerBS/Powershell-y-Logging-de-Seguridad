# Resultados preliminares — 18 de octubre de 2026

Datos: `datos/ejemplo.json` (340 eventos, ventana 16:45–17:45), `evidencia/estado-antes.json`, `evidencia/estado-despues.json`.

## Entorno

| Elemento | Valor |
|---|---|
| Sistema | Windows 11 Enterprise LTSC Evaluation, build 26100 |
| PowerShell | 5.1.26100.9444 |
| Equipo | W11-WM (VM propia, aislada) |
| Umbral de bloqueo de cuenta | 10 intentos (valor por defecto; observado en ambas pruebas) |
| Scripts | `Configurar-Auditoria.ps1` y `Recolectar-Eventos.ps1` v0.2.0 |
| Cuenta de prueba | `prueba_isw612` (local, creada y eliminada en la prueba) |
| Generación de fallos | `runas /user:prueba_isw612 cmd` con contraseña incorrecta, a mano |

## Tabla 1. Visibilidad por defecto frente a auditoría activa

Fuente: `estado-antes.json` (configuración por defecto) y `estado-despues.json` (tras `-Accion Activar`).

| Evento / dato | Qué registra | Por defecto | Con auditoría activa |
|---|---|---|---|
| 4624 | Inicio de sesión exitoso | Sí | Sí |
| 4625 | Inicio de sesión fallido | Sí | Sí |
| 4625 con "cuenta bloqueada" | Intentos contra una cuenta ya bloqueada | **No** | Sí |
| 4740 | Momento en que se bloquea la cuenta | Sí | Sí |
| 4688 | Programas que se ejecutan | **No** | Sí |
| 4688 + línea de comandos | Con qué parámetros se ejecutaron | **No** | Sí |
| 4104 | Contenido de los scripts de PowerShell | **No** (solo bloques "sospechosos") | Sí |
| Tamaño del registro Security | | 20 MB, circular | 128 MB, circular |
| Tamaño de PowerShell/Operational | | 15 MB, circular | 64 MB, circular |

**Resultado:** con la configuración por defecto, 4 de los 7 tipos de visibilidad estudiados están desactivados.

## Tabla 2. Simulación de fuerza bruta: misma prueba, dos configuraciones

Cada intento ejecutó `runas.exe`, y el 4688 lo registró en ambas pruebas, porque la creación de procesos ya estaba activa en las dos. Eso permite contar los intentos reales y compararlos con los 4625.

| | Prueba 1 (16:49–16:52) | Prueba 2 (17:41–17:44) |
|---|---|---|
| Subcategoría *Account Lockout*, errores | Desactivada (por defecto) | Activada |
| Intentos reales (`runas.exe` en 4688) | 16 | 13 |
| 4625 "Contraseña incorrecta" (0xc000006a) | 10 | 10 |
| 4740 (cuenta bloqueada) | 16:51:44 | 17:43:33 |
| Intentos después del bloqueo | 6 | 3 |
| 4625 "Cuenta bloqueada" (0xc0000234) | **0** | **3** |
| Intentos visibles en 4625 | **10 de 16 (62,5 %)** | **13 de 13 (100 %)** |

**Resultado:** con la configuración por defecto, los intentos posteriores al bloqueo **no dejan ningún 4625**. En la prueba 1 se perdieron 6 de 16 intentos (37,5 %). Activar *Account Lockout* (errores) cerró ese punto ciego.

## Tabla 3. Otros hallazgos

| Hallazgo | Evidencia | Uso en el documento |
|---|---|---|
| El bloqueo ocurre exactamente al 10.º fallo y el 4740 se registra en el mismo segundo que ese 4625 | 16:51:44 y 17:43:33 | Metodología y Resultados |
| PowerShell marcó por su cuenta como **sospechoso** (4104, nivel Advertencia) el comando `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` | 3 eventos: 17:06:45, 17:25:51, 17:41:23 | Discusión: la detección automática de PowerShell sí reconoce el salto de la directiva de ejecución |
| El 4104 genera mucho volumen: 258 de 340 eventos (76 %), sobre todo del propio laboratorio (221 de consola y 37 de los scripts del proyecto) | `conteo_por_id` | Discusión: más visibilidad trae más ruido, y hace falta filtrar o tener reglas |
| El ocultamiento de secretos funcionó con datos reales: `New-LocalUser … -Password [OCULTO]` | 4104 de 17:41:39 | Implementación |
| Falso positivo del ocultamiento: `runas /user:prueba_isw612 cmd` salió como `… [OCULTO]` | 29 eventos 4688 | Bitácora; corregido en v0.2.1 |
| Un 4625 de la cuenta de administrador (`win-wm`) a las 17:28:36 | Error de contraseña del propio equipo | Ruido; no forma parte de la simulación |
| 4624 = 0 en la ventana | No hubo inicios de sesión interactivos nuevos y las cuentas del sistema se filtran | Limitación de la ventana elegida |

## Respuesta preliminar a la pregunta de investigación

Con la configuración por defecto de Windows 11 LTSC, los eventos permiten **ver** un ataque de fuerza bruta (4625 y 4740), pero de forma **incompleta**: se pierden los intentos posteriores al bloqueo, y no queda registro de qué programas se ejecutaron (4688) ni del contenido de los scripts de PowerShell (4104). Activando cuatro subcategorías de auditoría y dos valores de registro, la visibilidad de los intentos pasó del 62,5 % al 100 % en la prueba. La configuración se revirtió por completo después (capturas 01 y 06 idénticas).

## Capturas asociadas (Figuras para el documento)

| Archivo | Contenido | Tabla / sección |
|---|---|---|
| `00a-entorno-versiones.png` | Versión de PowerShell y de Windows | Metodología |
| `00-revertir-v0.1.png` | Reversión de la primera prueba; tamaños por defecto de los registros | Metodología, reversibilidad |
| `01-estado-antes.png` | Estado por defecto (v0.2.0): 4 de 7 visibilidades en NO | Tabla 1 |
| `02-activar.png` | Las 7 visibilidades en SÍ | Tabla 1 |
| `03-bloqueo.png` | Intentos con `runas`: error 1326 y luego 1909 (cuenta bloqueada) | Tabla 2 |
| `04-05-recoleccion-y-tabla-4625-4740.png` | Conteo por ID (340 eventos) y secuencia de 4625 y 4740 de ambas pruebas | Tabla 2 (figura principal) |
| `06-revertir.png` | Estado final igual al inicial | Reversibilidad |
| `07-cuenta-eliminada.png` | `prueba_isw612` eliminada | Limpieza del laboratorio |
| `prueba-v0.1/v01-01-cuenta-prueba-creada.png` | Creación de la cuenta de prueba (primera prueba) | Metodología |
| `prueba-v0.1/v01-02-bloqueo-1909.png` | Primer bloqueo observado | Tabla 2, prueba 1 |
| `prueba-v0.1/v01-03-recoleccion.png` | Recolección v0.1.0: 128 eventos | Historia del método |
| `prueba-v0.1/v01-04-tabla-4625-y-busqueda-secretos.png` | 4625 sin "cuenta bloqueada" y búsqueda de contraseñas en el JSON | Tabla 2 y seguridad del JSON |
| `prueba-v0.1/v01-05-auditpol-account-lockout-solo-aciertos.png` | `auditpol`: Bloqueo de cuenta = Aciertos (causa del punto ciego) | Discusión |
| `bitacora/error-01-count-propertynotfound.png` | Error del recolector v0.1.0 con 0 eventos | Bitácora de IA |
