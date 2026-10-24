# PowerShell y logging de seguridad en Windows — ISW-612, Tema 4

Universidad Técnica Nacional · Ingeniería del Software · ISW-612 Administración de Sistemas Operativos de Red · Prof. Marcos Castro

**Integrantes:** Deiner Brenes Soto · Warner Mora Taisigue

> **Estado del repositorio (26 de octubre de 2026):** scripts funcionando y probados en la VM, JSON de ejemplo real (`datos/ejemplo.json`), resultados (`evidencia/resultados-19oct.md`) y app web (`web/index.html`).
>
> **Resultado preliminar:** con la configuración por defecto, los intentos contra una cuenta ya bloqueada no generan 4625. En la prueba solo fueron visibles 10 de 16 intentos (62,5 %); con la auditoría activada, 13 de 13 (100 %).

## Pregunta de investigación

¿Qué visibilidad dan los eventos de Windows y el logging de PowerShell para detectar fuerza bruta y abuso de scripts?

**Hipótesis:** Creemos que con Windows por defecto solo vamos a ver los inicios de sesión (4624 y
4625), y que casi nada de lo que pasa con procesos y scripts (4688 y 4104) va a quedar
registrado. Al activar la auditoría y el logging de PowerShell deberían aparecer los cuatro
eventos, y una regla simple como “5 fallos en 2 minutos” debería detectar una fuerza bruta
simulada. Lo esperábamos porque, según Microsoft, parte de estos registros se activa por
política, aunque había que confirmarlo en la VM.

## Qué hace el proyecto

| Pieza | Archivo | Qué hace |
|---|---|---|
| Script 1 | `script/Configurar-Auditoria.ps1` | Muestra qué eventos se ven hoy (`Estado`), activa la auditoría necesaria guardando un respaldo (`Activar`) y deja el equipo como estaba (`Revertir`). |
| Script 2 | `script/Recolectar-Eventos.ps1` | Lee los eventos 4624, 4625, 4688, 4104 y 4740, los normaliza y los exporta a JSON. Solo lee, no cambia nada. |
| Contrato | `datos/esquema.md` | Qué significa cada campo del JSON. |
| App web | `web/index.html` | Carga el JSON, muestra un semáforo de riesgo, los hallazgos principales, la tabla de eventos con filtros, la regla configurable "N fallos en X minutos", explicaciones simples y exportación a JSON o PDF. |

```
Configurar-Auditoria.ps1 ──► Windows registra 4624/4625/4688/4104
                                         │
Recolectar-Eventos.ps1  ◄────────────────┘
          │  exporta
          ▼
   datos/*.json  (contrato, ver esquema.md)
          │  se carga en el navegador
          ▼
   web/index.html  (todo se procesa localmente)
```

## Eventos que se estudian

| ID | Registro | Qué significa | Cómo se activa |
|---|---|---|---|
| 4624 | Security | Inicio de sesión exitoso | Subcategoría de auditoría *Logon*, aciertos |
| 4625 | Security | Inicio de sesión fallido | Subcategoría *Logon*, errores. Los intentos contra una cuenta **ya bloqueada** requieren además *Account Lockout*, errores |
| 4688 | Security | Se creó un proceso | Subcategoría *Process Creation* + valor `ProcessCreationIncludeCmdLine_Enabled` para ver el comando |
| 4740 | Security | Windows bloqueó una cuenta por demasiados intentos fallidos | Subcategoría *User Account Management*, aciertos |
| 4104 | Microsoft-Windows-PowerShell/Operational | Bloque de script de PowerShell | `EnableScriptBlockLogging` (PowerShell registra por su cuenta los bloques que considera sospechosos aunque esté desactivado) |

## Requisitos

- Probado en: Windows 11 Enterprise LTSC Evaluation (build 26100), PowerShell 5.1.26100.9444.
- Máquina virtual **propia y aislada** (Hyper-V o VirtualBox) con Windows 10/11 o Windows Server 2019/2022 de evaluación. **Nunca** en equipos de la universidad ni de terceros.
- Windows PowerShell 5.1 (viene con Windows). No requiere módulos extra.
- Consola **como administrador** (leer el registro Security y cambiar la auditoría lo exigen).
- Si aparece un error de política de ejecución, solo para esa ventana: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

## Cómo ejecutar

```powershell
cd <ruta>\proyecto-isw612-tema4\script

# 1) Ver qué se registra hoy y guardarlo como evidencia
.\Configurar-Auditoria.ps1 -Accion Estado -SalidaEstado ..\evidencia\estado-antes.json

# 2) Recolectar con la configuración por defecto (línea base)
.\Recolectar-Eventos.ps1 -Horas 24 -Perfil por_defecto -Salida ..\evidencia\eventos-por-defecto.json

# 3) Activar auditoría (pide confirmación y guarda respaldo en ..\respaldo)
.\Configurar-Auditoria.ps1 -Accion Activar
#    Cerrar y abrir una NUEVA consola de PowerShell (administrador)

# 4) Generar actividad de prueba (ver docs/guia-entrega-19oct.md) y recolectar
.\Recolectar-Eventos.ps1 -Horas 1 -Perfil auditoria_activa -Salida ..\datos\ejemplo.json

# 5) Dejar el equipo como estaba
.\Configurar-Auditoria.ps1 -Accion Revertir
```

Parámetros útiles del recolector: `-Horas`, `-MaxPorId`, `-IncluirCuentasSistema`, `-Perfil`, `-Nota`. Ver `Get-Help .\Recolectar-Eventos.ps1 -Full`.

## Cómo abrir la web

Doble clic en `web/index.html`. No necesita servidor, internet ni instalación.

| Pantalla | Qué tiene |
|---|---|
| Inicio | Qué hace la herramienta, los tres pasos para usarla, la carga del JSON y el botón **Cargar datos de ejemplo** (la salida real de la VM). |
| Resumen | Semáforo de riesgo (con color y texto), cifras, los tres hallazgos principales y recomendaciones. |
| Eventos | La regla "N fallos en X minutos" (por defecto 5 en 2), filtros por tipo de evento, cuenta y origen, la tabla en orden de hora y la explicación de cada evento al hacer clic. |
| Exportar | Descarga del resultado en JSON o impresión / PDF. |
| Acerca de | Metodología en pocas líneas, glosario de eventos y fuentes. |

Archivos de prueba en `web/pruebas/`: un JSON vacío, uno dañado, uno con otra estructura y uno con etiquetas HTML (para comprobar que la página muestra el contenido como texto y no lo ejecuta).
## Estructura

```
proyecto-isw612-tema4/
├─ README.md
├─ script/            Configurar-Auditoria.ps1, Recolectar-Eventos.ps1
├─ datos/
│  ├─ ejemplo.json            salida real de una ejecución en la VM
│  ├─ ejemplo-ilustrativo.json   ejemplo ficticio (forma del contrato)
│  └─ esquema.md              qué significa cada campo
├─ web/               index.html, css/, js/ y pruebas/
├─ evidencia/         capturas y JSON de antes/después
├─ bitacora-ia.md
└─ docs/              requisitos del tema, guía de ejecución, documento APA y PPTX
```

## Limitaciones conocidas

- El ocultamiento de secretos (`[OCULTO]`) usa patrones simples (`-Password`, `password=`, `ConvertTo-SecureString "…"`, `net user x clave`). Un secreto escrito de otra forma puede quedar visible. **Revisar el JSON antes de subirlo.**
- La auditoría de línea de comandos y el registro de bloques de script pueden guardar contraseñas en texto claro en el propio Windows; Microsoft recomienda *Protected Event Logging* para uso fuera de diagnóstico. En este laboratorio se activan solo durante la prueba y luego se revierten.
- Por defecto se omiten los eventos de cuentas del sistema para reducir ruido; los 4625 nunca se omiten.
- Probado únicamente en el entorno descrito en la sección Metodología del documento.

## Seguridad y ética

- Todo se ejecuta en VM propias. No se usa malware ni herramientas de ataque.
- Los intentos fallidos se generan a mano contra una cuenta de prueba propia de la VM.
- No se suben credenciales, llaves ni datos reales: `respaldo/` y `datos/salida/` están en `.gitignore`.

## Uso de IA

Los scripts se escribieron con ayuda de un asistente de IA (Claude) y fueron revisados y probados por el equipo. Cada uso está registrado en `bitacora-ia.md`.

## Fuentes

- Microsoft. (s. f.). *4625(F): An account failed to log on*. Microsoft Learn. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Microsoft. (s. f.). *about_Logging* (Windows PowerShell 5.1). Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
- Microsoft. (s. f.). *Command line process auditing*. Microsoft Learn. https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing
- Microsoft. (s. f.). *auditpol*. Microsoft Learn. https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol
- Microsoft. (s. f.). *auditpol restore*. Microsoft Learn. https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-restore

