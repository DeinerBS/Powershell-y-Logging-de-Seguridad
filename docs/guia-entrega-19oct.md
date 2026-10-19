# Guía para la entrega del 19 de octubre

**Qué pide el enunciado para esta fecha:** repositorio con un primer script funcionando y un JSON de ejemplo; lo revisa el profesor.

Tiempo estimado: 45 a 60 minutos en la VM.

## 0. Preparar la VM (10 min)

1. Encender la VM de laboratorio (Windows de evaluación, red aislada o NAT).
2. **Tomar un snapshot/punto de control** llamado `antes-tema4`. Si algo sale mal, se vuelve aquí.
3. Copiar la carpeta `proyecto-isw612-tema4` a la VM (por ejemplo `C:\Lab\proyecto-isw612-tema4`).
4. Abrir **Windows PowerShell como administrador**:
   ```powershell
   cd C:\Lab\proyecto-isw612-tema4\script
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   $PSVersionTable.PSVersion          # anotar en la bitácora/metodología
   (Get-CimInstance Win32_OperatingSystem).Caption, (Get-CimInstance Win32_OperatingSystem).BuildNumber
   ```

## 1. Medir la configuración por defecto (5 min)

```powershell
.\Configurar-Auditoria.ps1 -Accion Estado -SalidaEstado ..\evidencia\estado-antes.json
.\Recolectar-Eventos.ps1 -Horas 24 -Perfil por_defecto -Salida ..\evidencia\eventos-por-defecto.json
```
Captura de pantalla de ambas salidas → `evidencia/01-estado-por-defecto.png`. Fíjense en las advertencias: es lo primero de la evidencia "qué no se ve por defecto".

## 2. Activar la auditoría (5 min)

```powershell
.\Configurar-Auditoria.ps1 -Accion Activar     # responder "S"/"Y" a la confirmación
```
Captura → `evidencia/02-activar.png`. **Cerrar la consola y abrir otra como administrador** (el registro de bloques de script aplica a sesiones nuevas).

## 3. Generar actividad de prueba (10 min)

1. Crear una cuenta local de prueba, propia de la VM (contraseña inventada, que no usen en ningún otro lado):
   ```powershell
   $p = Read-Host -AsSecureString "Contraseña para prueba_isw612"
   New-LocalUser -Name prueba_isw612 -Password $p -Description "Cuenta de prueba ISW-612"
   ```
2. Generar unos 6 intentos fallidos escribiendo a mano una contraseña **equivocada**. Cada intento genera un evento 4625:
   - **Opción A (recomendada):** en PowerShell, `runas /user:prueba_isw612 cmd` y escribir una contraseña incorrecta. Repetir con ↑ + Enter.
   - **Opción B:** Inicio → Cerrar sesión → elegir `prueba_isw612` abajo a la izquierda y escribir mal la contraseña.
   - Nota: en Windows 11 la pantalla de bloqueo (Win + L) muchas veces no muestra "Otro usuario", y en Hyper-V con sesión mejorada solo desconecta la ventana.
   - Comprobar: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 10 | Format-Table TimeCreated, Id`
   Antes, revisen con `net accounts` el umbral de bloqueo; Windows 11 reciente trae 10 intentos por defecto. Si se bloquea la cuenta, también es un resultado interesante (código `0xc0000234`).
3. Volver a entrar con su cuenta de administrador y ejecutar algunos comandos normales en PowerShell (`Get-LocalUser`, `whoami`, `ipconfig`) para tener 4104 y 4688.

## 4. Recolectar el JSON de ejemplo (5 min)

```powershell
.\Recolectar-Eventos.ps1 -Horas 1 -Perfil auditoria_activa -Nota "Después de 6 intentos fallidos manuales" -Salida ..\datos\ejemplo.json
.\Configurar-Auditoria.ps1 -Accion Estado -SalidaEstado ..\evidencia\estado-despues.json
```
Captura → `evidencia/03-recoleccion.png`.

**Revisar `datos/ejemplo.json` a mano** antes de subirlo: que no tenga contraseñas ni datos personales. Si el nombre del equipo o del usuario es personal, renombren la VM/cuenta y repitan.

## 5. Revertir (5 min)

```powershell
.\Configurar-Auditoria.ps1 -Accion Revertir
Remove-LocalUser -Name prueba_isw612
```
Comparar con `estado-antes.json`: deben coincidir. Captura → `evidencia/04-revertir.png`. Esto ya sirve como evidencia de que el script es reversible.

## 6. Subir al repositorio (10 min)

```bash
git add .
git commit -m "Entrega 19-oct: recolector de eventos, configuración de auditoría y JSON de ejemplo"
git push
```

## 7. Bitácora de IA (10 min)

Completar las columnas "Qué verificaron", "Qué corrigieron" y "Qué aprendieron" de `bitacora-ia.md` con lo que realmente pasó al ejecutar. Si algo falló y lo arreglaron, anótenlo: es lo más valorado.

## Lista rápida antes de entregar

- [ ] `datos/ejemplo.json` existe y es salida real de la VM.
- [ ] Tiene eventos de los cuatro IDs (o advertencias que expliquen por qué falta alguno).
- [ ] `README.md` tiene nombres, hipótesis y versión de Windows usada.
- [ ] `evidencia/` tiene capturas de antes, activar, recolección y revertir.
- [ ] No hay contraseñas ni carpetas `respaldo/` o `datos/salida/` en el commit.
- [ ] La bitácora tiene las primeras entradas verificadas.
