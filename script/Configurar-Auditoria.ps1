#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Muestra, activa o revierte la auditoría de seguridad y el logging de PowerShell
    que necesita el proyecto (ISW-612, Tema 4).

.DESCRIPTION
    Acciones:
      Estado   -> Lee la configuración actual y dice qué eventos (4624, 4625, 4688, 4104)
                  se pueden ver hoy en el equipo. Opcionalmente la guarda en un JSON.
      Activar  -> Guarda un respaldo del estado actual y luego activa:
                    * Subcategoría "Logon" (aciertos y errores)      -> eventos 4624 y 4625
                    * Subcategoría "Process Creation" (aciertos)      -> evento 4688
                    * Subcategoría "Account Lockout" (aciertos y errores) -> 4625 de cuenta bloqueada
                    * Subcategoría "User Account Management"          -> evento 4740
                    * Línea de comandos dentro del 4688 (registro)
                    * Script Block Logging de PowerShell (registro)   -> evento 4104
                    * Tamaño mínimo de los registros Security y PowerShell/Operational
      Revertir -> Devuelve el equipo al estado guardado en un respaldo.

    Las subcategorías de auditpol se manejan por GUID (no por nombre) porque los nombres
    cambian según el idioma de Windows ("Logon" vs "Inicio de sesión").

    Ejecutar SOLO en una máquina virtual propia del laboratorio.

.PARAMETER Accion
    Estado, Activar o Revertir.

.PARAMETER SalidaEstado
    (Estado) Ruta de un archivo JSON donde guardar el estado. Si se omite, solo se muestra.

.PARAMETER CarpetaRespaldo
    Carpeta donde se guardan los respaldos. Por defecto: <repo>\respaldo (ignorada por git).

.PARAMETER Respaldo
    (Revertir) Carpeta de un respaldo concreto. Si se omite, se usa el más reciente.

.PARAMETER TamanoSecurityMB
    (Activar) Tamaño mínimo del registro Security en MB. Nunca se reduce un tamaño mayor.

.EXAMPLE
    .\Configurar-Auditoria.ps1 -Accion Estado -SalidaEstado ..\evidencia\estado-antes.json

.EXAMPLE
    .\Configurar-Auditoria.ps1 -Accion Activar

.EXAMPLE
    .\Configurar-Auditoria.ps1 -Accion Revertir

.NOTES
    Proyecto ISW-612 · Tema 4 · Script escrito con ayuda de IA (Claude) y revisado por el
    equipo: ver bitacora-ia.md. Fuentes: auditpol (Microsoft Learn), about_Logging (Microsoft
    Learn), Command line process auditing (Microsoft Learn).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Estado', 'Activar', 'Revertir')]
    [string]$Accion,

    [string]$SalidaEstado,

    [string]$CarpetaRespaldo = (Join-Path (Split-Path $PSScriptRoot -Parent) 'respaldo'),

    [string]$Respaldo,

    [ValidateRange(20, 1024)]
    [int]$TamanoSecurityMB = 128
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VersionScript = '0.2.0'

# ---------------------------------------------------------------------------
# 1. Qué vamos a revisar/cambiar (una sola tabla para las tres acciones)
# ---------------------------------------------------------------------------

# Subcategorías de la política de auditoría avanzada (GUID fijo, independiente del idioma).
$Subcategorias = @(
    [pscustomobject]@{
        Nombre      = 'Logon (Inicio de sesión)'
        Guid        = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        Eventos     = '4624 (aciertos), 4625 (errores)'
        Deseado     = 3   # 3 = aciertos y errores
    },
    [pscustomobject]@{
        Nombre      = 'Process Creation (Creación de procesos)'
        Guid        = '{0CCE922B-69AE-11D9-BED3-505054503030}'
        Eventos     = '4688'
        Deseado     = 1   # 1 = solo aciertos (un proceso que "falla al crearse" no aporta aquí)
    },
    [pscustomobject]@{
        # Agregado en v0.2.0: sin "errores" aquí, un intento contra una cuenta YA bloqueada
        # no genera 4625 (hallazgo en la VM el 18-oct, ver bitacora-ia.md).
        Nombre      = 'Account Lockout (Bloqueo de cuenta)'
        Guid        = '{0CCE9217-69AE-11D9-BED3-505054503030}'
        Eventos     = '4625 con motivo "cuenta bloqueada"'
        Deseado     = 3
    },
    [pscustomobject]@{
        # Agregado en v0.2.0: registra el momento en que Windows bloquea la cuenta (4740).
        Nombre      = 'User Account Management (Administración de cuentas de usuario)'
        Guid        = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        Eventos     = '4740 (cuenta bloqueada), 4720 (cuenta creada), 4726 (eliminada)'
        Deseado     = 3
    }
)

# Valores de registro que activan detalles extra en los eventos.
$ValoresRegistro = @(
    [pscustomobject]@{
        Ruta        = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        Nombre      = 'ProcessCreationIncludeCmdLine_Enabled'
        Deseado     = 1
        Descripcion = 'Incluir la línea de comandos en el evento 4688'
    },
    [pscustomobject]@{
        Ruta        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Nombre      = 'EnableScriptBlockLogging'
        Deseado     = 1
        Descripcion = 'Registro de bloques de script de PowerShell (evento 4104)'
    }
)

# Registros de eventos cuyo tamaño revisamos (un registro pequeño se sobrescribe rápido).
$RegistrosEventos = @(
    [pscustomobject]@{ Log = 'Security';                                 MinimoMB = $TamanoSecurityMB },
    [pscustomobject]@{ Log = 'Microsoft-Windows-PowerShell/Operational'; MinimoMB = 64 }
)

# Significado del "Setting Value" del CSV de auditpol /backup.
$TextoAuditoria = @{ 0 = 'Sin auditoría'; 1 = 'Solo aciertos'; 2 = 'Solo errores'; 3 = 'Aciertos y errores' }

# ---------------------------------------------------------------------------
# 2. Funciones de lectura
# ---------------------------------------------------------------------------

function Get-PoliticaAuditoria {
    <# Devuelve un diccionario GUID -> valor (0-3) usando "auditpol /backup".
       Se usa el CSV de respaldo porque su columna "Setting Value" es numérica y no depende
       del idioma de Windows (la salida de /get sí está traducida). #>
    $tmp = Join-Path $env:TEMP ('auditpol_{0}.csv' -f [guid]::NewGuid())
    try {
        $null = & auditpol.exe /backup "/file:$tmp"
        if ($LASTEXITCODE -ne 0) { throw "auditpol /backup terminó con código $LASTEXITCODE." }

        # Columnas por posición: 0 Machine, 1 Target, 2 Subcategory, 3 GUID, 4 Inclusion,
        # 5 Exclusion, 6 Setting Value. Se omite la fila de encabezado.
        $filas = Get-Content -Path $tmp | Select-Object -Skip 1 |
            ConvertFrom-Csv -Header 'Equipo', 'Destino', 'Subcategoria', 'Guid', 'Inclusion', 'Exclusion', 'Valor'

        $mapa = @{}
        foreach ($f in $filas) {
            if ($f.Guid -and $f.Valor -match '^\d+$') { $mapa[$f.Guid.ToUpperInvariant()] = [int]$f.Valor }
        }
        return $mapa
    }
    finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

function Get-ValorRegistro {
    param([string]$Ruta, [string]$Nombre)
    # Devuelve $null si la clave o el valor no existen.
    $item = Get-ItemProperty -Path $Ruta -Name $Nombre -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Nombre
}

function Get-EstadoActual {
    <# Reúne todo el estado relevante en un objeto que se puede exportar a JSON. #>
    $politica = Get-PoliticaAuditoria

    $auditoria = foreach ($s in $Subcategorias) {
        $valor = 0
        if ($politica.ContainsKey($s.Guid)) { $valor = $politica[$s.Guid] }
        [ordered]@{
            subcategoria = $s.Nombre
            guid         = $s.Guid
            eventos      = $s.Eventos
            valor        = $valor
            descripcion  = $TextoAuditoria[$valor]
            aciertos     = [bool]($valor -band 1)
            errores      = [bool]($valor -band 2)
        }
    }

    $registro = foreach ($r in $ValoresRegistro) {
        $actual = Get-ValorRegistro -Ruta $r.Ruta -Nombre $r.Nombre
        [ordered]@{
            ruta        = $r.Ruta
            nombre      = $r.Nombre
            valor       = $actual
            activo      = ($actual -eq 1)
            descripcion = $r.Descripcion
        }
    }

    $logs = foreach ($l in $RegistrosEventos) {
        $cfg = Get-WinEvent -ListLog $l.Log
        [ordered]@{
            log        = $l.Log
            habilitado = $cfg.IsEnabled
            tamano_mb  = [math]::Round($cfg.MaximumSizeInBytes / 1MB, 1)
            tamano_bytes = $cfg.MaximumSizeInBytes   # valor exacto, usado al revertir
            modo       = [string]$cfg.LogMode
        }
    }

    # Traducción a "qué se ve": es lo que sirve para la comparación antes/después.
    $logon   = @($auditoria)[0]
    $proceso = @($auditoria)[1]
    $bloqueo = @($auditoria)[2]
    $cuentas = @($auditoria)[3]
    $cmdLine = @($registro)[0]
    $sbl     = @($registro)[1]

    $visibilidad = [ordered]@{
        '4624'               = $logon.aciertos
        '4625'               = $logon.errores
        '4625_cuenta_bloqueada' = $bloqueo.errores
        '4740'               = $cuentas.aciertos
        '4688'               = $proceso.aciertos
        '4688_linea_comandos' = ($proceso.aciertos -and $cmdLine.activo)
        # Nota: aun sin activarlo, PowerShell 5+ registra como 4104 (nivel Advertencia) los
        # bloques que considera sospechosos. "true" aquí significa registro de TODOS los bloques.
        '4104'               = $sbl.activo
    }

    return [ordered]@{
        equipo         = $env:COMPUTERNAME
        fecha          = (Get-Date).ToString('o')
        version_script = $VersionScript
        auditoria      = @($auditoria)
        registro       = @($registro)
        logs           = @($logs)
        visibilidad    = $visibilidad
    }
}

function Write-Estado {
    param($Estado)
    Write-Host "`n=== Estado de auditoría en $($Estado.equipo) ===" -ForegroundColor Cyan
    $Estado.auditoria | ForEach-Object { [pscustomobject]$_ } |
        Format-Table subcategoria, eventos, descripcion -AutoSize | Out-Host
    $Estado.registro | ForEach-Object { [pscustomobject]$_ } |
        Format-Table descripcion, valor, activo -AutoSize | Out-Host
    $Estado.logs | ForEach-Object { [pscustomobject]$_ } |
        Format-Table log, habilitado, tamano_mb, modo -AutoSize | Out-Host

    Write-Host '¿Qué eventos se pueden ver hoy?' -ForegroundColor Cyan
    foreach ($k in $Estado.visibilidad.Keys) {
        $si = $Estado.visibilidad[$k]
        $txt = if ($si) { 'SÍ' } else { 'NO' }
        $color = if ($si) { 'Green' } else { 'Yellow' }
        Write-Host ('  {0,-24} {1}' -f $k, $txt) -ForegroundColor $color
    }
}

function Save-Json {
    param($Objeto, [string]$Ruta)
    $carpeta = Split-Path -Path $Ruta -Parent
    if ($carpeta -and -not (Test-Path $carpeta)) { New-Item -ItemType Directory -Path $carpeta -Force | Out-Null }
    $json = $Objeto | ConvertTo-Json -Depth 6
    # UTF-8 sin BOM: el navegador (JSON.parse) lo lee sin problemas.
    [System.IO.File]::WriteAllText((Resolve-RutaNueva $Ruta), $json, (New-Object System.Text.UTF8Encoding $false))
}

function Resolve-RutaNueva {
    param([string]$Ruta)
    # Convierte una ruta relativa (que quizá aún no existe) en absoluta.
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Ruta)
}

# ---------------------------------------------------------------------------
# 3. Acciones
# ---------------------------------------------------------------------------

switch ($Accion) {

    'Estado' {
        $estado = Get-EstadoActual
        Write-Estado $estado
        if ($SalidaEstado) {
            Save-Json -Objeto $estado -Ruta $SalidaEstado
            Write-Host "`nEstado guardado en: $(Resolve-RutaNueva $SalidaEstado)" -ForegroundColor Green
        }
    }

    'Activar' {
        $estado = Get-EstadoActual
        Write-Estado $estado

        $mensaje = 'Activar auditoría de Logon, Process Creation, Account Lockout y User Account Management, línea de comandos en 4688, ' +
                   'Script Block Logging y ajustar tamaño de registros (se guarda respaldo antes)'
        if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $mensaje)) {
            Write-Host 'Cancelado. No se cambió nada.' -ForegroundColor Yellow
            return
        }

        # 3.1 Respaldo ANTES de tocar nada.
        $destino = Join-Path $CarpetaRespaldo (Get-Date -Format 'yyyyMMdd-HHmmss')
        New-Item -ItemType Directory -Path $destino -Force | Out-Null
        $null = & auditpol.exe /backup "/file:$(Join-Path $destino 'auditpol.csv')"
        if ($LASTEXITCODE -ne 0) { throw 'No se pudo respaldar la política de auditoría. No se cambió nada.' }
        Save-Json -Objeto $estado -Ruta (Join-Path $destino 'estado.json')
        Write-Host "Respaldo guardado en: $destino" -ForegroundColor Green

        # 3.2 Política de auditoría por GUID.
        foreach ($s in $Subcategorias) {
            $exito = if ($s.Deseado -band 1) { 'enable' } else { 'disable' }
            $error_ = if ($s.Deseado -band 2) { 'enable' } else { 'disable' }
            $null = & auditpol.exe /set "/subcategory:$($s.Guid)" "/success:$exito" "/failure:$error_"
            if ($LASTEXITCODE -ne 0) { throw "auditpol /set falló para $($s.Nombre)." }
            Write-Host "  [OK] $($s.Nombre): $($TextoAuditoria[$s.Deseado])"
        }

        # 3.3 Valores de registro.
        foreach ($r in $ValoresRegistro) {
            if (-not (Test-Path $r.Ruta)) { New-Item -Path $r.Ruta -Force | Out-Null }
            New-ItemProperty -Path $r.Ruta -Name $r.Nombre -Value $r.Deseado -PropertyType DWord -Force | Out-Null
            Write-Host "  [OK] $($r.Descripcion)"
        }

        # 3.4 Tamaño de registros: solo se agranda, nunca se achica.
        foreach ($l in $RegistrosEventos) {
            $cfg = Get-WinEvent -ListLog $l.Log
            $minimo = [long]$l.MinimoMB * 1MB
            if ($cfg.MaximumSizeInBytes -lt $minimo) {
                $cfg.MaximumSizeInBytes = $minimo
                $cfg.SaveChanges()
                Write-Host "  [OK] $($l.Log): tamaño máximo -> $($l.MinimoMB) MB"
            }
            else {
                Write-Host "  [--] $($l.Log): ya tiene $([math]::Round($cfg.MaximumSizeInBytes/1MB)) MB, no se cambia"
            }
        }

        Write-Host "`nListo. Abra una NUEVA ventana de PowerShell para que el registro de bloques aplique." -ForegroundColor Green
        Write-Estado (Get-EstadoActual)
    }

    'Revertir' {
        # 3.5 Elegir el respaldo (el indicado o el más reciente).
        if (-not $Respaldo) {
            if (-not (Test-Path $CarpetaRespaldo)) { throw "No hay respaldos en $CarpetaRespaldo." }
            $ultimo = Get-ChildItem -Path $CarpetaRespaldo -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if (-not $ultimo) { throw "No hay respaldos en $CarpetaRespaldo." }
            $Respaldo = $ultimo.FullName
        }
        $csv = Join-Path $Respaldo 'auditpol.csv'
        $jsonPrevio = Join-Path $Respaldo 'estado.json'
        if (-not (Test-Path $csv) -or -not (Test-Path $jsonPrevio)) { throw "El respaldo $Respaldo está incompleto." }

        if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Restaurar la configuración guardada en $Respaldo")) {
            Write-Host 'Cancelado. No se cambió nada.' -ForegroundColor Yellow
            return
        }

        $previo = Get-Content -Path $jsonPrevio -Raw -Encoding UTF8 | ConvertFrom-Json

        # Política de auditoría completa, tal como estaba.
        $null = & auditpol.exe /restore "/file:$csv"
        if ($LASTEXITCODE -ne 0) { throw 'auditpol /restore falló.' }
        Write-Host '  [OK] Política de auditoría restaurada'

        # Registro: si antes no existía el valor, se borra; si existía, se repone.
        foreach ($r in $previo.registro) {
            if ($null -eq $r.valor) {
                Remove-ItemProperty -Path $r.ruta -Name $r.nombre -ErrorAction SilentlyContinue
                Write-Host "  [OK] $($r.nombre): eliminado (no existía antes)"
            }
            else {
                if (-not (Test-Path $r.ruta)) { New-Item -Path $r.ruta -Force | Out-Null }
                New-ItemProperty -Path $r.ruta -Name $r.nombre -Value ([int]$r.valor) -PropertyType DWord -Force | Out-Null
                Write-Host "  [OK] $($r.nombre): repuesto a $($r.valor)"
            }
        }

        # Tamaño de registros.
        foreach ($l in $previo.logs) {
            $cfg = Get-WinEvent -ListLog $l.log
            $cfg.MaximumSizeInBytes = [long]$l.tamano_bytes
            $cfg.SaveChanges()
            Write-Host "  [OK] $($l.log): tamaño -> $($l.tamano_mb) MB"
        }

        Write-Host "`nReversión completa." -ForegroundColor Green
        Write-Estado (Get-EstadoActual)
    }
}
