#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Recolecta los eventos de seguridad 4624, 4625, 4688, 4104 y 4740 y los normaliza a un JSON
    que la aplicación web puede leer (ISW-612, Tema 4).

.DESCRIPTION
    Lee:
      * Registro "Security":                         4624, 4625, 4688, 4740
      * Registro "Microsoft-Windows-PowerShell/Operational": 4104
    y convierte cada evento a un objeto con los campos mínimos del enunciado:
      hora, id_evento, cuenta, origen, tipo_logon, resumen
    más un bloque "detalle" propio de cada tipo de evento.

    Además agrega "metadatos" con el conteo por ID y advertencias cuando un tipo de evento
    no aparece (lo normal es que sea porque la auditoría está desactivada).

    Protección de datos: el texto de los bloques de script (4104) y las líneas de comando
    (4688) se recortan y se ocultan patrones típicos de contraseñas antes de exportar.
    No es perfecto (ver README, "Limitaciones").

    El script SOLO LEE: no cambia nada del sistema.

.PARAMETER Horas
    Ventana de tiempo hacia atrás (por defecto 24 horas).

.PARAMETER Salida
    Ruta del JSON de salida. Por defecto: <repo>\datos\salida\eventos_<EQUIPO>_<fecha>.json

.PARAMETER MaxPorId
    Máximo de eventos leídos por cada ID (los más recientes). Evita archivos enormes.

.PARAMETER IncluirCuentasSistema
    Incluye inicios de sesión y procesos de cuentas del sistema (SYSTEM, LOCAL SERVICE,
    NETWORK SERVICE, DWM-*, UMFD-*, cuentas de equipo terminadas en $). Por defecto se
    excluyen porque son ruido. Los 4625 (fallos) NUNCA se excluyen.

.PARAMETER Perfil
    Etiqueta libre para comparar ejecuciones, p. ej. "por_defecto" o "auditoria_activa".

.PARAMETER Nota
    Texto libre que se copia a metadatos.nota (p. ej. "después de la simulación").

.EXAMPLE
    .\Recolectar-Eventos.ps1 -Horas 2 -Perfil auditoria_activa -Salida ..\datos\ejemplo.json

.NOTES
    Proyecto ISW-612 · Tema 4 · Script escrito con ayuda de IA (Claude) y revisado por el
    equipo: ver bitacora-ia.md. Fuentes: documentación de eventos 4624/4625/4688 y
    about_Logging (Microsoft Learn).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$Horas = 24,

    [string]$Salida,

    [ValidateRange(1, 50000)]
    [int]$MaxPorId = 2000,

    [switch]$IncluirCuentasSistema,

    [ValidateSet('por_defecto', 'auditoria_activa', 'simulacion', 'otro')]
    [string]$Perfil = 'otro',

    [string]$Nota
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VersionScript = '0.2.1'

# ---------------------------------------------------------------------------
# 1. Tablas de traducción a lenguaje simple
# ---------------------------------------------------------------------------

# Tipos de inicio de sesión (campo LogonType de 4624/4625).
$TiposLogon = @{
    2  = 'Interactivo (teclado y pantalla del equipo)'
    3  = 'Red (carpeta compartida, autenticación remota)'
    4  = 'Lote (tarea programada)'
    5  = 'Servicio'
    7  = 'Desbloqueo de pantalla'
    8  = 'Red con contraseña en texto claro'
    9  = 'Credenciales nuevas (runas /netonly)'
    10 = 'Remoto interactivo (Escritorio remoto / RDP)'
    11 = 'Interactivo con credenciales en caché'
}

# Códigos de motivo de 4625 (Status/SubStatus, en minúsculas como vienen en el XML).
$MotivosFallo = @{
    '0xc000006a' = 'Contraseña incorrecta'
    '0xc0000064' = 'El usuario no existe'
    '0xc000006d' = 'Usuario o contraseña incorrectos'
    '0xc0000234' = 'Cuenta bloqueada'
    '0xc0000072' = 'Cuenta deshabilitada'
    '0xc000006f' = 'Fuera del horario permitido'
    '0xc0000070' = 'Equipo no permitido para esta cuenta'
    '0xc0000071' = 'Contraseña vencida'
    '0xc0000193' = 'Cuenta vencida'
    '0xc0000224' = 'Debe cambiar la contraseña'
    '0xc000015b' = 'Tipo de inicio de sesión no permitido'
}

# SIDs de cuentas del sistema (no dependen del idioma).
$SidsSistema = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')

# ---------------------------------------------------------------------------
# 2. Funciones auxiliares
# ---------------------------------------------------------------------------

function Get-DatosEvento {
    <# Convierte los <Data Name="..."> del XML del evento en un diccionario. #>
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Evento)
    $xml = [xml]$Evento.ToXml()
    $d = @{}
    $eventData = $xml.Event.EventData
    if ($null -ne $eventData) {
        foreach ($n in @($eventData.ChildNodes)) {
            if ($n.LocalName -eq 'Data' -and $n.Attributes['Name']) {
                $d[$n.Attributes['Name'].Value] = $n.InnerText
            }
        }
    }
    return $d
}

function Get-Campo {
    <# Lee un campo del diccionario; devuelve '' si no existe (evita errores con StrictMode). #>
    param([hashtable]$Datos, [string]$Nombre)
    if ($Datos.ContainsKey($Nombre) -and $null -ne $Datos[$Nombre]) { return [string]$Datos[$Nombre] }
    return ''
}

function Join-Cuenta {
    param([string]$Dominio, [string]$Usuario)
    if ([string]::IsNullOrWhiteSpace($Usuario) -or $Usuario -eq '-') { return '(desconocida)' }
    if ([string]::IsNullOrWhiteSpace($Dominio) -or $Dominio -eq '-') { return $Usuario }
    return "$Dominio\$Usuario"
}

function Test-CuentaSistema {
    param([string]$Sid, [string]$Usuario)
    if ($SidsSistema -contains $Sid) { return $true }
    if ($Usuario -match '^(DWM-|UMFD-)\d+$') { return $true }
    if ($Usuario.EndsWith('$')) { return $true }   # cuentas de equipo
    return $false
}

function Protect-Texto {
    <# Recorta y oculta patrones típicos de secretos ANTES de exportar.
       Riesgo documentado por Microsoft: la línea de comandos (4688) y los bloques de script
       (4104) pueden contener contraseñas en texto claro. #>
    param([string]$Texto, [int]$Max = 300)
    if ([string]::IsNullOrEmpty($Texto)) { return '' }
    $t = $Texto -replace '\s+', ' '
    # -Password algo / -Token algo / -Secret algo ...
    $t = $t -replace '(?i)(-(?:Password|Passwd|Pwd|Secret|Token|ApiKey|Key)\w*\s*[: ]\s*)("[^"]*"|''[^'']*''|\S+)', '$1[OCULTO]'
    # ConvertTo-SecureString "texto" ...
    $t = $t -replace '(?i)(ConvertTo-SecureString\s+(?:-String\s+)?)("[^"]*"|''[^'']*''|\S+)', '$1[OCULTO]'
    # password=..., pwd: ..., contraseña=...
    $t = $t -replace '(?i)((?:password|passwd|pwd|contrase(?:ñ|n)a)\s*[=:]\s*)("[^"]*"|''[^'']*''|\S+)', '$1[OCULTO]'
    # net user <usuario> <contraseña>  /  net use ... /user:x <contraseña>
    $t = $t -replace '(?i)(\bnet1?(?:\.exe)?\s+user\s+\S+\s+)(?!/)(\S+)', '$1[OCULTO]'
    # Solo para "net use": en "runas /user:x cmd" el texto tras /user: es el programa, no una clave
    # (falso positivo detectado en la VM el 18-oct, corregido en v0.2.1).
    $t = $t -replace '(?i)(\bnet1?(?:\.exe)?\s+use\b.*?/user:\S+\s+)(?!/)(\S+)', '$1[OCULTO]'
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

function Read-Eventos {
    <# Lee eventos de un registro sin romperse cuando no hay coincidencias. #>
    param([string]$Log, [int]$Id, [datetime]$Desde, [int]$Max)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Id; StartTime = $Desde } -MaxEvents $Max -ErrorAction Stop)
    }
    catch {
        # Get-WinEvent lanza un error cuando no encuentra eventos: eso no es un fallo.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }
}

# ---------------------------------------------------------------------------
# 3. Normalizadores: un evento de Windows -> un objeto del contrato JSON
# ---------------------------------------------------------------------------

function ConvertFrom-EventoLogon {
    <# 4624 (éxito) y 4625 (fallo). #>
    param($Evento)
    $d = Get-DatosEvento $Evento
    $usuario = Get-Campo $d 'TargetUserName'
    $sid     = Get-Campo $d 'TargetUserSid'
    $cuenta  = Join-Cuenta (Get-Campo $d 'TargetDomainName') $usuario

    $tipoTxt = Get-Campo $d 'LogonType'
    $tipo = $null
    if ($tipoTxt -match '^\d+$') { $tipo = [int]$tipoTxt }
    $tipoDesc = if ($null -ne $tipo -and $TiposLogon.ContainsKey($tipo)) { $TiposLogon[$tipo] } else { 'Tipo desconocido' }

    # Origen: IP si existe; si no, el nombre del equipo que lo intentó; si no, "local".
    $ip = Get-Campo $d 'IpAddress'
    $estacion = Get-Campo $d 'WorkstationName'
    $origen = if ($ip -and $ip -ne '-') { $ip } elseif ($estacion -and $estacion -ne '-') { $estacion } else { 'local' }

    $detalle = [ordered]@{
        tipo_logon_desc = $tipoDesc
        proceso         = Get-Campo $d 'ProcessName'
        sid             = $sid
    }

    if ($Evento.Id -eq 4624) {
        if (-not $IncluirCuentasSistema -and (Test-CuentaSistema $sid $usuario)) { return $null }
        $resumen = "Inicio de sesión EXITOSO de $cuenta. Tipo: $tipoDesc. Origen: $origen."
    }
    else {
        $status    = (Get-Campo $d 'Status').ToLowerInvariant()
        $subStatus = (Get-Campo $d 'SubStatus').ToLowerInvariant()
        # SubStatus es más específico; si viene en 0x0 se usa Status.
        $codigo = if ($subStatus -and $subStatus -ne '0x0') { $subStatus } else { $status }
        $motivo = if ($MotivosFallo.ContainsKey($codigo)) { $MotivosFallo[$codigo] } else { "Código $codigo" }
        $detalle['codigo'] = $codigo
        $detalle['motivo'] = $motivo
        $resumen = "Inicio de sesión FALLIDO para $cuenta. Motivo: $motivo. Tipo: $tipoDesc. Origen: $origen."
    }

    return [ordered]@{
        hora       = $Evento.TimeCreated.ToString('o')
        id_evento  = $Evento.Id
        cuenta     = $cuenta
        origen     = $origen
        tipo_logon = $tipo
        resumen    = $resumen
        log        = 'Security'
        detalle    = $detalle
    }
}

function ConvertFrom-EventoProceso {
    <# 4688: creación de proceso. #>
    param($Evento)
    $d = Get-DatosEvento $Evento
    $usuario = Get-Campo $d 'SubjectUserName'
    $sid     = Get-Campo $d 'SubjectUserSid'
    if (-not $IncluirCuentasSistema -and (Test-CuentaSistema $sid $usuario)) { return $null }

    $proceso = Get-Campo $d 'NewProcessName'
    $padre   = Get-Campo $d 'ParentProcessName'
    $cmd     = Protect-Texto (Get-Campo $d 'CommandLine')

    $nombre = Split-Path -Path $proceso -Leaf
    $resumen = "Se inició el programa $nombre"
    if ($padre) { $resumen += " desde $(Split-Path -Path $padre -Leaf)" }
    if ($cmd)   { $resumen += ". Comando: $cmd" } else { $resumen += '. (Sin línea de comandos registrada)' }

    return [ordered]@{
        hora       = $Evento.TimeCreated.ToString('o')
        id_evento  = 4688
        cuenta     = Join-Cuenta (Get-Campo $d 'SubjectDomainName') $usuario
        origen     = if ($padre) { $padre } else { '(desconocido)' }
        tipo_logon = $null
        resumen    = $resumen
        log        = 'Security'
        detalle    = [ordered]@{
            proceso         = $proceso
            proceso_padre   = $padre
            linea_comandos  = $cmd
            elevacion       = Get-Campo $d 'TokenElevationType'
        }
    }
}

function ConvertFrom-EventoScript {
    <# 4104: bloque de script de PowerShell. #>
    param($Evento)
    $d = Get-DatosEvento $Evento

    # La cuenta viene como SID en el encabezado del evento; se intenta traducir a nombre.
    $cuenta = '(desconocida)'
    if ($null -ne $Evento.UserId) {
        try   { $cuenta = $Evento.UserId.Translate([System.Security.Principal.NTAccount]).Value }
        catch { $cuenta = $Evento.UserId.Value }
    }

    $ruta   = Get-Campo $d 'Path'
    $texto  = Protect-Texto (Get-Campo $d 'ScriptBlockText')
    $parte  = '{0}/{1}' -f (Get-Campo $d 'MessageNumber'), (Get-Campo $d 'MessageTotal')
    # Nivel 3 = Advertencia: PowerShell lo marcó como sospechoso por su cuenta.
    $sospechoso = ($Evento.Level -eq 3)

    $resumen = if ($sospechoso) { 'PowerShell marcó como SOSPECHOSO un bloque de script' } else { 'Se ejecutó un bloque de script de PowerShell' }
    $resumen += if ($ruta) { " del archivo $(Split-Path -Path $ruta -Leaf)" } else { ' escrito en consola' }
    $resumen += ". Inicio: $texto"

    return [ordered]@{
        hora       = $Evento.TimeCreated.ToString('o')
        id_evento  = 4104
        cuenta     = $cuenta
        origen     = if ($ruta) { $ruta } else { '(consola interactiva)' }
        tipo_logon = $null
        resumen    = $resumen
        log        = 'Microsoft-Windows-PowerShell/Operational'
        detalle    = [ordered]@{
            sospechoso      = $sospechoso
            script_block_id = Get-Campo $d 'ScriptBlockId'
            parte           = $parte
        }
    }
}

function ConvertFrom-EventoBloqueo {
    <# 4740: Windows bloqueó una cuenta por demasiados intentos fallidos (agregado en v0.2.0). #>
    param($Evento)
    $d = Get-DatosEvento $Evento
    $usuario = Get-Campo $d 'TargetUserName'
    # En 4740, TargetDomainName es el "equipo que hizo la llamada" (de dónde vinieron los intentos).
    $llamador = Get-Campo $d 'TargetDomainName'
    $origen = if ($llamador -and $llamador -ne '-') { $llamador } else { 'local' }
    $cuenta = Join-Cuenta $env:COMPUTERNAME $usuario

    return [ordered]@{
        hora       = $Evento.TimeCreated.ToString('o')
        id_evento  = 4740
        cuenta     = $cuenta
        origen     = $origen
        tipo_logon = $null
        resumen    = "La cuenta $cuenta quedó BLOQUEADA por demasiados intentos fallidos. Equipo de origen de los intentos: $origen."
        log        = 'Security'
        detalle    = [ordered]@{
            equipo_llamador = $llamador
            sid             = Get-Campo $d 'TargetSid'
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Programa principal
# ---------------------------------------------------------------------------

$hasta = Get-Date
$desde = $hasta.AddHours(-$Horas)

$fuentes = @(
    [pscustomobject]@{ Id = 4624; Log = 'Security';                                 Normalizar = ${function:ConvertFrom-EventoLogon} },
    [pscustomobject]@{ Id = 4625; Log = 'Security';                                 Normalizar = ${function:ConvertFrom-EventoLogon} },
    [pscustomobject]@{ Id = 4688; Log = 'Security';                                 Normalizar = ${function:ConvertFrom-EventoProceso} },
    [pscustomobject]@{ Id = 4104; Log = 'Microsoft-Windows-PowerShell/Operational'; Normalizar = ${function:ConvertFrom-EventoScript} },
    [pscustomobject]@{ Id = 4740; Log = 'Security';                                 Normalizar = ${function:ConvertFrom-EventoBloqueo} }
)

$eventos     = New-Object System.Collections.Generic.List[object]
$conteo      = [ordered]@{}
$advertencias = New-Object System.Collections.Generic.List[string]

foreach ($f in $fuentes) {
    Write-Host ("Leyendo {0} de {1}..." -f $f.Id, $f.Log)
    # @( ) obligatorio: al salir de una función, PowerShell "desenrolla" el arreglo y, si hay
    # 0 eventos, llega $null (y con StrictMode $null.Count da error). Corregido el 18-oct
    # tras fallar en la VM: ver bitacora-ia.md.
    $crudos = @(Read-Eventos -Log $f.Log -Id $f.Id -Desde $desde -Max $MaxPorId)
    $n = 0
    foreach ($e in $crudos) {
        $obj = & $f.Normalizar $e
        if ($null -ne $obj) { $eventos.Add($obj); $n++ }
    }
    $conteo[[string]$f.Id] = $n

    if ($crudos.Count -ge $MaxPorId) {
        $advertencias.Add("Se alcanzó el máximo de $MaxPorId eventos $($f.Id); puede haber más. Use -MaxPorId o reduzca -Horas.")
    }
    if ($crudos.Count -eq 0) {
        switch ($f.Id) {
            4624 { $advertencias.Add('No hay eventos 4624: es probable que la auditoría de inicios de sesión exitosos esté desactivada.') }
            4625 { $advertencias.Add('No hay eventos 4625: no hubo fallos de inicio de sesión en la ventana, o la auditoría de errores está desactivada.') }
            4688 { $advertencias.Add('No hay eventos 4688: la auditoría de creación de procesos está desactivada (así viene por defecto).') }
            4104 { $advertencias.Add('No hay eventos 4104: el registro de bloques de script de PowerShell no está activado.') }
            4740 { $advertencias.Add('No hay eventos 4740: ninguna cuenta se bloqueó en la ventana, o la auditoría de administración de cuentas de usuario está desactivada.') }
        }
    }
}

# Orden cronológico (las cadenas ISO 8601 con la misma zona se ordenan bien como texto).
$ordenados = @($eventos | Sort-Object { [datetime]$_.hora })

$resultado = [ordered]@{
    metadatos = [ordered]@{
        equipo                    = $env:COMPUTERNAME
        generado                  = $hasta.ToString('o')
        version_script            = $VersionScript
        perfil                    = $Perfil
        ventana_horas             = $Horas
        desde                     = $desde.ToString('o')
        hasta                     = $hasta.ToString('o')
        ids_solicitados           = @(4624, 4625, 4688, 4104, 4740)
        cuentas_sistema_incluidas = [bool]$IncluirCuentasSistema
        total_eventos             = $ordenados.Count
        conteo_por_id             = $conteo
        advertencias              = @($advertencias)
    }
    eventos = $ordenados
}
if ($Nota) { $resultado.metadatos['nota'] = $Nota }

# Ruta de salida por defecto (carpeta ignorada por git para no subir datos sin revisar).
if (-not $Salida) {
    $Salida = Join-Path (Split-Path $PSScriptRoot -Parent) ('datos\salida\eventos_{0}_{1}.json' -f $env:COMPUTERNAME, $hasta.ToString('yyyyMMdd-HHmmss'))
}
$rutaAbs = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Salida)
$carpeta = Split-Path -Path $rutaAbs -Parent
if (-not (Test-Path $carpeta)) { New-Item -ItemType Directory -Path $carpeta -Force | Out-Null }

# -InputObject (no tubería) para que un arreglo de 0 o 1 elementos siga siendo arreglo en el JSON.
$json = ConvertTo-Json -InputObject $resultado -Depth 6
[System.IO.File]::WriteAllText($rutaAbs, $json, (New-Object System.Text.UTF8Encoding $false))

Write-Host ''
Write-Host "Eventos exportados: $($ordenados.Count)" -ForegroundColor Green
$conteo.GetEnumerator() | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Key, $_.Value) }
foreach ($a in $advertencias) { Write-Host "  AVISO: $a" -ForegroundColor Yellow }
Write-Host "Archivo: $rutaAbs" -ForegroundColor Green
