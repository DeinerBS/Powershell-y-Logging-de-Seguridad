// app.js - Visor de eventos de seguridad (ISW-612, Tema 4)
// Escrito con ayuda de IA (Claude) y revisado por el equipo: ver bitacora-ia.md.
// Seguridad: todo lo que viene del JSON se muestra con textContent (nunca innerHTML)
// y la página no se conecta a ningún servidor.

// Explicación simple y recomendación de cada tipo de evento
const EVENTOS = {
  4624: ['Inicio de sesión exitoso', 'Alguien entró al equipo con la contraseña correcta.', 'Revisar si ocurre justo después de muchos fallos.'],
  4625: ['Inicio de sesión fallido', 'Alguien intentó entrar y falló. Muchos fallos seguidos son señal de fuerza bruta.', 'Confirmar con el dueño de la cuenta si fue un error suyo.'],
  4740: ['Cuenta bloqueada', 'Windows bloqueó la cuenta por demasiadas contraseñas incorrectas.', 'Cambiar la contraseña si el dueño no reconoce los intentos.'],
  4688: ['Programa ejecutado', 'Se abrió un programa. Permite saber qué se ejecutó y con qué parámetros.', 'Revisar programas desconocidos o lanzados desde PowerShell.'],
  4104: ['Script de PowerShell', 'Se ejecutó código de PowerShell y quedó guardado su contenido.', 'Revisar los scripts marcados como sospechosos.']
};
const CAMPOS = ['hora', 'id_evento', 'cuenta', 'origen', 'tipo_logon', 'resumen'];

let datos = null;      // JSON cargado
let eventos = [];      // eventos válidos ordenados por hora
let alertas = [];      // alertas de fuerza bruta
let enAlerta = new Set();

const $ = id => document.getElementById(id);
function nuevo(etiqueta, texto) {
  const n = document.createElement(etiqueta);
  if (texto !== undefined) n.textContent = texto;
  return n;
}
const horaTexto = e => e.hora.slice(0, 10) + ' ' + e.hora.slice(11, 19);

// ---------- Navegación ----------
document.querySelectorAll('nav button').forEach(b => b.onclick = () => mostrar(b.dataset.pantalla));
function mostrar(id) {
  document.querySelectorAll('section').forEach(s => s.classList.toggle('activa', s.id === id));
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('activo', b.dataset.pantalla === id));
}

// ---------- Carga y validación ----------
$('archivo').onchange = () => {
  const f = $('archivo').files[0];
  if (!f) return;
  const lector = new FileReader();
  lector.onload = () => {
    try {
      cargar(JSON.parse(lector.result), f.name);
    } catch (err) {
      error('El archivo no es un JSON válido o está dañado.');
    }
  };
  lector.readAsText(f);
};
$('btn-ejemplo').onclick = () => cargar(window.DATOS_EJEMPLO, 'datos de ejemplo');

function error(texto) {
  $('mensaje').className = 'error';
  $('mensaje').textContent = texto;
}

function cargar(obj, nombre) {
  if (!obj || !Array.isArray(obj.eventos)) return error('El archivo no tiene la lista "eventos". ¿Lo generó Recolectar-Eventos.ps1?');
  // Solo se aceptan eventos con los seis campos mínimos y una hora válida
  const validos = obj.eventos.filter(e => e && CAMPOS.every(c => c in e) && !isNaN(Date.parse(e.hora)));
  if (validos.length === 0) return error('El archivo no tiene eventos válidos.');

  datos = obj;
  eventos = validos.map(e => Object.assign({ t: Date.parse(e.hora) }, e)).sort((a, b) => a.t - b.t);
  const descartados = obj.eventos.length - validos.length;
  $('mensaje').className = 'ok';
  $('mensaje').textContent = `Se cargaron ${eventos.length} eventos de "${nombre}"` + (descartados ? ` (${descartados} incompletos se ignoraron).` : '.');

  document.querySelectorAll('nav button').forEach(b => b.disabled = false);
  llenarFiltros();
  analizar();
  mostrar('resumen');
}

// ---------- Regla de detección: N fallos (4625) de una cuenta en X minutos ----------
function analizar() {
  const n = Math.max(2, Number($('regla-n').value) || 5);
  const ventana = Math.max(1, Number($('regla-min').value) || 2) * 60000;
  alertas = [];
  enAlerta = new Set();

  // Agrupar los fallos por cuenta
  const porCuenta = {};
  eventos.forEach(e => { if (e.id_evento === 4625) (porCuenta[e.cuenta] = porCuenta[e.cuenta] || []).push(e); });

  for (const cuenta in porCuenta) {
    const f = porCuenta[cuenta];
    let actual = null;
    for (let i = 0; i + n - 1 < f.length; i++) {
      // ¿El fallo i y el fallo i+n-1 están dentro de la ventana?
      if (f[i + n - 1].t - f[i].t <= ventana) {
        const grupo = f.slice(i, i + n);
        if (actual && f[i].t <= actual.fin.t) {
          grupo.forEach(e => actual.eventos.add(e));           // se une a la alerta anterior
          actual.fin = f[i + n - 1];
        } else {
          actual = { cuenta, eventos: new Set(grupo), inicio: f[i], fin: f[i + n - 1] };
          alertas.push(actual);
        }
      }
    }
  }
  alertas.forEach(a => a.eventos.forEach(e => enAlerta.add(e)));
  pintarResumen(n, ventana / 60000);
  pintarTabla();
}
$('regla-n').oninput = $('regla-min').oninput = () => eventos.length && analizar();

// ---------- Resumen ----------
function pintarResumen(n, minutos) {
  const contar = id => eventos.filter(e => e.id_evento === id).length;
  const sospechosos = eventos.filter(e => e.id_evento === 4104 && e.detalle && e.detalle.sospechoso);
  const bloqueos = eventos.filter(e => e.id_evento === 4740);

  // Semáforo
  let color, texto;
  if (alertas.length) { color = 'rojo'; texto = `ROJO - Riesgo alto: ${alertas.length} posible(s) ataque(s) de fuerza bruta.`; }
  else if (bloqueos.length || sospechosos.length) { color = 'amarillo'; texto = 'AMARILLO - Riesgo medio: hay cuentas bloqueadas o scripts sospechosos.'; }
  else { color = 'verde'; texto = 'VERDE - Sin señales de ataque con la regla actual.'; }
  $('semaforo').className = color;
  $('semaforo').textContent = texto;

  $('cifras').textContent = `${eventos.length} eventos: ${contar(4625)} fallos de inicio de sesión, ${contar(4740)} bloqueos, ` +
    `${contar(4688)} programas ejecutados y ${contar(4104)} scripts. Regla: ${n} fallos en ${minutos} min.`;

  // Hallazgos principales (máximo tres, los más graves primero)
  const hallazgos = [];
  alertas.forEach(a => {
    const lista = [...a.eventos];
    const trasBloqueo = lista.filter(e => e.detalle && e.detalle.codigo === '0xc0000234').length;
    let t = `Posible fuerza bruta contra ${a.cuenta}: ${lista.length} intentos fallidos entre ${horaTexto(a.inicio)} y ${a.fin.hora.slice(11, 19)}.`;
    if (trasBloqueo) t += ` ${trasBloqueo} llegaron con la cuenta ya bloqueada.`;
    hallazgos.push(t + ' (MITRE ATT&CK T1110)');
  });
  if (bloqueos.length) hallazgos.push(`Windows bloqueó cuentas ${bloqueos.length === 1 ? '1 vez' : bloqueos.length + ' veces'}: ${bloqueos.map(b => b.cuenta + ' a las ' + b.hora.slice(11, 19)).join(', ')}.`);
  if (sospechosos.length) hallazgos.push(`PowerShell marcó ${sospechosos.length} script(s) como sospechosos (MITRE ATT&CK T1059.001).`);
  if (!hallazgos.length) hallazgos.push('No se encontraron hallazgos con la regla actual.');
  $('hallazgos').replaceChildren(...hallazgos.slice(0, 3).map(h => nuevo('li', h)));

  // Recomendaciones concretas
  const rec = [];
  if (alertas.length) rec.push('Confirmar con el dueño de la cuenta si reconoce los intentos; si no, cambiar la contraseña.');
  if (alertas.length) rec.push('Mantener la política de bloqueo de cuentas y la auditoría de "Bloqueo de cuenta" con errores.');
  if (sospechosos.length) rec.push('Revisar quién ejecutó los scripts sospechosos y para qué.');
  if (!contar(4688)) rec.push('Activar la auditoría de creación de procesos (evento 4688).');
  if (!contar(4104)) rec.push('Activar el registro de scripts de PowerShell (evento 4104).');
  if (!rec.length) rec.push('No se requiere acción; seguir revisando los eventos de forma periódica.');
  $('recomendaciones').replaceChildren(...rec.map(r => nuevo('li', r)));
}

// ---------- Eventos: filtros, tabla y detalle ----------
function llenarFiltros() {
  const opciones = (id, campo, todos) => {
    const valores = [...new Set(eventos.map(e => String(e[campo])))].sort();
    const sel = $(id);
    sel.replaceChildren(nuevo('option', todos));
    sel.firstChild.value = '';
    valores.forEach(v => { const o = nuevo('option', v); o.value = v; sel.append(o); });
  };
  opciones('f-id', 'id_evento', 'Todos los eventos');
  opciones('f-cuenta', 'cuenta', 'Todas las cuentas');
  opciones('f-origen', 'origen', 'Todos los orígenes');
  $('detalle').style.display = 'none';
}
$('f-id').onchange = $('f-cuenta').onchange = $('f-origen').onchange = () => pintarTabla();

function pintarTabla() {
  const filtro = { id_evento: $('f-id').value, cuenta: $('f-cuenta').value, origen: $('f-origen').value };
  const lista = eventos.filter(e => Object.keys(filtro).every(k => !filtro[k] || String(e[k]) === filtro[k]));
  $('conteo').textContent = `${lista.length} eventos (las filas amarillas forman parte de una alerta). Haga clic en una fila para ver qué significa.`;
  $('tabla').replaceChildren(...lista.map(e => {
    const tr = nuevo('tr');
    if (enAlerta.has(e)) tr.className = 'alerta';
    [horaTexto(e), e.id_evento, e.cuenta, e.origen, e.resumen].forEach(v => tr.append(nuevo('td', String(v))));
    tr.onclick = () => verDetalle(e);
    return tr;
  }));
}

function verDetalle(e) {
  const info = EVENTOS[e.id_evento] || ['Evento ' + e.id_evento, 'Evento sin explicación en esta página.', '-'];
  const d = $('detalle');
  d.replaceChildren(
    nuevo('b', `${e.id_evento} - ${info[0]}`),
    nuevo('p', info[1]),
    nuevo('p', 'Recomendación: ' + info[2]),
    nuevo('p', `Detalle técnico: ${horaTexto(e)} | cuenta ${e.cuenta} | origen ${e.origen}` + (e.detalle && e.detalle.motivo ? ` | motivo: ${e.detalle.motivo}` : ''))
  );
  d.style.display = 'block';
  d.scrollIntoView({ behavior: 'smooth' });
}

// ---------- Exportar ----------
$('btn-json').onclick = () => {
  const resultado = {
    equipo: datos.metadatos ? datos.metadatos.equipo : null,
    fecha_analisis: new Date().toISOString(),
    regla: { fallos: Number($('regla-n').value), minutos: Number($('regla-min').value) },
    riesgo: $('semaforo').textContent,
    alertas: alertas.map(a => ({ cuenta: a.cuenta, intentos: a.eventos.size, desde: a.inicio.hora, hasta: a.fin.hora }))
  };
  const enlace = nuevo('a');
  enlace.href = URL.createObjectURL(new Blob([JSON.stringify(resultado, null, 2)], { type: 'application/json' }));
  enlace.download = 'resultado-analisis.json';
  enlace.click();
};
$('btn-imprimir').onclick = () => window.print();

// ---------- Glosario de Acerca de ----------
$('glosario').replaceChildren(...Object.keys(EVENTOS).map(id => nuevo('li', `${id} - ${EVENTOS[id][0]}: ${EVENTOS[id][1]}`)));
