# App web

Abrir `index.html` con doble clic. Todo se procesa en el navegador; ningún dato sale del equipo.

| Archivo | Qué es |
|---|---|
| `index.html` | Las cinco pantallas: Inicio (con la carga), Resumen, Eventos, Exportar y Acerca de. |
| `css/estilos.css` | Estilos. |
| `js/app.js` | Lógica: validación, regla de detección, filtros y exportación (unas 200 líneas comentadas). |
| `js/datos-ejemplo.js` | Copia de `../datos/ejemplo.json` guardada como script para que el botón "Cargar datos de ejemplo" funcione sin servidor. |
| `pruebas/` | JSON vacío, dañado, con otra estructura y con etiquetas HTML. |

## Regla de detección

Por cada cuenta se ordenan sus eventos 4625. Si el fallo número *i* y el fallo número *i + N − 1* ocurren con X minutos o menos de diferencia, hay alerta de fuerza bruta. Las alertas que se solapan se unen en una sola.

## Semáforo

- **Rojo:** al menos una alerta de fuerza bruta.
- **Amarillo:** sin fuerza bruta, pero con cuentas bloqueadas (4740) o scripts que PowerShell marcó como sospechosos (4104).
- **Verde:** ninguna de las anteriores.

## Seguridad

El contenido del JSON se muestra siempre con `textContent`, nunca con `innerHTML`, y la página no se conecta a ningún servidor.
