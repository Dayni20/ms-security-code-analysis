'use strict';

const obtener = id => document.getElementById(id);
const formulario = obtener('formulario');
const archivo = obtener('archivo');
const metodo = obtener('metodo');
const configuraciones = {
  static: { ruta: '/api/v1/analysis/static', descripcion: 'Reglas locales de Semgrep para identificar patrones de riesgo.', espera: 'Semgrep está procesando los archivos. Mantén esta página abierta.' },
  ai: { ruta: '/api/v1/analysis/ai', descripcion: 'Análisis independiente del código mediante Qwen y Ollama local.', espera: 'La IA analiza los archivos de forma secuencial. Puede tardar varios minutos; mantén esta página abierta.' },
  hybrid: { ruta: '/api/v1/analysis/hybrid', descripcion: 'Detección independiente con ambos métodos y correlación de sus hallazgos.', espera: 'Se ejecutan ambos analizadores y se revisa la evidencia local. Puede tardar varios minutos; mantén esta página abierta.' }
};
const etiquetas = {
  COMPLETADO: 'Completado', PARCIAL: 'Parcial', INCOMPLETO: 'Incompleto', ERROR: 'Error',
  ESTATICO: 'Estático', IA: 'IA', AMBOS: 'Ambos', CRITICO: 'Crítico', ALTO: 'Alto', MEDIO: 'Medio', BAJO: 'Bajo',
  RESPALDADO_POR_EVIDENCIA: 'Respaldado por evidencia', DESCARTADO_CON_JUSTIFICACION: 'Descartado con justificación', PENDIENTE_REVISION: 'Pendiente de revisión',
  MISMA_OPERACION: 'Misma operación', SOLO_ESTATICO: 'Solo estático', SOLO_IA: 'Solo IA', AMBIGUA: 'Ambigua', NO_COMPARABLE: 'No comparable',
  ORIGEN: 'Origen', PROPAGACION: 'Propagación', PROTECCION: 'Protección', OPERACION: 'Operación'
};
const clases = { COMPLETADO: 'completado', PARCIAL: 'parcial', INCOMPLETO: 'incompleto', ERROR: 'error', CRITICO: 'critico', ALTO: 'alto', MEDIO: 'medio', BAJO: 'bajo', RESPALDADO_POR_EVIDENCIA: 'respaldado', DESCARTADO_CON_JUSTIFICACION: 'descartado', PENDIENTE_REVISION: 'pendiente' };
const lista = valor => Array.isArray(valor) ? valor : [];
const texto = valor => valor === null || valor === undefined || valor === '' ? 'No disponible' : String(valor);
const etiqueta = valor => Object.hasOwn(etiquetas, valor) ? etiquetas[valor] : texto(valor);
let procesando = false;

function crear(tipo, contenido, clase) {
  const elemento = document.createElement(tipo);
  if (contenido !== undefined) elemento.textContent = texto(contenido);
  if (clase) elemento.className = clase;
  return elemento;
}

function insignia(valor) {
  return crear('span', etiqueta(valor), `insignia ${Object.hasOwn(clases, valor) ? clases[valor] : ''}`);
}

function mostrarAviso(mensaje, error = false) {
  const aviso = obtener('aviso');
  aviso.textContent = mensaje;
  aviso.className = error ? 'aviso error' : 'aviso';
  aviso.hidden = !mensaje;
}

function duracion(milisegundos) {
  const segundos = Math.max(0, Math.floor(milisegundos / 1000));
  return `${String(Math.floor(segundos / 60)).padStart(2, '0')}:${String(segundos % 60).padStart(2, '0')}`;
}

function agregarDato(contenedor, nombre, valor) {
  contenedor.append(crear('dt', nombre), crear('dd', Array.isArray(valor) ? valor.length ? valor.join(', ') : 'Ninguno reportado' : valor));
}

function detallesHallazgo(hallazgo) {
  const detalles = crear('details');
  detalles.append(crear('summary', 'Ver detalles'));
  const datos = crear('dl');
  agregarDato(datos, 'Archivo', hallazgo.rutaRelativa);
  agregarDato(datos, 'Descripción', hallazgo.descripcion);
  agregarDato(datos, 'Línea', hallazgo.linea);
  agregarDato(datos, 'Identificador', hallazgo.identificador || hallazgo.identificadorRegla);
  if (hallazgo.estadoCorrelacion) agregarDato(datos, 'Correlación', etiqueta(hallazgo.estadoCorrelacion));
  if (hallazgo.estadoRevision) agregarDato(datos, 'Revisión', etiqueta(hallazgo.estadoRevision));
  if (hallazgo.justificacion) agregarDato(datos, 'Justificación', hallazgo.justificacion);
  detalles.append(datos);
  if (hallazgo.estadoRevision) {
    detalles.append(crear('strong', 'Evidencia disponible'));
    const evidencia = crear('ul');
    lista(hallazgo.evidencia).forEach(paso => evidencia.append(crear('li', `${etiqueta(paso.tipo)} · líneas ${texto(paso.lineaInicio)}–${texto(paso.lineaFin)}: ${texto(paso.descripcion)}`)));
    if (!evidencia.childElementCount) evidencia.append(crear('li', 'Sin evidencia local registrada.'));
    detalles.append(evidencia);
  }
  if (lista(hallazgo.originales).length) {
    detalles.append(crear('strong', 'Hallazgos originales'), crear('pre', JSON.stringify(hallazgo.originales, null, 2)));
  }
  return detalles;
}

function mostrarHallazgos(hallazgos, completo) {
  const cuerpo = obtener('hallazgos');
  const fragmento = document.createDocumentFragment();
  hallazgos.forEach(hallazgo => {
    const fila = crear('tr');
    const cwe = Array.isArray(hallazgo.cwe) ? hallazgo.cwe.join(', ') : hallazgo.cwe;
    const descripcion = crear('td');
    descripcion.append(crear('div', hallazgo.descripcion, 'descripcion-corta'));
    fila.append(crear('td', cwe), descripcion);
    const ruta = crear('td', hallazgo.rutaRelativa);
    ruta.append(crear('small', `Línea ${texto(hallazgo.linea)}`));
    const riesgo = crear('td');
    riesgo.append(insignia(hallazgo.nivelRiesgo));
    const deteccion = crear('td');
    deteccion.append(insignia(hallazgo.metodoDeteccion));
    const revision = crear('td');
    if (hallazgo.estadoRevision) revision.append(insignia(hallazgo.estadoRevision));
    revision.append(detallesHallazgo(hallazgo));
    fila.append(ruta, riesgo, deteccion, revision);
    fragmento.append(fila);
  });
  cuerpo.replaceChildren(fragmento);
  obtener('sin-hallazgos').hidden = hallazgos.length > 0;
  obtener('sin-hallazgos').textContent = completo
    ? 'No se reportaron hallazgos en los archivos analizados y dentro de la cobertura disponible. Esto no garantiza que el código sea seguro.'
    : 'No hay hallazgos disponibles en este resultado. El procesamiento es incompleto o fallido; no permite concluir que el proyecto esté libre de vulnerabilidades.';
}

function agregarSeccion(titulo, valores) {
  const seccion = crear('section');
  seccion.append(crear('h3', titulo));
  const elementos = crear('ul');
  valores.forEach(valor => elementos.append(crear('li', valor)));
  seccion.append(elementos);
  obtener('informacion').append(seccion);
}

function mostrarInformacion(resultado, metodoElegido) {
  obtener('informacion').replaceChildren();
  obtener('cobertura').replaceChildren();
  const analizadores = metodoElegido === 'hybrid'
    ? [['Semgrep', resultado.estatico], ['IA', resultado.ia]]
    : [[metodoElegido === 'static' ? 'Semgrep' : 'IA', { resultado, estado: resultado.estado }]];
  analizadores.forEach(([nombre, ejecucion]) => {
    if (!ejecucion) return;
    const datos = ejecucion.resultado || {};
    const cobertura = ejecucion.cobertura || datos;
    const cubiertos = lista(cobertura.lenguajesConCobertura || cobertura.lenguajesConReglas);
    const sinCobertura = lista(cobertura.lenguajesSinCobertura || cobertura.lenguajesSinReglas);
    const resumen = cubiertos.length ? cubiertos.join(', ') : 'Cobertura no verificada';
    obtener('cobertura').append(crear('span', `${nombre}: ${resumen}`));
    const valores = [
      `Estado: ${etiqueta(ejecucion.estado || (metodoElegido === 'static' ? 'COMPLETADO' : 'INCOMPLETO'))}`,
      `Lenguajes reconocidos: ${lista(cobertura.lenguajesReconocidos).join(', ') || 'No disponibles'}`,
      `Sin cobertura: ${sinCobertura.join(', ') || 'Ninguno reportado'}`,
      `Archivos analizados: ${lista(cobertura.archivosAnalizados).length}`
    ];
    if (lista(cobertura.lenguajesSinVerificar).length) valores.push(`Sin verificar: ${cobertura.lenguajesSinVerificar.join(', ')}`);
    if (lista(cobertura.archivosNoAnalizados).length) valores.push(`Archivos no analizados: ${cobertura.archivosNoAnalizados.join(', ')}`);
    if (ejecucion.error) valores.push(`Error: ${ejecucion.error}`);
    if (ejecucion.motivo) valores.push(`Motivo: ${ejecucion.motivo}`);
    if (Number.isFinite(ejecucion.tiempoMilisegundos)) valores.push(`Ejecución: ${duracion(ejecucion.tiempoMilisegundos)}`);
    if (datos.versionSemgrep) valores.push(`Versión Semgrep: ${datos.versionSemgrep}`);
    if (datos.huellaReglas) valores.push(`Huella de reglas: ${datos.huellaReglas}`);
    if (datos.modelo) valores.push(`Modelo: ${datos.modelo}`);
    if (datos.digestModelo) valores.push(`Digest del modelo: ${datos.digestModelo}`);
    if (datos.versionPrompt) valores.push(`Versión del prompt: ${datos.versionPrompt}`);
    if (datos.huellaPrompt) valores.push(`Huella del prompt: ${datos.huellaPrompt}`);
    agregarSeccion(nombre, valores);
    if (datos.parametros) {
      const detalle = crear('details');
      detalle.append(crear('summary', `Parámetros de ${nombre}`), crear('pre', JSON.stringify(datos.parametros, null, 2)));
      obtener('informacion').append(detalle);
    }
    const pendientes = lista(datos.fragmentos).filter(fragmento => fragmento.estado !== 'ANALIZADO');
    if (pendientes.length) agregarSeccion('Fragmentos sin análisis completo', pendientes.map(fragmento => `${texto(fragmento.rutaRelativa)} · ${texto(fragmento.estado)} · líneas ${texto(fragmento.lineaInicio)}–${texto(fragmento.lineaFin)} · ${texto(fragmento.descripcion)}`));
    if (lista(datos.limitaciones).length) agregarSeccion(`Limitaciones de ${nombre}`, datos.limitaciones);
  });
  if (lista(resultado.limitaciones).length && metodoElegido === 'hybrid') agregarSeccion('Limitaciones del análisis híbrido', resultado.limitaciones);
  if (lista(resultado.criterios).length) agregarSeccion('Criterios de correlación', resultado.criterios);
  if (resultado.versionCorrelacion) agregarSeccion('Versión de correlación', [resultado.versionCorrelacion]);
  if (resultado.tiempos) agregarSeccion('Tiempos del servidor', Object.entries(resultado.tiempos).map(([nombre, valor]) => `${nombre}: ${typeof valor === 'boolean' ? valor ? 'Sí' : 'No' : `${valor} ms`}`));
}

function mostrarResultado(respuesta, metodoElegido, transcurrido, httpCorrecto) {
  const resultado = respuesta.resultado;
  if (!resultado || typeof resultado !== 'object' || !Array.isArray(resultado.hallazgos)) return false;
  const estado = respuesta.estado || resultado.estado || (httpCorrecto ? 'COMPLETADO' : 'ERROR');
  const completo = httpCorrecto && estado === 'COMPLETADO';
  obtener('estado').replaceChildren(insignia(estado));
  obtener('nombre-proyecto').textContent = texto(respuesta.nombreArchivoZip || archivo.files[0]?.name);
  obtener('total-archivos').textContent = lista(resultado.archivosAnalizados).length;
  obtener('detalle-archivos').textContent = metodoElegido === 'hybrid' ? 'Procesados por al menos un analizador' : 'Completados por el analizador';
  obtener('total-hallazgos').textContent = resultado.hallazgos.length;
  const tiempoServidor = resultado.tiempos?.totalMilisegundos;
  obtener('tiempo-total').textContent = duracion(Number.isFinite(tiempoServidor) ? tiempoServidor : transcurrido);
  obtener('origen-tiempo').textContent = Number.isFinite(tiempoServidor) ? 'Tiempo informado por el servidor' : 'Tiempo de la solicitud en el navegador';
  mostrarHallazgos(resultado.hallazgos, completo);
  mostrarInformacion(resultado, metodoElegido);
  obtener('resultados').hidden = false;
  const sinCobertura = lista(resultado.lenguajesSinReglas).length || lista(resultado.lenguajesSinCobertura).length;
  if (!completo && httpCorrecto) mostrarAviso('Resultado parcial o incompleto. Consulta los errores y la cobertura antes de interpretar los hallazgos.');
  else if (sinCobertura) mostrarAviso('El resultado incluye lenguajes sin cobertura. La ausencia de alertas no permite evaluar esos archivos.');
  return true;
}

metodo.addEventListener('change', () => { obtener('descripcion-metodo').textContent = configuraciones[metodo.value].descripcion; });
metodo.dispatchEvent(new Event('change'));
archivo.addEventListener('change', () => {
  const seleccionado = archivo.files[0];
  obtener('descripcion-archivo').textContent = seleccionado ? `${seleccionado.name} · ${(seleccionado.size / 1048576).toFixed(2)} MB` : 'Archivo ZIP · hasta 100 MB';
});

formulario.addEventListener('submit', async evento => {
  evento.preventDefault();
  if (procesando) return;
  const seleccionado = archivo.files[0];
  if (!seleccionado || !/\.zip$/i.test(seleccionado.name) || seleccionado.size === 0) {
    mostrarAviso('Selecciona un archivo ZIP que no esté vacío.', true);
    return;
  }
  if (seleccionado.size > 104857600) {
    mostrarAviso('El ZIP supera el límite configurado de 100 MB.', true);
    return;
  }
  const metodoElegido = metodo.value;
  const configuracion = configuraciones[metodoElegido];
  procesando = true;
  mostrarAviso('');
  obtener('resultados').hidden = true;
  [archivo, metodo, obtener('iniciar')].forEach(elemento => { elemento.disabled = true; });
  formulario.setAttribute('aria-busy', 'true');
  obtener('procesando').hidden = false;
  obtener('mensaje-espera').textContent = configuracion.espera;
  const inicio = performance.now();
  const actualizarReloj = () => { obtener('cronometro').textContent = duracion(performance.now() - inicio); };
  actualizarReloj();
  const reloj = window.setInterval(actualizarReloj, 1000);
  const datos = new FormData();
  datos.append('file', seleccionado);
  try {
    const respuesta = await fetch(configuracion.ruta, { method: 'POST', body: datos, headers: { Accept: 'application/json' } });
    let contenido;
    try { contenido = await respuesta.json(); }
    catch { throw new Error(`El servidor devolvió una respuesta no interpretable (HTTP ${respuesta.status}). No se puede determinar el resultado del análisis.`); }
    if (!contenido || typeof contenido !== 'object' || Array.isArray(contenido)) throw new Error('El servidor no devolvió un objeto de respuesta válido.');
    const visible = mostrarResultado(contenido, metodoElegido, performance.now() - inicio, respuesta.ok);
    if (!respuesta.ok) {
      mostrarAviso(`HTTP ${respuesta.status} · ${texto(contenido.error || 'El análisis no pudo completarse')}${contenido.motivo ? ` · ${texto(contenido.motivo)}` : ''}${visible ? '. Se muestran los resultados disponibles.' : ''}`, true);
    } else if (!visible) {
      throw new Error('La respuesta del servidor no contiene el resultado esperado. No se puede determinar si existen hallazgos.');
    }
  } catch (error) {
    mostrarAviso(error instanceof TypeError ? 'No se pudo completar la comunicación con el servidor. Comprueba la conexión; no se puede confirmar si el procesamiento terminó.' : error.message, true);
  } finally {
    window.clearInterval(reloj);
    actualizarReloj();
    procesando = false;
    obtener('procesando').hidden = true;
    formulario.setAttribute('aria-busy', 'false');
    [archivo, metodo, obtener('iniciar')].forEach(elemento => { elemento.disabled = false; });
  }
});
