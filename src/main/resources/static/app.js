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
const nombresMetodos = { static: 'Análisis estático', ai: 'Análisis con IA', hybrid: 'Análisis híbrido' };
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
let informeDisponible = null;
let descargando = false;
let validandoZip = false;
let archivoValidado = null;

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
  if (hallazgo.recomendacion) agregarDato(datos, 'Recomendación', hallazgo.recomendacion);
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
    descripcion.append(crear('div', tipoHallazgo(hallazgo.cwe), 'tipo-hallazgo'), crear('div', hallazgo.descripcion, 'descripcion-corta'));
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
  obtener('nombre-proyecto').textContent = `${texto(respuesta.nombreArchivoZip || archivo.files[0]?.name)} · ${nombresMetodos[metodoElegido]}`;
  obtener('total-archivos').textContent = lista(resultado.archivosAnalizados).length;
  obtener('detalle-archivos').textContent = metodoElegido === 'hybrid' ? 'Procesados por al menos un analizador' : 'Completados por el analizador';
  obtener('total-hallazgos').textContent = resultado.hallazgos.length;
  const tiempoServidor = resultado.tiempos?.totalMilisegundos;
  obtener('tiempo-total').textContent = duracion(Number.isFinite(tiempoServidor) ? tiempoServidor : transcurrido);
  obtener('origen-tiempo').textContent = Number.isFinite(tiempoServidor) ? 'Tiempo informado por el servidor' : 'Tiempo de la solicitud en el navegador';
  mostrarHallazgos(resultado.hallazgos, completo);
  mostrarInformacion(resultado, metodoElegido);
  obtener('resultados').hidden = false;
  informeDisponible = {
    metodo: metodoElegido,
    nombreArchivoZip: respuesta.nombreArchivoZip || archivo.files[0]?.name,
    fechaAnalisis: new Date().toISOString(),
    tiempoSolicitudMilisegundos: Math.round(transcurrido),
    respuesta: JSON.parse(JSON.stringify(respuesta))
  };
  obtener('descargar-pdf').hidden = false;
  obtener('estado-descarga').textContent = '';
  const sinCobertura = lista(resultado.lenguajesSinReglas).length || lista(resultado.lenguajesSinCobertura).length;
  if (!completo && httpCorrecto) mostrarAviso('Resultado parcial o incompleto. Consulta los errores y la cobertura antes de interpretar los hallazgos.');
  else if (sinCobertura) mostrarAviso('El resultado incluye lenguajes sin cobertura. La ausencia de alertas no permite evaluar esos archivos.');
  return true;
}

metodo.addEventListener('change', () => { obtener('descripcion-metodo').textContent = configuraciones[metodo.value].descripcion; });
metodo.dispatchEvent(new Event('change'));
archivo.addEventListener('change', () => {
  const seleccionado = archivo.files[0];
  archivoValidado = null;
  obtener('validacion-zip').textContent = '';
  obtener('archivos-cargados').hidden = true;
  obtener('lista-archivos').replaceChildren();
  obtener('descripcion-archivo').textContent = seleccionado ? `${seleccionado.name} · ${(seleccionado.size / 1048576).toFixed(2)} MB` : 'Selecciona un archivo ZIP.';
});

formulario.addEventListener('submit', async evento => {
  evento.preventDefault();
  if (procesando || descargando || validandoZip || evaluacionActiva()) return;
  const seleccionado = archivo.files[0];
  if (!seleccionado || !/\.zip$/i.test(seleccionado.name) || seleccionado.size === 0) {
    mostrarAviso('Selecciona un archivo ZIP que no esté vacío.', true);
    return;
  }
  const metodoElegido = metodo.value;
  const configuracion = configuraciones[metodoElegido];
  procesando = true;
  informeDisponible = null;
  obtener('descargar-pdf').hidden = true;
  obtener('estado-descarga').textContent = '';
  mostrarAviso('');
  obtener('resultados').hidden = true;
  [archivo, metodo, obtener('iniciar')].forEach(elemento => { elemento.disabled = true; });
  formulario.setAttribute('aria-busy', 'true');
  obtener('procesando').hidden = false;
  obtener('mensaje-espera').textContent = 'Verificando el formato y el contenido del ZIP en el servidor.';
  actualizarDisponibilidad();
  let inicio = performance.now();
  const actualizarReloj = () => { obtener('cronometro').textContent = duracion(performance.now() - inicio); };
  actualizarReloj();
  const reloj = window.setInterval(actualizarReloj, 1000);
  const datos = new FormData();
  datos.append('file', seleccionado);
  try {
    await validarZip(seleccionado);
    obtener('mensaje-espera').textContent = configuracion.espera;
    inicio = performance.now();
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
    actualizarDisponibilidad();
  }
});

obtener('descargar-pdf').addEventListener('click', async () => {
  if (!informeDisponible || procesando || descargando) return;
  const boton = obtener('descargar-pdf');
  const solicitud = informeDisponible;
  descargando = true;
  boton.disabled = true;
  obtener('iniciar').disabled = true;
  boton.textContent = 'Generando informe…';
  obtener('estado-descarga').textContent = 'Preparando el PDF con el resultado disponible, sin repetir el análisis.';
  try {
    const respuesta = await fetch('/api/v1/analysis/report/pdf', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/pdf' },
      body: JSON.stringify(solicitud)
    });
    if (!respuesta.ok) {
      let mensaje = `No se pudo generar el informe (HTTP ${respuesta.status}).`;
      try {
        const error = await respuesta.json();
        if (typeof error.error === 'string') mensaje += ` ${error.error}`;
      } catch {}
      throw new Error(mensaje);
    }
    if (!respuesta.headers.get('Content-Type')?.includes('application/pdf')) throw new Error('El servidor no devolvió un archivo PDF válido.');
    const pdf = await respuesta.blob();
    if (!pdf.size || await pdf.slice(0, 5).text() !== '%PDF-') throw new Error('El archivo recibido no es un PDF válido.');
    const direccion = URL.createObjectURL(pdf);
    const enlace = document.createElement('a');
    enlace.href = direccion;
    enlace.download = 'informe-seguridad.pdf';
    document.body.append(enlace);
    enlace.click();
    enlace.remove();
    window.setTimeout(() => URL.revokeObjectURL(direccion), 30000);
    obtener('estado-descarga').textContent = 'Se ha iniciado la descarga del informe PDF.';
  } catch (error) {
    obtener('estado-descarga').textContent = error instanceof TypeError ? 'No se pudo descargar el PDF. Comprueba la conexión y vuelve a intentarlo.' : error.message;
  } finally {
    descargando = false;
    boton.disabled = false;
    actualizarDisponibilidad();
    boton.textContent = '↓ Descargar informe PDF';
  }
});


function tipoHallazgo(cwe) {
  const tipos = { 'CWE-89': 'Posible inyección SQL', 'CWE-78': 'Posible inyección de comandos',
    'CWE-22': 'Posible recorrido de rutas', 'CWE-23': 'Posible recorrido relativo de rutas', 'CWE-36': 'Posible recorrido absoluto de rutas' };
  return lista(Array.isArray(cwe) ? cwe : [cwe]).map(valor => tipos[valor] || 'Indicio de seguridad').join(' · ');
}

async function solicitarJson(ruta, opciones = {}) {
  const respuesta = await fetch(ruta, { ...opciones, headers: { Accept: 'application/json', ...opciones.headers } });
  let contenido;
  try { contenido = await respuesta.json(); }
  catch { throw new Error(`Respuesta no interpretable del servidor (HTTP ${respuesta.status}).`); }
  if (!respuesta.ok) {
    const error = new Error(`HTTP ${respuesta.status} · ${texto(contenido?.error || 'No se pudo completar la solicitud')}`);
    error.estadoHTTP = respuesta.status;
    throw error;
  }
  if (!contenido || typeof contenido !== 'object' || Array.isArray(contenido)) throw new Error('La respuesta no tiene la estructura esperada.');
  return contenido;
}

async function validarZip(seleccionado) {
  if (archivoValidado === seleccionado) return;
  const datos = new FormData();
  datos.append('file', seleccionado);
  obtener('validacion-zip').textContent = 'Validando el ZIP en el servidor…';
  const respuesta = await solicitarJson('/api/v1/analysis/upload', { method: 'POST', body: datos });
  if (!Number.isInteger(respuesta.cantidadArchivosFuente) || !Array.isArray(respuesta.archivos)) {
    throw new Error('La respuesta de validación no contiene la lista de archivos esperada.');
  }
  const java = respuesta.archivos.filter(fuente => fuente.lenguaje === 'Java').length;
  obtener('validacion-zip').textContent = `${texto(respuesta.nombreArchivoZip)} · ${respuesta.cantidadArchivosFuente} archivos fuente identificados; ${java} archivos Java.`;
  obtener('lista-archivos').replaceChildren(...respuesta.archivos.map(fuente => crear('li', `${texto(fuente.rutaRelativa)} · ${texto(fuente.lenguaje)}`)));
  obtener('archivos-cargados').hidden = false;
  archivoValidado = seleccionado;
}

obtener('validar-zip').addEventListener('click', async () => {
  const seleccionado = archivo.files[0];
  if (!seleccionado) { mostrarAviso('Selecciona un ZIP para validar.', true); return; }
  validandoZip = true;
  actualizarDisponibilidad();
  mostrarAviso('');
  try { await validarZip(seleccionado); }
  catch (error) {
    obtener('validacion-zip').textContent = 'No se pudo validar el proyecto.';
    mostrarAviso(mensajeError(error), true);
  } finally { validandoZip = false; actualizarDisponibilidad(); }
});

const estadosEvaluacion = {
  PENDIENTE: ['Pendiente', 'pendiente'], EN_PROCESO: ['En proceso', 'parcial'],
  COMPLETADA: ['Completada', 'completado'], COMPLETADA_CON_ERRORES: ['Completada con errores', 'parcial'],
  FALLIDA: ['Fallida', 'error'], INTERRUMPIDA: ['Interrumpida', 'incompleto']
};
const nombresEvaluacion = { ESTATICO: 'Semgrep', IA: 'Inteligencia artificial', HIBRIDO: 'Análisis híbrido' };
const nombresClasificacion = { VP: 'VP · Verdadero positivo', VN: 'VN · Verdadero negativo', FP: 'FP · Falso positivo',
  FN: 'FN · Falso negativo', NO_EVALUABLE: 'No evaluable' };
const claveEvaluacion = 'securityCodeAnalysis.evaluacionId';
const formatoDecimal = new Intl.NumberFormat('es', { maximumFractionDigits: 2 });
let resumenEvaluacion = null;
let detallesEvaluacion = [];
let temporizadorEvaluacion = null;
let controladorConsulta = null;
let generacionConsulta = 0;
let iniciandoEvaluacion = false;
let descargandoCsv = false;
let detallesActualizados = null;

function mensajeError(error) {
  return error instanceof TypeError ? 'Sin conexión con el servidor.' : error.message;
}

function abrirSeccion(nombre) {
  for (const seccion of ['analisis', 'evaluacion']) {
    const activa = nombre === seccion;
    obtener(`seccion-${seccion}`).hidden = !activa;
    if (activa) obtener(`nav-${seccion}`).setAttribute('aria-current', 'page');
    else obtener(`nav-${seccion}`).removeAttribute('aria-current');
  }
}

obtener('nav-analisis').addEventListener('click', () => abrirSeccion('analisis'));
obtener('nav-evaluacion').addEventListener('click', () => abrirSeccion('evaluacion'));

function evaluacionActiva() {
  return resumenEvaluacion && ['PENDIENTE', 'EN_PROCESO'].includes(resumenEvaluacion.estado);
}

function evaluacionFinalizada() {
  return resumenEvaluacion && ['COMPLETADA', 'COMPLETADA_CON_ERRORES', 'FALLIDA', 'INTERRUMPIDA'].includes(resumenEvaluacion.estado);
}

function actualizarDisponibilidad() {
  const ocupado = procesando || descargando || validandoZip || iniciandoEvaluacion || Boolean(evaluacionActiva());
  [archivo, metodo, obtener('iniciar'), obtener('validar-zip')].forEach(elemento => { elemento.disabled = ocupado; });
  obtener('iniciar-evaluacion').disabled = ocupado;
  obtener('seleccion-casos').disabled = iniciandoEvaluacion || Boolean(evaluacionActiva());
  obtener('identificadores').disabled = iniciandoEvaluacion || Boolean(evaluacionActiva());
  obtener('descargar-csv').disabled = descargandoCsv || !evaluacionFinalizada();
}

function avisoEvaluacion(mensaje, error = false) {
  const aviso = obtener('aviso-evaluacion');
  aviso.textContent = mensaje;
  aviso.className = error ? 'aviso error' : 'aviso';
  aviso.hidden = !mensaje;
}

function numeroDisponible(valor) {
  return Number.isFinite(valor) ? formatoDecimal.format(valor) : 'N/A';
}

function porcentaje(valor) {
  return Number.isFinite(valor) && valor >= 0 && valor <= 100 ? `${formatoDecimal.format(valor)} %` : 'N/A';
}

function metricaDisponible(valor) {
  return Number.isFinite(valor) && valor >= 0 && valor <= 1;
}

function porcentajeMetrica(valor) {
  return metricaDisponible(valor) ? porcentaje(valor * 100) : 'N/A';
}

function guardarIdentificador(id) {
  obtener('identificador-evaluacion').value = id;
  try { localStorage.setItem(claveEvaluacion, id); }
  catch { avisoEvaluacion('El navegador no permite guardar el identificador. Cópialo para recuperar esta evaluación.'); }
}

function mostrarResumenEvaluacion(resumen) {
  if (!resumen.identificador || !Object.hasOwn(estadosEvaluacion, resumen.estado)) throw new Error('El servidor no devolvió un estado de evaluación reconocido.');
  resumenEvaluacion = resumen;
  obtener('resultado-evaluacion').hidden = false;
  obtener('id-ejecucion').textContent = resumen.identificador;
  const [nombreEstado, clase] = estadosEvaluacion[resumen.estado];
  obtener('estado-evaluacion').replaceChildren(crear('span', nombreEstado, `insignia ${clase}`));
  const cantidades = { solicitados: 'casosSolicitados', procesados: 'casosProcesados', exitosos: 'casosExitosos', fallidos: 'casosFallidos', excluidos: 'casosExcluidosComparacion' };
  Object.entries(cantidades).forEach(([id, campo]) => { obtener(`eval-${id}`).textContent = numeroDisponible(resumen[campo]); });
  obtener('eval-cobertura').textContent = porcentaje(resumen.coberturaExperimental);
  obtener('eval-tiempo').textContent = Number.isFinite(resumen.duracionMilisegundos) ? duracion(resumen.duracionMilisegundos) : 'N/A';
  obtener('porcentaje-evaluacion').textContent = porcentaje(resumen.porcentajeAvance);
  if (porcentaje(resumen.porcentajeAvance) === 'N/A') obtener('progreso-evaluacion').removeAttribute('value');
  else obtener('progreso-evaluacion').value = resumen.porcentajeAvance;
  obtener('actualizacion-evaluacion').textContent = `Última consulta: ${new Date().toLocaleTimeString('es')}. ${evaluacionActiva() ? 'Consulta automática cada cinco segundos; puedes recargar y recuperar la ejecución.' : 'La ejecución finalizó. Las consultas automáticas se han detenido.'}`;
  mostrarMetricas();
  mostrarTrazabilidad(resumen);
  actualizarDisponibilidad();
}

function mostrarTrazabilidad(resumen) {
  const contenedor = obtener('trazabilidad-evaluacion');
  const datos = crear('dl');
  agregarDato(datos, 'Inicio', fechaLegible(resumen.fechaInicio));
  agregarDato(datos, 'Finalización', fechaLegible(resumen.fechaFinalizacion));
  agregarDato(datos, 'Casos seleccionados', lista(resumen.identificadoresSeleccionados));
  agregarDato(datos, 'Casos fuera de la comparación principal en este estado', lista(resumen.identificadoresExcluidosComparacion));
  if (resumen.error) agregarDato(datos, 'Error de la ejecución', resumen.error);
  Object.entries(resumen.reproducibilidad || {}).forEach(([nombre, valor]) => agregarDato(datos, nombre, valor));
  contenedor.replaceChildren(datos);
}

function fechaLegible(valor) {
  if (!valor) return 'No disponible';
  const fecha = new Date(valor);
  return Number.isNaN(fecha.getTime()) ? texto(valor) : fecha.toLocaleString('es');
}

function mostrarMetricas() {
  const categoria = obtener('categoria-metricas').value;
  const cuerpo = obtener('metricas');
  const grafica = obtener('grafica-metricas');
  cuerpo.replaceChildren();
  grafica.replaceChildren();
  for (const [metodo, nombre] of Object.entries(nombresEvaluacion)) {
    const metricas = resumenEvaluacion?.comparacionPrincipal?.[metodo]?.[categoria] || {};
    const fila = crear('tr');
    fila.append(crear('th', nombre));
    fila.firstChild.scope = 'row';
    for (const campo of ['total', 'verdaderosPositivos', 'verdaderosNegativos', 'falsosPositivos', 'falsosNegativos']) fila.append(crear('td', numeroDisponible(metricas[campo])));
    for (const campo of ['precision', 'recall', 'f1']) fila.append(crear('td', porcentajeMetrica(metricas[campo])));
    cuerpo.append(fila);
    const grupo = crear('div', undefined, 'grupo-barras');
    grupo.append(crear('strong', nombre));
    const barras = crear('div', undefined, 'serie-barras');
    for (const [campo, etiquetaMetrica] of [['precision', 'Precisión'], ['recall', 'Recall'], ['f1', 'F1-score']]) {
      const valor = metricas[campo];
      if (!metricaDisponible(valor)) { barras.append(crear('p', `${etiquetaMetrica}: N/A`, 'metrica-no-disponible')); continue; }
      const filaBarra = crear('div', undefined, 'fila-barra');
      const barra = crear('span', undefined, `barra ${campo}`);
      barra.style.width = `${valor * 100}%`;
      barra.setAttribute('aria-hidden', 'true');
      filaBarra.append(barra, crear('span', `${etiquetaMetrica}: ${porcentajeMetrica(valor)}`, 'valor-barra'));
      barras.append(filaBarra);
    }
    grupo.append(barras);
    grafica.append(grupo);
  }
}

obtener('categoria-metricas').addEventListener('change', mostrarMetricas);

function mostrarCasosExperimentales() {
  const cuerpo = obtener('casos-experimentales');
  cuerpo.replaceChildren();
  const excluidos = new Set(lista(resumenEvaluacion?.identificadoresExcluidosComparacion));
  for (const resultado of detallesEvaluacion) {
    const caso = resultado.caso || {};
    const fila = crear('tr');
    fila.append(crear('td', caso.identificador), crear('td', `${texto(caso.cweOriginal)} / ${texto(caso.cweNormalizado)}`),
      crear('td', caso.clasificacionEsperada === 'SEGURO' ? 'Seguro' : caso.clasificacionEsperada === 'VULNERABLE' ? 'Vulnerable' : 'N/A'));
    for (const metodo of Object.keys(nombresEvaluacion)) {
      const datos = resultado.clasificaciones?.[metodo];
      const celda = crear('td');
      const clasificacion = datos?.clasificacion;
      const clase = clasificacion === 'NO_EVALUABLE' ? 'no-evaluable' : ['VP', 'VN', 'FP', 'FN'].includes(clasificacion) ? clasificacion.toLowerCase() : '';
      celda.append(crear('span', nombresClasificacion[clasificacion] || 'N/A', `insignia ${clase}`));
      if (Number.isFinite(datos?.tiempoMilisegundos)) celda.append(crear('small', duracion(datos.tiempoMilisegundos)));
      fila.append(celda);
    }
    const detalle = crear('td');
    detalle.append(crear('span', excluidos.has(caso.identificador) ? 'Excluido de la comparación' : 'Incluido en la comparación', `insignia ${excluidos.has(caso.identificador) ? 'pendiente' : 'completado'}`));
    detalle.append(detallesCasoExperimental(resultado));
    fila.append(detalle);
    cuerpo.append(fila);
  }
  obtener('estado-detalles').textContent = detallesEvaluacion.length
    ? `${detallesEvaluacion.length} resultados individuales disponibles. VP: verdadero positivo · VN: verdadero negativo · FP: falso positivo · FN: falso negativo.`
    : 'Todavía no hay casos procesados. La ausencia de resultados no significa que el código sea seguro.';
}

function detallesCasoExperimental(resultado) {
  const detalle = crear('details');
  detalle.append(crear('summary', 'Tiempos, hallazgos y errores'));
  const datos = crear('dl');
  if (resultado.falloTecnico) agregarDato(datos, 'Fallo técnico', resultado.falloTecnico);
  agregarDato(datos, 'Tiempo del caso', Number.isFinite(resultado.tiempoMilisegundos) ? duracion(resultado.tiempoMilisegundos) : 'N/A');
  for (const [metodo, nombre] of Object.entries(nombresEvaluacion)) {
    const clasificacion = resultado.clasificaciones?.[metodo];
    if (clasificacion?.motivo) agregarDato(datos, nombre, clasificacion.motivo);
  }
  detalle.append(datos);
  if (resultado.resultadosOriginales) {
    const originales = crear('details');
    originales.append(crear('summary', 'Resultados originales y trazabilidad'), crear('pre', JSON.stringify(resultado.resultadosOriginales, null, 2)));
    detalle.append(originales);
  }
  return detalle;
}

function detenerConsultas() {
  window.clearTimeout(temporizadorEvaluacion);
  temporizadorEvaluacion = null;
  controladorConsulta?.abort();
  controladorConsulta = null;
  generacionConsulta += 1;
}

function validarIdentificadorEjecucion(id) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

async function consultarEvaluacion(id, generacion) {
  const controlador = new AbortController();
  controladorConsulta = controlador;
  const limite = window.setTimeout(() => controlador.abort(), 30000);
  let continuar = true;
  try {
    const resumen = await solicitarJson(`/api/v1/evaluation/${encodeURIComponent(id)}`, { signal: controlador.signal });
    if (generacion !== generacionConsulta) return;
    if (resumen.identificador !== id) throw new Error('El identificador de la respuesta no coincide con la ejecución consultada.');
    mostrarResumenEvaluacion(resumen);
    avisoEvaluacion(resumen.error || (evaluacionActiva() ? 'Evaluación en curso.' : ''));
    guardarIdentificador(id);
    continuar = Boolean(evaluacionActiva());
    const versionDetalle = `${id}:${resumen.casosProcesados}:${resumen.estado}`;
    if (detallesActualizados !== versionDetalle) {
      const detalle = await solicitarJson(`/api/v1/evaluation/${encodeURIComponent(id)}/results`, { signal: controlador.signal });
      if (generacion !== generacionConsulta) return;
      if (!Array.isArray(detalle.resultados)) throw new Error('El servidor no devolvió los resultados individuales esperados.');
      detallesEvaluacion = detalle.resultados;
      detallesActualizados = versionDetalle;
    }
    mostrarCasosExperimentales();
  } catch (error) {
    if (generacion !== generacionConsulta) return;
    continuar = ![400, 404].includes(error.estadoHTTP) && !evaluacionFinalizada();
    const mensaje = error.name === 'AbortError' ? 'Se agotó el tiempo de consulta. Esto no cancela la evaluación del servidor.' : mensajeError(error);
    avisoEvaluacion(`${mensaje}${continuar ? ' Reintentando en 5 segundos.' : ' Puedes consultar nuevamente con el identificador.'}`, true);
  } finally {
    window.clearTimeout(limite);
    if (generacion === generacionConsulta) {
      controladorConsulta = null;
      obtener('recuperar-evaluacion').disabled = false;
      actualizarDisponibilidad();
      if (continuar) temporizadorEvaluacion = window.setTimeout(() => consultarEvaluacion(id, generacion), 5000);
    }
  }
}

function recuperarEvaluacion(id) {
  detenerConsultas();
  resumenEvaluacion = null;
  detallesEvaluacion = [];
  detallesActualizados = null;
  obtener('resultado-evaluacion').hidden = true;
  obtener('estado-csv').textContent = '';
  obtener('recuperar-evaluacion').disabled = true;
  avisoEvaluacion('Consultando la evaluación…');
  actualizarDisponibilidad();
  consultarEvaluacion(id, generacionConsulta);
}

obtener('formulario-recuperar').addEventListener('submit', evento => {
  evento.preventDefault();
  const id = obtener('identificador-evaluacion').value.trim().toLowerCase();
  if (!validarIdentificadorEjecucion(id)) { avisoEvaluacion('Introduce un identificador de ejecución UUID válido.', true); return; }
  recuperarEvaluacion(id);
});

obtener('seleccion-casos').addEventListener('change', () => {
  const seleccion = obtener('seleccion-casos').value === 'seleccion';
  obtener('campo-identificadores').hidden = !seleccion;
  obtener('identificadores').required = seleccion;
});

obtener('formulario-evaluacion').addEventListener('submit', async evento => {
  evento.preventDefault();
  if (iniciandoEvaluacion || evaluacionActiva() || procesando || validandoZip || descargando) return;
  const seleccion = obtener('seleccion-casos').value === 'seleccion';
  const identificadores = seleccion ? obtener('identificadores').value.trim().split(/[\s,;]+/).filter(Boolean) : [];
  if (seleccion && !identificadores.length) { avisoEvaluacion('Escribe al menos un identificador de caso.', true); return; }
  iniciandoEvaluacion = true;
  actualizarDisponibilidad();
  avisoEvaluacion('Solicitando el inicio de la evaluación. El servidor validará los casos seleccionados.');
  try {
    const resumen = await solicitarJson('/api/v1/evaluation/run', { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(seleccion ? { identificadores } : {}) });
    if (!validarIdentificadorEjecucion(resumen.identificador || '')) throw new Error('La respuesta de inicio no contiene un identificador válido.');
    detenerConsultas();
    detallesEvaluacion = [];
    detallesActualizados = null;
    mostrarResumenEvaluacion(resumen);
    mostrarCasosExperimentales();
    guardarIdentificador(resumen.identificador);
    obtener('estado-csv').textContent = '';
    consultarEvaluacion(resumen.identificador, generacionConsulta);
  } catch (error) {
    avisoEvaluacion(`${mensajeError(error)}${error instanceof TypeError ? ' No se repetirá automáticamente la solicitud de inicio.' : ''}`, true);
  } finally { iniciandoEvaluacion = false; actualizarDisponibilidad(); }
});

function descargarArchivo(contenido, nombre) {
  const direccion = URL.createObjectURL(contenido);
  const enlace = crear('a');
  enlace.href = direccion;
  enlace.download = nombre;
  document.body.append(enlace);
  enlace.click();
  enlace.remove();
  window.setTimeout(() => URL.revokeObjectURL(direccion), 30000);
}

obtener('descargar-csv').addEventListener('click', async () => {
  if (!evaluacionFinalizada() || descargandoCsv) return;
  const id = resumenEvaluacion.identificador;
  descargandoCsv = true;
  actualizarDisponibilidad();
  obtener('estado-csv').textContent = 'Preparando la descarga…';
  try {
    const respuesta = await fetch(`/api/v1/evaluation/${encodeURIComponent(id)}/export`, { headers: { Accept: 'text/csv' } });
    if (!respuesta.ok) {
      let mensaje = `No se pudo descargar el CSV (HTTP ${respuesta.status}).`;
      try { const error = await respuesta.json(); if (error.error) mensaje += ` ${texto(error.error)}`; } catch {}
      throw new Error(mensaje);
    }
    if (!respuesta.headers.get('Content-Type')?.includes('text/csv')) throw new Error('El servidor no devolvió un archivo CSV válido.');
    const csv = await respuesta.blob();
    if (!csv.size) throw new Error('El archivo CSV recibido está vacío.');
    descargarArchivo(csv, `evaluacion-${id}.csv`);
    obtener('estado-csv').textContent = `Se inició la descarga del CSV de la evaluación ${id}.`;
  } catch (error) { obtener('estado-csv').textContent = mensajeError(error); }
  finally { descargandoCsv = false; actualizarDisponibilidad(); }
});

function restaurarEvaluacion() {
  actualizarDisponibilidad();
  let id;
  try { id = localStorage.getItem(claveEvaluacion); } catch { return; }
  if (id && validarIdentificadorEjecucion(id)) {
    abrirSeccion('evaluacion');
    obtener('identificador-evaluacion').value = id;
    recuperarEvaluacion(id);
  }
}

restaurarEvaluacion();
