from pathlib import Path
import collections,hashlib,json,re,random,subprocess,zipfile
import sys
sys.dont_write_bytecode = True
from entorno_juliet import RAIZ, TRABAJO, iniciar, herramienta_java

iniciar()
BASE=Path('dataset/juliet-java-1.3')
SALIDA=Path('dataset/evaluacion-experimental')
CONFIG=Path('configuracion-experimental/casos-prueba.json')
URL='https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip'
SHA='d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60'
TOKEN=re.compile(r'(?P<cadena>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(?P<comentario>//[^\r\n]*|/\*[\s\S]*?\*/)|(?P<identificador>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<otro>[^\s])')

def huella(datos): return hashlib.sha256(datos).hexdigest()
def inventario():
 return {p.relative_to(BASE).as_posix():huella(p.read_bytes()) for p in sorted(BASE.rglob('*')) if p.is_file()}
def sin_comentarios(texto):
 return TOKEN.sub(lambda m: ''.join(c if c in '\r\n' else ' ' for c in m.group()) if m.lastgroup=='comentario' else m.group(),texto)
def renombrar(texto,mapa):
 return TOKEN.sub(lambda m:mapa.get(m.group(),m.group()) if m.lastgroup=='identificador' else m.group(),texto)
def tokens(texto):return [(m.lastgroup,m.group()) for m in TOKEN.finditer(texto) if m.lastgroup!='comentario']
def sin_paquete(texto):return re.sub(r'\bpackage\s+[\w.]+\s*;','',texto,count=1)
def cerrar_metodos(metodos,raiz):
 cierre=set();pendientes=[raiz]
 while pendientes:
  nombre=pendientes.pop()
  if nombre in cierre:continue
  cierre.add(nombre)
  pendientes.extend(n for n in metodos[nombre]['llamadas'] if n in metodos)
 return cierre

assert not CONFIG.exists(),'No se sobrescriben preparaciones completas existentes'
originales_antes=inventario()
z=zipfile.ZipFile(TRABAJO/'juliet-1.3.zip')
assert huella((TRABAJO/'juliet-1.3.zip').read_bytes())==SHA
manifest_oficial=z.read('Java/manifest.xml')
manifest_normalizado,cierres_duplicados=re.subn(rb'(  </testcase>\n)  </testcase>\n',rb'\1',manifest_oficial)
assert cierres_duplicados==2 and manifest_normalizado==(BASE/'manifest.xml').read_bytes()
seleccion=json.loads((TRABAJO/'seleccion-verificada.json').read_text(encoding='utf-8'))
unidades=[(r,raiz) for r in seleccion for raiz in ['bad','good']]
random.Random(20261125).shuffle(unidades)
SALIDA.mkdir(parents=True,exist_ok=True)
jar=z.read('Java/lib/servlet-api.jar')
soporte_compartido=SALIDA/'soporte/servlet-api.jar';soporte_compartido.parent.mkdir(exist_ok=True);soporte_compartido.write_bytes(jar)
io_original=z.read('Java/src/testcasesupport/IO.java').decode('utf-8')
assert io_original.isascii()
io_limpio=sin_comentarios(io_original)
casos=[];control_ast=[];huellas=set();fuentes_preparadas=[]
for numero,(registro,raiz) in enumerate(unidades,1):
 identificador=f'Caso{numero:03d}'
 cwe=registro['cwe'];normalizado=22 if cwe in (23,36) else cwe
 carpeta=SALIDA/f'CWE-{cwe}'/identificador
 paquete=f'muestra.c{numero:03d}'
 destino=carpeta/'src/muestra'/f'c{numero:03d}'/'Unidad.java'
 destino.parent.mkdir(parents=True,exist_ok=True)
 original=Path(registro['archivo'].replace('\\','/'));texto=original.read_bytes().decode('utf-8');assert texto.isascii()
 arbol=registro['arbol'];metodos={m['nombre']:m for m in arbol['miembros'] if m['tipo']=='metodo'}
 cierre=cerrar_metodos(metodos,raiz)
 assert ('good' not in cierre if raiz=='bad' else 'bad' not in cierre)
 campos=[m for m in arbol['miembros'] if m['tipo']=='campo']
 miembros=sorted(campos+[metodos[n] for n in cierre],key=lambda m:m['inicio'])
 mapa={arbol['clase']:'Unidad','IO':'EntradaSalida',raiz:'ejecutar'}
 auxiliares=sorted([metodos[n] for n in cierre if n!=raiz],key=lambda m:m['inicio'])
 mapa.update({m['nombre']:f'operacion{i:02d}' for i,m in enumerate(auxiliares,1)})
 mapa.update({m['nombre']:f'estado{i:02d}' for i,m in enumerate(campos,1)})
 limpio=sin_comentarios(texto)
 lineas_originales=texto.splitlines();lineas_limpias=limpio.splitlines()
 paquete_original=re.search(r'(?m)^package\s+[^;]+;',limpio)
 cabecera=re.search(r'public class\s+'+re.escape(arbol['clase'])+r'\s+extends\s+AbstractTestCase(?:Servlet)?\s*\{',limpio)
 assert paquete_original and cabecera,original
 rangos=[(m['lineaInicio'],m['lineaFin']) for m in miembros]
 lineas_conservadas=set()
 for a,b in rangos:lineas_conservadas.update(range(a,b+1))
 for coincidencia in [paquete_original,cabecera,*re.finditer(r'(?m)^import\s+[^;]+;',limpio)]:
  a=limpio[:coincidencia.start()].count('\n')+1;b=limpio[:coincidencia.end()].count('\n')+1
  lineas_conservadas.update(range(a,b+1))
 cierre_clase=limpio.rfind('}');lineas_conservadas.add(limpio[:cierre_clase].count('\n')+1)
 preparadas=[];correspondencia=[]
 for i,linea in enumerate(lineas_limpias,1):
  if i not in lineas_conservadas or not linea.strip():continue
  nueva=renombrar(linea,mapa)
  if re.match(r'\s*package\s',nueva):nueva=f'package {paquete};'
  if re.match(r'\s*import testcasesupport\.\*;',nueva):nueva=f'import {paquete}.EntradaSalida;'
  nueva=re.sub(r'\s+extends\s+AbstractTestCase(?:Servlet)?\b','',nueva)
  preparadas.append(nueva.rstrip())
  correspondencia.append({'original':i,'preparada':len(preparadas)})
 resultado='\n'.join(preparadas)+'\n'
 assert not re.search(r'\b(?:good\w*|bad\w*|CWE\w*|AbstractTestCase\w*)\b',sin_comentarios(resultado),re.I),identificador
 destino.write_text(resultado,encoding='utf-8',newline='\n')
 canonico=renombrar(resultado,{f'c{numero:03d}':'unidad'})
 huella_canonica=huella(json.dumps(tokens(canonico),ensure_ascii=False).encode())
 assert huella_canonica not in huellas,('Duplicado',identificador)
 huellas.add(huella_canonica)
 io_transformado=renombrar(io_limpio,{'IO':'EntradaSalida'})
 io_transformado=re.sub(r'\bpackage\s+testcasesupport\s*;',f'package {paquete};',io_transformado,count=1)
 contenido_io=[];mapa_io=[]
 for i,l in enumerate(io_transformado.splitlines(),1):
  if l.strip():contenido_io.append(l.rstrip());mapa_io.append({'original':i,'preparada':len(contenido_io)})
 io_preparado='\n'.join(contenido_io)+'\n'
 assert tokens(sin_paquete(io_preparado))==tokens(renombrar(sin_paquete(io_original),{'IO':'EntradaSalida'}))
 archivo_io=destino.with_name('EntradaSalida.java');archivo_io.write_text(io_preparado,encoding='utf-8',newline='\n')
 dependencias=[{'archivoPreparado':archivo_io.as_posix(),'origenDistribucion':'Java/src/testcasesupport/IO.java',
   'sha256Original':huella(z.read('Java/src/testcasesupport/IO.java')),'sha256Preparado':huella(archivo_io.read_bytes()),'correspondenciaLineas':mapa_io},
   {'archivoPreparado':soporte_compartido.as_posix(),'origenDistribucion':'Java/lib/servlet-api.jar','sha256Original':huella(jar),'sha256Preparado':huella(jar)}]
 recursos=[]
 if 'PropertiesFile' in original.name:
  recurso=z.read('Java/src/testcases/common/config.properties').decode('utf-8')
  contenido_recurso='\n'.join(l for l in recurso.splitlines() if l.strip() and not l.lstrip().startswith('#'))+'\n'
  archivo_recurso=carpeta/'common/config.properties';archivo_recurso.parent.mkdir(exist_ok=True);archivo_recurso.write_text(contenido_recurso,encoding='utf-8',newline='\n')
  recursos.append(archivo_recurso)
  dependencias.append({'archivoPreparado':archivo_recurso.as_posix(),'origenDistribucion':'Java/src/testcases/common/config.properties',
   'sha256Original':huella(z.read('Java/src/testcases/common/config.properties')),'sha256Preparado':huella(archivo_recurso.read_bytes())})
 flaws=[f for nodo in registro['manifest'] for f in nodo['flaws'] if any(metodos[n]['lineaInicio']<=int(f['line'])<=metodos[n]['lineaFin'] for n in cierre)]
 assert bool(flaws)==(raiz=='bad')
 for f in flaws:assert int(re.search(r'CWE-(\d+)',f['name']).group(1))==cwe
 mapeo={r['original']:r['preparada'] for r in correspondencia}
 for f in flaws:assert int(f['line']) in mapeo
 lineas_flaw=sorted(set(int(f['line']) for f in flaws))
 operacion=re.compile(r'\.addBatch\(|\.execute(?:Query|Update)?\(|\.prepareStatement\(') if cwe==89 else re.compile(r'Runtime\.getRuntime\(\)\.exec\(') if cwe==78 else re.compile(r'new File\(root \+ data\)|new File\(data\)')
 lineas_sensibles=[i for i in sorted(mapeo) if any(metodos[n]['lineaInicio']<=i<=metodos[n]['lineaFin'] for n in cierre)
                   and operacion.search(lineas_limpias[i-1])]
 lineas_operacion=lineas_sensibles if raiz=='bad' else []
 assert raiz=='good' or lineas_operacion,(original,lineas_flaw)
 evidencias=[]
 for m in miembros:
  if m['tipo']!='metodo':continue
  cuerpo=m['ast']
  if m['nombre'].startswith('goodG2B'):assert re.search(r'data\s*=\s*"foo"',cuerpo)
  if m['nombre'].startswith('goodB2G'):assert cwe==89 and 'prepareStatement(' in cuerpo and '.setString(' in cuerpo and '?' in cuerpo
  for i in range(m['lineaInicio'],m['lineaFin']+1):
   l=lineas_limpias[i-1].strip()
   if i in mapeo and (re.search(r'\bdata\s*=',l) or operacion.search(l) or '.setString(' in l or 'case ' in l or 'return true' in l or 'return false' in l):
    evidencias.append({'metodoOriginal':m['nombre'],'lineaOriginal':i,'lineaPreparada':mapeo[i],'codigoOriginal':l})
 paquete_zip=carpeta.parent/(identificador+'.zip')
 with zipfile.ZipFile(paquete_zip,'w',compression=zipfile.ZIP_DEFLATED) as unidad_zip:
  for fichero in [destino,archivo_io,*recursos]:
   info=zipfile.ZipInfo(fichero.relative_to(carpeta).as_posix(),date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
   unidad_zip.writestr(info,fichero.read_bytes())
  info=zipfile.ZipInfo('lib/servlet-api.jar',date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;unidad_zip.writestr(info,jar)
 raiz_nodo=metodos[raiz]
 fuente=re.search(r'BadSource:\s*([^\r\n]+)',texto).group(1)
 flujo=re.search(r'Flow Variant:\s*([^\r\n]+)',texto).group(1)
 razon=('El método bad alcanza una operación sensible con datos externos según el flujo original y las anotaciones del manifiesto.' if raiz=='bad' else
  'El método good conserva todos sus auxiliares: las ramas alcanzables usan datos constantes; las variantes B2G de SQL usan parámetros enlazados con setString. La clasificación se verificó por el código, no por ausencia de etiquetas.')
 caso={'identificador':identificador,'archivoOriginal':original.as_posix(),'archivoPreparado':destino.as_posix(),'paqueteAnalisis':paquete_zip.as_posix(),
  'metodoOriginal':raiz,'metodoPreparado':'ejecutar','cweOriginal':f'CWE-{cwe}','cweNormalizado':f'CWE-{normalizado}',
  'clasificacionEsperada':'VULNERABLE' if raiz=='bad' else 'SEGURO','fuenteDatosOriginal':fuente,'varianteFlujo':flujo,'fundamentoClasificacion':razon,
  'anotacionesManifiesto':flaws,'testcasesManifiesto':[n['indiceTestcase'] for n in registro['manifest']],
  'lineasVulnerabilidadOriginales':lineas_flaw,'lineasVulnerabilidadPreparadas':[mapeo[i] for i in lineas_flaw],
  'lineasOperacionSensibleOriginales':lineas_sensibles,'lineasOperacionSensiblePreparadas':[mapeo[i] for i in lineas_sensibles],
  'lineasOperacionVulnerableOriginales':lineas_operacion,'lineasOperacionVulnerablePreparadas':[mapeo[i] for i in lineas_operacion],
  'correspondenciaLineas':correspondencia,'metodosIncluidos':[{'original':m['nombre'],'preparado':mapa[m['nombre']],
      'inicioOriginal':m['lineaInicio'],'finOriginal':m['lineaFin'],'inicioPreparado':mapeo[m['lineaInicio']],
      'finPreparado':mapeo[m['lineaFin']]} for m in miembros if m['tipo']=='metodo'],
  'renombrados':mapa,'dependencias':dependencias,'evidenciasVerificacion':evidencias,
  'sha256Original':huella(original.read_bytes()),'sha256Preparado':huella(destino.read_bytes()),'sha256PaqueteAnalisis':huella(paquete_zip.read_bytes()),
  'sha256TokensNeutrales':huella_canonica,'directorioTrabajoRelativo':'src',
  'transformaciones':['Separación por cierre de llamadas de la entrada original, conservando todos los campos y auxiliares necesarios.',
   'Retirada del arnés main y de la herencia AbstractTestCase/AbstractTestCaseServlet que invocaba las dos clasificaciones; no se sustituye código de los métodos seleccionados.',
   'Eliminación léxica de comentarios y líneas vacías; renombrado de paquete, clase, entrada, auxiliares y campos, sin modificar literales, expresiones ni control de flujo.',
   'ZIP individual con rutas neutrales y marcas de tiempo uniformes; sin el registro de etiquetas esperado.'],
  'validaciones':{'fuenteCoincideDistribucionOficial':True,'manifiestoContrastadoConCodigo':True,'equivalenciaAstMetodosYCampos':False,'compilacionJava21':False}}
 casos.append(caso);control_ast.append({'archivo':destino.as_posix(),'mapa':mapa,'miembros':miembros});fuentes_preparadas.extend([destino,archivo_io])

argumentos=TRABAJO/'compilar-unidades.args'
carpeta_clases=TRABAJO/'clases';carpeta_clases.mkdir(exist_ok=True)
argumentos.write_text('\n'.join(['-proc:none','--release','21','-encoding','UTF-8','-classpath',soporte_compartido.as_posix(),'-d',carpeta_clases.as_posix(),*[p.as_posix() for p in fuentes_preparadas]]),encoding='utf-8')
compilacion=subprocess.run([herramienta_java('javac'),'@'+argumentos.as_posix()],capture_output=True)
(TRABAJO/'compilacion.stdout').write_bytes(compilacion.stdout);(TRABAJO/'compilacion.stderr').write_bytes(compilacion.stderr)
assert compilacion.returncode==0,compilacion.stderr.decode(errors='replace')
ast=subprocess.run([herramienta_java('java'),'-cp',str(TRABAJO),'InspeccionarJava',*[c['archivo'] for c in control_ast]],capture_output=True,encoding='utf-8',check=True)
arboles={Path(a['archivo']).resolve():a for a in map(json.loads,ast.stdout.splitlines())}
for caso,control in zip(casos,control_ast):
 nuevos=arboles[Path(control['archivo']).resolve()]['miembros']
 assert len(nuevos)==len(control['miembros'])
 inverso={nuevo:viejo for viejo,nuevo in control['mapa'].items()}
 for antiguo,nuevo in zip(control['miembros'],nuevos):
  assert tokens(antiguo['ast'])==tokens(renombrar(nuevo['ast'],inverso)),(caso['identificador'],antiguo['nombre'])
 caso['validaciones']['equivalenciaAstMetodosYCampos']=True;caso['validaciones']['compilacionJava21']=True

assert originales_antes==inventario(),'El dataset original ha cambiado'
conteos=collections.Counter((c['cweOriginal'],c['clasificacionEsperada']) for c in casos)
assert len(casos)==60 and len(huellas)==60
grupos_origen=collections.defaultdict(list)
for caso in casos:grupos_origen[caso['sha256Original']].append(caso['identificador'])
for caso in casos:
 caso['grupoOrigen']=caso['sha256Original']
 caso['unidadesDelMismoOriginal']=grupos_origen[caso['sha256Original']]
for cwe,n in [(89,10),(78,10),(23,5),(36,5)]:
 for clase in ['VULNERABLE','SEGURO']:assert conteos[(f'CWE-{cwe}',clase)]==n
documento={'dataset':'Juliet Java 1.3','origenOficial':URL,'sha256DistribucionOficial':SHA,
 'manifestOficial':{'sha256':huella(manifest_oficial),'diferenciaConCopiaLocal':'La distribución oficial contiene dos cierres testcase duplicados en CWE-190 y CWE-191; la copia local únicamente omite esos cierres. Se contrastó sin modificar ningún archivo original. Las anotaciones de los 30 archivos seleccionados son idénticas.'},
 'sha256ManifestOriginal':huella((BASE/'manifest.xml').read_bytes()),'sha256InventarioOriginal':huella(json.dumps(originales_antes,sort_keys=True).encode()),
 'unidadDeAnalisis':'Una entrada bad o good del archivo original y su cierre de llamadas local, aislados por paquete ZIP. good puede agrupar varios auxiliares seguros originales.',
 'restriccion':'Este archivo contiene etiquetas y correspondencias; no incluirlo en los ZIP ni enviarlo a los analizadores.',
 'seleccion':'Intencional por variedad de fuente, operación y variante de flujo; sin usar resultados de Semgrep ni de IA.',
 'semillaOrdenNeutro':20261125,'normalizacionCwe':{'CWE-23':'CWE-22','CWE-36':'CWE-22','CWE-78':'CWE-78','CWE-89':'CWE-89'},
 'distribucion':[{'cwe':cwe,'clasificacion':clase,'cantidad':cantidad} for (cwe,clase),cantidad in sorted(conteos.items())],
 'validacionesGlobales':{'totalCasos':60,'fuentesOriginalesDistintas':30,'duplicadosExactosNeutrales':0,'datasetOriginalSinCambios':True,
   'compilador':'Java 21; javac -proc:none; sin ejecutar los casos','casosEjecutados':0,'seleccionBasadaEnAnalizadores':False},
 'limitaciones':['Se conserva el comportamiento de cada entrada seleccionada y sus auxiliares, no el arnés completo original que ejecutaba ambas clasificaciones.',
  'Las etiquetas describen la debilidad objetivo bajo las precondiciones originales de Juliet; no certifican ausencia de otras debilidades.',
  'No se ejecutaron comandos, accesos de red ni consultas de los casos. Compilación y equivalencia AST no equivalen a prueba dinámica ni equivalencia formal completa.',
  'Los casos necesitan sus condiciones originales de entrada: variables, consola, servlet, archivos o servicios TCP/HTTP. Los datos externos y las rutas absolutas no se inventaron ni sustituyeron.',
  'IO.getDBConnection conserva sus parámetros originales vacíos. Ejecutar dinámicamente las variantes SQL requiere configurar un entorno de base de datos; no se agregó driver ni configuración ficticia.',
  'Los métodos good pueden contener varios auxiliares seguros. Las anotaciones del manifiesto incluyen fuentes y operaciones: no deben contarse como vulnerabilidades independientes.',
  'Se eligieron variantes de un solo archivo con auxiliares locales; no se afirma cobertura de toda la suite ni representatividad estadística.',
  'La copia local carecía de testcasesupport y de servlet-api.jar; se recuperaron del paquete oficial verificado. Se comparte el JAR original para compilación y se incluye en cada ZIP individual. No se modificaron dependencias del microservicio.',
  'Las unidades vulnerable y segura de un mismo archivo son casos relacionados, no muestras independientes; la correspondencia se conserva mediante grupoOrigen.',
  'En los seguros de comandos y rutas predominan entradas constantes originales. SQL conserva también consultas parametrizadas. No se agregaron validadores ni sanitizadores ajenos a Juliet.'],
 'casos':casos}
CONFIG.parent.mkdir(exist_ok=True)
CONFIG.write_text(json.dumps(documento,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(documento['distribucion'],ensure_ascii=False))
print('60 unidades, 60 ZIP, 120 fuentes compiladas. AST conservado y dataset original intacto.')
