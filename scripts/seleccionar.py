from pathlib import Path
import subprocess,json,zipfile,hashlib,xml.etree.ElementTree as ET
import sys
sys.dont_write_bytecode = True
from entorno_juliet import RAIZ, TRABAJO, iniciar, herramienta_java

iniciar()
BASE=Path('dataset/juliet-java-1.3')
ARCHIVO=Path('build/preparacion-juliet/juliet-1.3.zip')
SHA='d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60'
assert hashlib.sha256(ARCHIVO.read_bytes()).hexdigest()==SHA
SELECCION={
89:['Environment_executeQuery_01','getParameter_Servlet_execute_02','getCookies_Servlet_executeUpdate_05','getQueryString_Servlet_prepareStatement_08','Property_executeBatch_15','PropertiesFile_executeQuery_17','File_execute_03','console_readLine_executeUpdate_04','connect_tcp_prepareStatement_06','URLConnection_executeBatch_07'],
78:['Environment_01','getParameter_Servlet_02','getCookies_Servlet_03','File_04','Property_05','PropertiesFile_06','console_readLine_07','connect_tcp_08','listen_tcp_15','URLConnection_17'],
23:['Environment_01','getParameter_Servlet_02','File_05','connect_tcp_15','Property_17'],
36:['getCookies_Servlet_01','PropertiesFile_02','console_readLine_05','listen_tcp_15','URLConnection_17']}
archivos=[]
for cwe,variantes in SELECCION.items():
 for variante in variantes:
  encontrados=list(BASE.glob(f'CWE{cwe}_*/**/CWE{cwe}_*__{variante}.java'))
  assert len(encontrados)==1,(cwe,variante,encontrados)
  archivos.append((cwe,encontrados[0]))
subprocess.run([herramienta_java('javac'),'-proc:none','--release','21','-encoding','UTF-8','-d',str(TRABAJO),str(RAIZ/'scripts/InspeccionarJava.java')],check=True,capture_output=True)
salida=subprocess.run([herramienta_java('java'),'-Dfile.encoding=UTF-8','-cp',str(TRABAJO),'InspeccionarJava',*[str(p) for _,p in archivos]],check=True,capture_output=True,encoding='utf-8')
arboles={Path(r['archivo']).resolve():r for r in map(json.loads,salida.stdout.splitlines())}
manifest={}
for numero,caso in enumerate(ET.parse(BASE/'manifest.xml').getroot().findall('testcase'),1):
 for fichero in caso.findall('file'):
  manifest.setdefault(fichero.get('path'),[]).append({'indiceTestcase':numero,'flaws':[dict(f.attrib) for f in fichero.findall('flaw')]})
z=zipfile.ZipFile(ARCHIVO)
revisiones=[]
for cwe,p in archivos:
 assert z.read('Java/src/testcases/'+p.relative_to(BASE).as_posix())==p.read_bytes(),p
 arbol=arboles[p.resolve()]
 arbol['archivo']=p.as_posix()
 assert p.name in manifest
 metodos={m['nombre']:m for m in arbol['miembros'] if m['tipo']=='metodo'}
 assert 'bad' in metodos and 'good' in metodos
 lineas=p.read_text(encoding='utf-8').splitlines()
 print('\n',p.name)
 for raiz in ['bad','good']:
  cierre=set();pendientes=[raiz]
  while pendientes:
   nombre=pendientes.pop()
   if nombre in cierre:continue
   cierre.add(nombre)
   pendientes.extend(n for n in metodos[nombre]['llamadas'] if n in metodos)
  segmentos=[metodos[n] for n in sorted(cierre)]
  flaws=[f for nodo in manifest[p.name] for f in nodo['flaws'] if any(m['lineaInicio']<=int(f['line'])<=m['lineaFin'] for m in segmentos)]
  assert (raiz=='bad')==bool(flaws),(p,raiz,flaws)
  print(' ROOT',raiz,'METHODS',','.join(sorted(cierre)),'FLAWS',','.join(f['line'] for f in flaws))
  for m in segmentos:
   for n in range(m['lineaInicio'],m['lineaFin']+1):
    s=lineas[n-1].strip()
    if any(x in s for x in ['data =','data=','execute','prepareStatement','setString','exec(','new File(','new FileInputStream','if (','switch (','case ','return true','return false']):print(n,s)
 revisiones.append({'cwe':cwe,'archivo':p.as_posix(),'arbol':arbol,'manifest':manifest[p.name]})
Path('build/preparacion-juliet/seleccion-verificada.json').write_text(json.dumps(revisiones,ensure_ascii=False,indent=2),encoding='utf-8')
