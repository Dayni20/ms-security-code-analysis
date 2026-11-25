import os
import shutil
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
TRABAJO = Path('build/preparacion-juliet')


def iniciar():
    os.chdir(RAIZ)
    TRABAJO.mkdir(parents=True, exist_ok=True)


def herramienta_java(nombre):
    ejecutable = nombre + ('.exe' if os.name == 'nt' else '')
    java_home = os.environ.get('JAVA_HOME')
    if java_home:
        ruta = Path(java_home) / 'bin' / ejecutable
        if ruta.is_file():
            return str(ruta)
        raise RuntimeError(f'JAVA_HOME no contiene {ejecutable}. Configura un JDK compatible con Java 21.')
    ruta = shutil.which(ejecutable)
    if ruta:
        return ruta
    raise RuntimeError(f'No se encuentra {ejecutable}. Configura JAVA_HOME o el PATH con un JDK compatible con Java 21.')
