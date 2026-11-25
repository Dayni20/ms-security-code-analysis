import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def detener_grupo(proceso):
    try:
        os.killpg(proceso.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proceso.wait()


def ejecutar():
    tiempo_maximo = float(sys.argv[1])
    cancelacion = Path(sys.argv[2])
    directorio = Path.cwd()
    if cancelacion.exists():
        return 125

    entorno = os.environ.copy()
    for variable in ("PYTHONPATH", "PYTHONSTARTUP", "SEMGREP_APP_TOKEN"):
        entorno.pop(variable, None)
    entorno["PYTHONUTF8"] = "1"
    entorno["SEMGREP_SETTINGS_FILE"] = str(directorio / "semgrep-settings.yaml")

    try:
        proceso = subprocess.Popen(sys.argv[3:], env=entorno, start_new_session=True)
    except FileNotFoundError:
        return 127
    except OSError:
        return 126

    limite = time.monotonic() + tiempo_maximo
    try:
        while proceso.poll() is None:
            if cancelacion.exists() or not directorio.exists():
                return 125
            if time.monotonic() >= limite:
                return 124
            time.sleep(0.05)
        return proceso.returncode
    finally:
        detener_grupo(proceso)


if __name__ == "__main__":
    sys.exit(ejecutar())
