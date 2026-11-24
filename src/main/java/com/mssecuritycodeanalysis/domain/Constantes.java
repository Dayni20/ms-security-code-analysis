package com.mssecuritycodeanalysis.domain;

public final class Constantes {

    public static final String MENSAJE_RUTA_ARCHIVO_OBLIGATORIA = "La ruta del archivo es obligatoria";
    public static final String MENSAJE_CONTENIDO_NULO = "El contenido no puede ser nulo";
    public static final String MENSAJE_LENGUAJE_OBLIGATORIO = "El lenguaje del archivo es obligatorio";
    public static final String MENSAJE_ZIP_SIN_ARCHIVOS_ADMITIDOS = "El ZIP debe contener al menos un archivo fuente de un lenguaje admitido";
    public static final String MENSAJE_NOMBRE_ZIP_INVALIDO = "El archivo debe tener un nombre válido con extensión .zip";
    public static final String MENSAJE_ARCHIVO_OBLIGATORIO = "El archivo es obligatorio";
    public static final String MENSAJE_ARCHIVO_VACIO = "El archivo está vacío";
    public static final String MENSAJE_ZIP_DANADO = "El ZIP está dañado o utiliza un formato no admitido";
    public static final String MENSAJE_ERROR_PROCESAR_ARCHIVO = "No se pudo procesar el archivo recibido";
    public static final String MENSAJE_LIMITE_TAMANO_ZIP = "El ZIP supera el tamaño comprimido permitido";
    public static final String MENSAJE_LIMITE_ENTRADAS = "El ZIP supera la cantidad de entradas permitida";
    public static final String MENSAJE_LIMITE_DESCOMPRESION = "El contenido del ZIP supera el tamaño descomprimido permitido";
    public static final String MENSAJE_ENTRADA_ZIP_DANADA = "El ZIP contiene una entrada dañada";
    public static final String MENSAJE_RUTAS_DUPLICADAS = "El ZIP contiene rutas duplicadas";
    public static final String MENSAJE_RUTA_NO_PERMITIDA = "El ZIP contiene una ruta no permitida";
    public static final String MENSAJE_CODIFICACION_INVALIDA = "Los archivos fuente deben estar codificados en UTF-8";
    public static final String MENSAJE_LIMITE_MULTIPART = "El archivo o la petición superan el tamaño permitido";
    public static final String MENSAJE_ARCHIVO_MULTIPART_REQUERIDO = "Se requiere un archivo ZIP en el campo 'file'";

    public static final String RUTA_CARGA_PROYECTO = "/api/v1/analysis/upload";
    public static final String RUTA_ESTADO_SERVICIO = "/api/v1/health";
    public static final String CAMPO_ARCHIVO_MULTIPART = "file";
    public static final String CLAVE_ERROR = "error";
    public static final String CLAVE_ESTADO = "status";
    public static final String CLAVE_SERVICIO = "service";
    public static final String ESTADO_SERVICIO_ACTIVO = "UP";

    public static final String PROPIEDAD_NOMBRE_APLICACION = "${spring.application.name}";
    public static final String PREFIJO_CONFIGURACION_CARGA = "proyecto.carga";
    public static final String PATRON_EXTENSION_PERMITIDA = "[a-z0-9]+";
    public static final String EXTENSION_ZIP = ".zip";
    public static final String PREFIJO_ARCHIVO_TEMPORAL = "proyecto-";
    public static final String SEPARADOR_RUTA_UNIX = "/";
    public static final String SEPARADOR_RUTA_WINDOWS = "\\";
    public static final String SEPARADOR_UNIDAD = ":";
    public static final String SEGMENTO_DIRECTORIO_PADRE = "..";
    public static final String SEGMENTO_DIRECTORIO_ACTUAL = ".";

    public static final char CARACTER_SEPARADOR_UNIX = '/';
    public static final char CARACTER_SEPARADOR_WINDOWS = '\\';
    public static final char CARACTER_PUNTO = '.';

    private Constantes() {
    }
}
