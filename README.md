# Plataforma Web de Recogida de Evidencias Forenses

Este repositorio contiene el desarrollo de una **plataforma web para la recogida y análisis automatizado de evidencias forenses**, realizada como **Trabajo Fin de Máster (TFM)** del Máster en Seguridad Informática.

El objetivo del proyecto es proporcionar una herramienta sencilla que permita a usuarios autenticados subir ficheros, lanzar un pipeline de análisis forense automatizado y consultar los resultados desde una interfaz web centrada en la trazabilidad.

---

## Objetivo del proyecto

La plataforma está pensada como un punto centralizado de recogida y análisis de evidencias digitales (principalmente documentos, imágenes y audio), con énfasis en:

- **Automatización** del análisis técnico (hashes, AV, YARA, macros, esteganografía, etc.).
- **Trazabilidad y auditoría** de las acciones realizadas sobre cada fichero.
- **Visualización** de indicadores clave (volumen, tipos de ficheros, detecciones, uso de almacenamiento).

---

## Características principales

### Autenticación y usuario

- Inicio y cierre de sesión mediante Flask-Login.
- Perfil de usuario con edición de nombre, cambio de contraseña y actualización de avatar.
- Contador de notificaciones nuevo en la interfaz (campana en la barra superior).

### Gestión de ficheros

- Subida de ficheros autenticada con validación de extensión y tamaño (hasta 100 MB).
- Soporte para ficheros ofimáticos (DOC/DOCX/DOCM, XLS/XLSX/XLSM, PPT/PPTX/PPTM), ejecutables, PDF, imágenes y WAV.
- Almacenamiento en disco con nombres internos aleatorizados y registro completo en base de datos.
- Cuota de almacenamiento configurable por usuario (`STORAGE_QUOTA_MB`) y cálculo del espacio usado.
- Sección de **Storage** donde el usuario puede ver sus ficheros, el espacio ocupado y eliminar evidencias (borrando también análisis y alertas asociadas).

### Pipeline de análisis forense

Implementado en `app/analysis/pipeline.py` y ejecutado en segundo plano tras la subida del fichero.

- **Cálculo de hashes**: MD5, SHA1, SHA256.
	- Se calculan tanto en el pipeline como en el momento de la subida, almacenándose también en el modelo `File` como huella de integridad.
- **Detección de tipo**: tipo MIME y tipo lógico de fichero.
- **Metadatos básicos**:
	- Tamaño y tipo.
	- Para imágenes: resolución y metadatos EXIF (si están disponibles).
	- Para audio: duración, bitrate y etiquetas típicas (artista, álbum, título).
- **Análisis antivirus local (ClamAV)**:
	- Ejecución de `clamscan` si está disponible en el sistema o dentro del contenedor Docker de la aplicación.
	- Clasificación del resultado: `clean`, `infected`, `not_available`, `error`, `unknown`.
- **Consulta a VirusTotal (opcional)**:
	- Uso de la API v3 de VirusTotal a partir del hash SHA256 (no se sube el fichero).
	- Requiere configurar `VIRUSTOTAL_API_KEY` (variable de entorno o entrada en `pyvenv.cfg`).
- **Escaneo YARA (opcional)**:
	- Carga de reglas desde una ruta configurable (`YARA_ENABLED` y `YARA_RULES_PATH`).
	- Integración con un conjunto de reglas públicas de alta calidad (snapshot del repositorio `Neo23x0/signature-base`) para disponer de firmas actualizadas sin tener que mantener reglas propias desde cero.
	- Serialización de las coincidencias para su consulta en el informe.
- **Detección de macros en documentos Office**:
	- Uso de `oletools/olevba` cuando está instalado.
	- Fallback heurístico cuando la librería no está disponible.
	- Extracción de módulos VBA, conteo de macros, tamaño de código e indicadores sospechosos.
- **Detección de esteganografía**:
	- Extracción de texto oculto en los bits menos significativos (LSB) de imágenes.
	- Extracción de posible contenido oculto en audio WAV mediante LSB.
	- Búsqueda de grandes blobs base64 embebidos en el fichero (PDF, audio u otros).
	- Heurísticas de tamaño para marcar ficheros inusualmente grandes como "posible" esteganografía.
	- Clasificación simple: `no`, `possible`, `yes`.
- **Análisis de ficheros de audio**:
	- Uso de `mutagen` para extraer metadatos de audio.
	- Generación opcional de espectrogramas en PNG para WAV mediante `numpy` y `matplotlib` (mostrados en el informe si las dependencias están instaladas).
- **Veredicto global**:
	- Combinación de señales (ClamAV, YARA, macros, estego) en un campo `final_verdict` (`clean`, `suspicious`, `malicious`, `critical`).
	- Generación de un resumen textual del análisis para facilitar la lectura rápida.

Todos los resultados se persisten en el modelo `Analysis`, incluyendo hashes, metadatos extendidos (`additional_results` como JSON) y versiones de motor/reglas.

### Alertas y notificaciones

- Modelo `Alert` asociado a ficheros y análisis.
- Creación automática de alertas en función de:
	- Veredictos `malicious`/`critical`.
	- Detección de macros sospechosas.
	- Presencia de indicadores de esteganografía.
	- Superación de un umbral diario de ficheros maliciosos.
	- Disponibilidad de nuevos informes (alerta de "Report ready").
- Contador de notificaciones en el usuario y endpoints para marcar todas como leídas.

### Dashboard y visualización

- **Dashboard principal** con:
	- KPIs de volumen de ficheros subidos, analizados, pendientes y detecciones recientes.
	- Uso de almacenamiento global y porcentaje de ocupación.
	- Series temporales de detecciones en los últimos 7 días.
	- Distribución de tipos de fichero analizados.
	- Detecciones por fuente (ClamAV, YARA, sandbox reservado, estego, macros).
	- Últimos ficheros analizados y alertas recientes.
- Gráficas interactivas implementadas con Chart.js (`dashboard.js`).

### Listados e informes

- Listado de ficheros con estado de análisis, tamaño legible y propietario.
- Listado de análisis realizados con veredicto, hashes y fuentes de detección activas.
- Informe de análisis detallado por fichero que incluye:
	- Hashes, metadatos y tipo de fichero.
	- Resultado enriquecido de ClamAV y VirusTotal.
	- Coincidencias YARA.
	- Resultado de detección de macros y acceso al código VBA.
	- Información de esteganografía (indicadores, blobs base64, payloads recuperados).
	- Metadatos y espectrograma de audio cuando aplica.
	- Alertas asociadas a ese análisis.
- Endpoints auxiliares para recuperar, en JSON, payloads completos de esteganografía o módulos VBA individuales (para mostrarlos en modales en la interfaz).

### Trazabilidad y auditoría

- Modelo `Log` para registrar eventos de alto nivel (login, logout, subida, análisis completado, limpieza de almacenamiento, etc.).
- Captura de IP, user-agent, acción, recurso lógico, estado y detalles adicionales en JSON.
- Vista de **Logs** paginada, ordenada por fecha descendente.

### Políticas de almacenamiento y borrado de evidencias

- Los ficheros subidos se almacenan en un directorio interno de la instancia de Flask (por defecto `instance/uploads/`), **fuera de la carpeta `static/`**, por lo que **no son servidos directamente por el servidor web**.
- El acceso a la evidencia se realiza siempre a través de vistas controladas (informes HTML, export JSON/PDF), nunca exponiendo la ruta física real del fichero como recurso estático.
- La sección de **Storage** permite al usuario revisar sus ficheros y eliminar evidencias cuando necesite liberar espacio. Al borrar un fichero se aplica una política de limpieza en cascada:
	- Se eliminan los análisis (`Analysis`) asociados a ese `File`.
	- Se eliminan las alertas (`Alert`) vinculadas a esos análisis y al propio fichero.
	- Se borra el fichero físico del disco si existe.
- Cada operación de borrado genera entradas en el modelo `Log` (por ejemplo, acciones `analysis_deleted` y `storage_cleanup`), de modo que queda constancia de **quién**, **cuándo** y **qué** se ha eliminado, cumpliendo el objetivo de trazabilidad en las operaciones de limpieza de almacenamiento.

---

## Tecnologías utilizadas

- Python 3
- Flask (aplicación web, blueprints, contexto de aplicación)
- Flask-Login (gestión de sesiones de usuario)
- Flask-WTF / WTForms (formularios de login)
- SQLAlchemy / Flask-SQLAlchemy (modelo de datos sobre PostgreSQL)
- PostgreSQL (almacenamiento principal de datos, normalmente desplegado en contenedor Docker o servicio gestionado)
- Jinja2 (plantillas HTML)
- HTML / CSS (Bootstrap) para la interfaz
- Chart.js para visualización de métricas en el dashboard
- SweetAlert2 para validaciones de subida en frontend
- Librerías forenses y de análisis opcionales:
	- `oletools` (análisis de macros VBA)
	- `yara` (reglas YARA)
	- `mutagen` (metadatos de audio)
	- `Pillow` (imágenes y EXIF)
	- `numpy` y `matplotlib` (espectrogramas de audio)
	- `requests` (integración con API de VirusTotal)

---

## Estado actual del proyecto

El proyecto se encuentra en un estado de **prototipo funcional**:

- El flujo completo de subida → análisis → alertas → consulta de informe está implementado.
- La plataforma ya ofrece un dashboard con métricas, vistas de ficheros, análisis, almacenamiento y logs.
- Varias características avanzadas (VirusTotal, YARA, macros, estego, espectrogramas) se han diseñado como **módulos opcionales**, que se activan cuando las dependencias y la configuración están disponibles.

Limitaciones actuales (trabajo futuro):

- No hay alta de usuarios vía interfaz (la creación de usuarios se realiza vía script/administración).
- No se ha integrado todavía un sandbox externo real (el campo `sandbox_score` está reservado).
- Faltan baterías de tests automatizados y documentación técnica más detallada (diagramas, ejemplos de despliegue avanzado, hardening, etc.).

---

## Aviso

Este proyecto tiene **fines académicos** y no pretende sustituir herramientas forenses profesionales certificadas.

---

## Configuración por variables de entorno (secrets y claves)

La plataforma está pensada para que las credenciales y parámetros sensibles **no** se almacenen en el código fuente, sino como variables de entorno o secretos del entorno de despliegue.

Variables de entorno principales:

- `SECRET_KEY`  
	Clave secreta de Flask para sesiones y CSRF. **Debe definirse siempre en producción**. En desarrollo, si no se establece, se usará un valor por defecto (`forenalyze-secret-key`).

- `DATABASE_URL`  
	URI de conexión a la base de datos, por ejemplo:  
	`postgresql+psycopg2://forenalyze:forenalyze@localhost:5432/forenalyze`  
	Si no se define, se usa este valor por defecto para desarrollo local.

- `STORAGE_QUOTA_MB`  
	Cuota de almacenamiento por usuario (en MB). Por defecto `2048`.

- `CLAMAV_PATH`  
	Ruta al ejecutable de `clamscan`/`clamscan.exe`. Si no se define, se intentará usar simplemente `clamscan` del `PATH` del sistema o del contenedor.

- `VIRUSTOTAL_API_KEY`  
	API key de VirusTotal para realizar consultas por hash (API v3). Si no está configurada, la integración se marca como `not_configured` y el análisis continúa sin romper el pipeline.  
	Como compatibilidad, también puede leerse desde `pyvenv.cfg` dentro del entorno virtual (`virustotal_api_key = ...`).

- `VIRUSTOTAL_ENABLED`  
	Permite activar/desactivar completamente las consultas a VirusTotal desde configuración. Valores aceptados: `1/true/yes` (activado), `0/false/no` (desactivado). Por defecto está activado.

- `VIRUSTOTAL_CACHE_TTL_SECONDS`  
	Tiempo de vida (en segundos) de una caché en memoria por hash SHA256. Mientras el TTL no haya expirado, se reutiliza la última respuesta de VirusTotal para ese hash dentro del mismo proceso. Por defecto `3600` segundos (1 hora).

- `YARA_ENABLED` y `YARA_RULES_PATH`  
	Controlan el escaneo YARA.  
	`YARA_ENABLED` (`1/true/yes` para activar) y `YARA_RULES_PATH` (ruta al fichero de reglas YARA **o a un directorio que contenga múltiples ficheros .yar/.yara/.rule**). Si la librería `yara` no está instalada o la ruta no existe, el escaneo se desactiva de forma segura.
	En el contexto del TFM, se utiliza normalmente un **snapshot local** del repositorio público `Neo23x0/signature-base` como fuente de reglas (por ejemplo, apuntando `YARA_RULES_PATH` al subdirectorio `yara/`). Esto permite beneficiarse de reglas mantenidas por terceros especializados, citando la fuente en la memoria y sin atribuirse la autoría de dichas firmas.

- `SANDBOX_ENABLED`, `SANDBOX_MODE` y `SANDBOX_MOCK_RESULT_PATH`  
	Controlan el **hook de integración con sandbox dinámico** (por ejemplo Cuckoo o un servicio remoto como Hybrid Analysis / Falcon Sandbox).  
	`SANDBOX_ENABLED` (`1/true/yes` para activar) y `SANDBOX_MODE` definen el modo de trabajo:
	- `disabled` (por defecto): el sandbox no se ejecuta y el campo `sandbox_score` permanece vacío.  
	- `mock`: el pipeline genera un resultado sintético en función del tipo de fichero (EXE, Office, PDF, etc.) para mostrar en los informes cómo se integrarían un `score`, familia y etiquetas de sandbox **sin necesidad de desplegar Cuckoo**.  
	- `file`: el pipeline intenta leer un JSON de ejemplo desde `SANDBOX_MOCK_RESULT_PATH` (por ejemplo, la salida real de Cuckoo para una muestra) y extrae de ahí un `score`, familia y tags. Esto permite una **PoC offline** en la que Forenalyze consume resultados de sandbox ya generados.
	- `hybrid_analysis`: el pipeline envía el fichero a un servicio remoto Hybrid Analysis / Falcon Sandbox mediante su API HTTP (cuenta community con API key) y adjunta en los metadatos la URL pública del informe, de modo que el informe HTML muestre un botón para abrir el análisis dinámico en una nueva pestaña.
	En todos los modos, el resultado se refleja en el campo `sandbox_score` del modelo `Analysis` (cuando hay `score`) y se adjunta en `additional_results['sandbox']`, de modo que tanto el informe HTML como el PDF/JSON muestran explícitamente el bloque de "Sandbox / dynamic analysis" y el diseño de integración quede claramente documentado para el TFM.

- `HYBRID_ANALYSIS_API_KEY`, `HYBRID_ANALYSIS_API_URL`, `HYBRID_ANALYSIS_PUBLIC_URL`, `HYBRID_ANALYSIS_ENV_ID`  
	Variables específicas para la integración remota con Hybrid Analysis / Falcon Sandbox cuando `SANDBOX_MODE=hybrid_analysis`. Permiten configurar la API key, el endpoint base de la API v2, la URL pública para ver muestras y el identificador de entorno (p.ej. un perfil concreto de Windows). El uso de este tipo de servicios está sujeto a sus términos y condiciones (cuotas, uso académico, privacidad de muestras, etc.), que deben respetarse en cualquier despliegue real.

En despliegues reales (por ejemplo, en Azure), estas variables deben definirse en el mecanismo de configuración de la plataforma (Application Settings, variables del contenedor, etc.), nunca en el código fuente.

---

## Uso de VirusTotal y límites de la API

La integración con VirusTotal se realiza **exclusivamente por hash SHA256**, es decir, la plataforma no sube los ficheros, sólo consulta si ya existen en VirusTotal y cuáles han sido los resultados de su último análisis.

Aspectos importantes:

- La API pública de VirusTotal tiene **límites estrictos de uso** (peticiones por minuto/día) y está pensada para uso ligero o académico. Las cuotas exactas dependen del plan contratado y pueden cambiar con el tiempo; para un uso intensivo es necesario un acuerdo comercial con VirusTotal.
- Si no se configura `VIRUSTOTAL_API_KEY`, el módulo de análisis devuelve `status = "not_configured"` y el resto del pipeline continúa funcionando con normalidad.
- La plataforma detecta algunos estados específicos de la API:
	- `auth_error`: problemas de autenticación/autorización (API key inválida o sin permisos adecuados).
	- `rate_limited`: se ha alcanzado el límite de peticiones permitido para la API key actual (`HTTP 429`).
	- `error`: otros errores HTTP o de red.
	- `not_found`: el hash no figura en la base de datos de VirusTotal.
- Para evitar consultas repetidas sobre el mismo fichero, se mantiene una **caché ligera en memoria** por hash con un TTL configurable (`VIRUSTOTAL_CACHE_TTL_SECONDS`). Esto reduce el riesgo de agotar la cuota si se re-analizan repetidas veces las mismas evidencias.

En el informe HTML y en las exportaciones (JSON/PDF) se refleja el estado de VirusTotal de forma clara, de modo que el usuario pueda distinguir entre:

- Resultado válido con estadísticas de motores.
- Falta de datos (`not_found`).
- Integración desactivada o no configurada.
- Errores de credenciales o de límite de cuota.
