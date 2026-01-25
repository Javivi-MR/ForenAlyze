# ForenAlyze

Plataforma web para **recogida y análisis automatizado de evidencias forenses**, desarrollada como
**Trabajo Fin de Máster (TFM)** en Seguridad Informática.

ForenAlyze permite a un usuario autenticado subir ficheros sospechosos (documentos Office, PDF,
ejecutables, imágenes, audio, etc.), lanzar un **pipeline de análisis forense** y consultar los
resultados desde una interfaz web cuidada, con énfasis en trazabilidad y experiencia de uso.

---

## 1. Funcionalidades principales

### 1.1. Gestión de usuarios y notificaciones

- Autenticación con Flask‑Login (login/logout).
- Usuario administrador creado mediante script (`create_admin.py`).
- Roles diferenciados de usuario (admin / normal) con control de acceso
  a vistas, logs, ficheros, análisis y reglas YARA.
- Perfil con edición de datos básicos y cambio de contraseña.
- Avatar configurable por usuario (almacenado en `app/static/avatars/`).
- Panel de administración de usuarios (sólo admin) para crear cuentas,
  resetear contraseñas de otros usuarios y consultar el espacio de
  almacenamiento utilizado por cada uno.
- Campana de notificaciones en la barra superior con contador y listado de alertas
  recientes (malware detectado, informes listos, etc.).

### 1.2. Flujo de trabajo

1. El usuario inicia sesión.
2. Sube un fichero desde la vista **Upload file**.
3. El backend almacena la evidencia en `instance/uploads/` y crea el registro `File`.
4. Se lanza en segundo plano el **pipeline de análisis** sobre esa evidencia.
5. Al finalizar, se crea un registro `Analysis`, se actualiza el `final_verdict` del fichero
	y se generan **alertas** si procede.
6. El usuario consulta el resultado desde:
	- El **Dashboard** (últimos análisis y KPIs).
	- La vista **Files & analyses** (listados, filtros y acceso al informe).
	- El **informe detallado** de cada análisis (HTML, JSON, PDF).

### 1.3. Gestión de ficheros

- Subida de ficheros autenticada con validación de extensión y tamaño (hasta 100 MB).
- Soporte para ficheros ofimáticos (DOC/DOCX/DOCM, XLS/XLSX/XLSM, PPT/PPTX/PPTM),
  ejecutables, PDF, imágenes y WAV.
- Almacenamiento en disco con nombres internos aleatorizados y registro completo
  en base de datos.
- Cuota de almacenamiento configurable por usuario (`STORAGE_QUOTA_MB`) y cálculo
  del espacio usado.
- Sección de **Storage** donde el usuario puede ver sus ficheros, el espacio
  ocupado y eliminar evidencias (borrando también análisis y alertas asociadas).

### 1.4. Pipeline de análisis (resumen)

Tras la subida de cada fichero se ejecuta en segundo plano un pipeline que:

- Calcula hashes (MD5, SHA1, SHA256), tamaño y tipo MIME del fichero.
- Extrae metadatos básicos según el tipo (Office/PDF/imágenes/audio).
- Lanza un análisis antivirus con ClamAV cuando está disponible.
- Escanea el fichero con reglas YARA configurables (`YARA_ENABLED` / `YARA_RULES_PATH`).
- Integra, si se configura, consultas a VirusTotal con caché en memoria.
- Puede extraer texto mediante Apache Tika para documentos soportados.
- Realiza detección básica de macros en documentos Office.
- Aplica comprobaciones sencillas de esteganografía y patrones sospechosos.
- Analiza ficheros de audio (metadatos y espectrograma para WAV).
- Invoca opcionalmente un hook de sandbox dinámico (mock, fichero de ejemplo o Hybrid Analysis).
- Consolida todos los resultados en un veredicto final normalizado y en un registro `Analysis`
  que alimenta los informes HTML/JSON/PDF.

### 1.5. Alertas y dashboard (resumen)

- Modelo `Alert` asociado a ficheros y análisis.
- Generación automática de alertas según veredictos y hallazgos.
- Dashboard con KPIs, gráficas y tabla de últimos ficheros analizados.
- Modelo `Log` para auditoría de acciones.

---

## 2. Arquitectura general

- Python 3 + Flask (blueprints, contexto de aplicación).
- Flask‑Login para autenticación.
- Flask‑SQLAlchemy + PostgreSQL como base de datos.
- Flask‑Migrate / Alembic para migraciones.
- Jinja2 + Bootstrap 5 + Chart.js en el frontend.
- Librerías forenses opcionales: `oletools`, `yara`, `mutagen`, `Pillow`,
  `numpy`, `matplotlib`, `requests`.

Estructura simplificada del proyecto:

```text
ForenAlyze/
├─ run.py                 # Punto de entrada Flask / Gunicorn
├─ create_admin.py        # Crea usuario admin (admin/admin123)
├─ requirements.txt
├─ docker-compose.yml
├─ Dockerfile
├─ .env.example           # Plantilla de configuración
├─ app/
│  ├─ __init__.py         # create_app(), registro de blueprints
│  ├─ config.py           # Clase Config (entorno, VT, YARA, Tika, sandbox...)
│  ├─ extensions.py       # db, login_manager, migrate
│  ├─ models.py           # User, File, Analysis, Alert, Log, etc.
│  ├─ analysis/
│  │  ├─ dashboard.py     # Rutas principales (dashboard, files, logs, storage...)
│  │  ├─ pipeline.py      # Lógica principal de análisis
│  │  └─ ...
│  ├─ auth/               # Blueprint de autenticación
│  ├─ templates/          # Plantillas Jinja2
│  └─ static/             # JS, CSS, avatars, espectrogramas...
└─ instance/
   └─ uploads/            # Evidencias subidas (fuera de static)
```

---

## 3. Puesta en marcha desde cero

A continuación se describe cómo arrancar ForenAlyze tanto en un entorno
**local con Python** como usando **Docker Compose**.

### 3.1. Prerrequisitos

- Python 3.11 (o compatible) instalado.
- Git.
- PostgreSQL 14+ (si vas a ejecutar sin Docker) **o** Docker + Docker Compose.

En Windows se recomienda usar PowerShell.

### 3.2. Clonar el repositorio

```bash
git clone https://github.com/Javivi-MR/ForenAlyze.git
cd ForenAlyze
```

### 3.3. Configuración de entorno (.env)

1. Copia el fichero de ejemplo:

   ```bash
   cp .env.example .env   # En PowerShell: copy .env.example .env
   ```

2. Edita `.env` y revisa al menos estas variables:

   - `SECRET_KEY` – cambia el valor por uno aleatorio en producción.
   - `DATABASE_URL` – URI de conexión a PostgreSQL, por ejemplo:

     ```text
     postgresql+psycopg2://forenalyze:forenalyze@localhost:5432/forenalyze
     ```

   - `STORAGE_QUOTA_MB` – cuota por usuario en MB (por defecto 2048).
   - `CLAMAV_PATH` – si tienes `clamscan` en el PATH, puedes dejarlo vacío.
   - `VIRUSTOTAL_API_KEY` – si quieres activar consultas a VirusTotal.
   - `YARA_ENABLED` / `YARA_RULES_PATH` – para activar reglas YARA.
   - `TIKA_ENABLED`, `TIKA_SERVER_URL` – si vas a usar Apache Tika.
   - `SANDBOX_*` – sólo si vas a probar el hook de sandbox / Hybrid Analysis.

### 3.4. Entorno virtual y dependencias (modo local)

```bash
python -m venv venv
# En Linux / macOS
source venv/bin/activate
# En Windows PowerShell
venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

### 3.5. Base de datos y migraciones

#### 3.5.1. Crear la base de datos PostgreSQL

Crea una base de datos vacía y un usuario que coincidan con tu `DATABASE_URL`.
Ejemplo (psql):

```sql
CREATE DATABASE forenalyze;
CREATE USER forenalyze WITH PASSWORD 'forenalyze';
GRANT ALL PRIVILEGES ON DATABASE forenalyze TO forenalyze;
```

#### 3.5.2. Aplicar migraciones Alembic

Desde la raíz del proyecto, con el entorno virtual activado:

```bash
# Linux / macOS
export FLASK_APP=run.py
flask db upgrade

# Windows PowerShell
$env:FLASK_APP = "run.py"
flask db upgrade
```

Esto creará todo el esquema definido en `migrations/`.

### 3.6. Crear usuario administrador

Ejecuta una vez el script `create_admin.py`:

```bash
python create_admin.py
```

- Si no existe, creará el usuario `admin` con contraseña `admin123`.
- Si ya existe, mostrará un mensaje indicándolo.

> Por motivos de seguridad, se recomienda cambiar la contraseña
> por defecto del usuario `admin` en el primer inicio de sesión
> utilizando la pantalla de perfil de usuario.

### 3.7. Ejecutar la aplicación en local

Con el entorno virtual activo:

```bash
python run.py
```

Por defecto Flask arranca en `http://127.0.0.1:5000` con `debug=True`.

Accede en el navegador y entra con las credenciales `admin` / `admin123`.

---

## 4. Despliegue con Docker Compose

El repositorio incluye un `Dockerfile` y un `docker-compose.yml` para levantar
rápidamente un entorno completo con PostgreSQL, Tika y la aplicación web.

### 4.1. Servicios definidos

En `docker-compose.yml` se definen:

- `postgres` – Contenedor PostgreSQL 16.
- `tika` – Contenedor `apache/tika:latest` exponiendo el puerto 9998.
- `web` – Imagen de la aplicación ForenAlyze basada en `python:3.11-slim` con
  ClamAV instalado y `gunicorn` escuchando en `0.0.0.0:8000`.

### 4.2. Variables de entorno en Docker

El servicio `web` ya establece algunas variables por defecto:

```yaml
environment:
  DATABASE_URL: postgresql+psycopg2://forenalyze:forenalyze@postgres:5432/forenalyze
  CLAMAV_PATH: clamscan
  SECRET_KEY: forenalyze-secret-key
  TIKA_ENABLED: "true"
  TIKA_SERVER_URL: http://tika:9998
```

Puedes complementarlas añadiendo un fichero `.env` o variables adicionales
según tus necesidades.

### 4.3. Construir e iniciar servicios

Desde la raíz del proyecto:

```bash
docker-compose up --build
```

Esto levantará PostgreSQL, Tika y la aplicación. La primera vez deberás aplicar
las migraciones dentro del contenedor `web`:

```bash
# En otra terminal
docker-compose run --rm web flask db upgrade
```

A partir de ahí, con `docker-compose up` el esquema ya estará creado.

La aplicación quedará accesible en `http://127.0.0.1:8000`.

> Para crear el usuario administrador dentro del contenedor puedes ejecutar:
>
> ```bash
> docker-compose run --rm web python create_admin.py
> ```

---

## 5. Configuración avanzada

### 5.1. VirusTotal

- Asegúrate de contar con una API key válida y respetar los límites de uso.
- Establece `VIRUSTOTAL_API_KEY` y, opcionalmente, ajusta:
  - `VIRUSTOTAL_ENABLED` (`true`/`false`).
  - `VIRUSTOTAL_CACHE_TTL_SECONDS` para la caché en memoria.
- El informe HTML indica claramente el estado de la integración
  (datos válidos, no configurado, rate‑limit, etc.).

### 5.2. YARA y reglas externas

- Instala la librería `yara` (o `yara-python`) en el entorno.
- Activa el módulo con:

  ```env
  YARA_ENABLED=true
  YARA_RULES_PATH=/ruta/a/mis/reglas
  ```

- `YARA_RULES_PATH` puede apuntar a:
  - Un único fichero de reglas (`forenalyze.yar`).
  - Un directorio con múltiples ficheros de reglas.
- Desde la interfaz **YARA rules** (lectura para todos los usuarios,
  gestión completa sólo para administradores) puedes:
  - Ver el listado actual.
  - Subir nuevos ficheros (modo directorio).
  - Editar un fichero desde el navegador.
  - Eliminar ficheros individuales (modo directorio).

Para utilizar reglas externas como `Neo23x0/signature-base` se recomienda:

1. Clonar ese repositorio **fuera** de ForenAlyze (para no anidar repositorios).
2. Apuntar `YARA_RULES_PATH` al subdirectorio adecuado (p.ej. `.../signature-base/yara`).
3. Documentar en la memoria del TFM la procedencia y licencia de dichas reglas.

### 5.3. Apache Tika

- El contenedor `tika` del `docker-compose.yml` expone el servidor en `9998`.
- Para un despliegue sin Docker puedes arrancar Tika Server manualmente y
  apuntar `TIKA_SERVER_URL` a la URL correspondiente.
- `TIKA_MAX_TEXT_CHARS` controla el máximo de caracteres de texto que se guardan
  en base de datos para cada documento (por defecto 20 000).

### 5.4. Sandbox / Hybrid Analysis

El proyecto implementa un **hook genérico** para sandbox dinámico:

- `SANDBOX_ENABLED=true` activa la integración.
- `SANDBOX_MODE` define el modo de operación:
  - `disabled` – apagado.
  - `mock` – genera resultados sintéticos para la demo.
  - `file` – lee un JSON de ejemplo desde `SANDBOX_MOCK_RESULT_PATH`.
  - `hybrid_analysis` – integra con Hybrid Analysis / Falcon Sandbox vía API.

Cuando `SANDBOX_MODE=hybrid_analysis` se usan además:

- `HYBRID_ANALYSIS_API_KEY`
- `HYBRID_ANALYSIS_API_URL`
- `HYBRID_ANALYSIS_PUBLIC_URL`
- `HYBRID_ANALYSIS_ENV_ID`

En el informe HTML aparece una tarjeta **Sandbox / dynamic analysis** con el
`score`, `verdict`, familia, tags y, cuando existe, un botón para abrir el
informe remoto en Hybrid Analysis.

---

## 6. Seguridad y privacidad

- El proyecto está orientado a un contexto **académico / de laboratorio**.
- No sustituye herramientas forenses certificadas ni productos comerciales.
- La responsabilidad sobre el uso de servicios externos (VirusTotal, Hybrid
  Analysis, etc.) y el tratamiento de las evidencias recae en el operador.
- No se recomienda subir evidencias con datos personales o sensibles a
  servicios externos sin haber revisado cuidadosamente sus políticas.

---

## 7. Licencia y créditos

- El código de ForenAlyze se publica con la licencia indicada en `LICENSE`.
- Las reglas YARA, firmas AV y servicios externos (VirusTotal, Hybrid Analysis,
  conjuntos de reglas públicos como `signature-base`, etc.) tienen sus propias
  licencias y términos de uso que deben respetarse por separado.

Si utilizas este proyecto como base para otros trabajos académicos, se
recomienda citar la memoria del TFM y el repositorio original.
