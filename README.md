# ForenAlyze

Web framework for **automated collection and analysis of forensic evidence**, developed as a
**Master’s Thesis (TFM)** in Information Security.

ForenAlyze allows an authenticated user to upload suspicious files (Office documents, PDFs,
executables, images, audio, etc.), trigger a **forensic analysis pipeline**, and review the
results from a polished web interface, with emphasis on traceability and user experience.

---

## 1. Main features

### 1.1. User management and notifications

- Authentication with Flask‑Login (login/logout).
- Administrator user created via script (`create_admin.py`).
- Distinct user roles (admin / regular) with access control to views,
  logs, files, analyses, and YARA rules.
- Profile page with basic data editing and password change.
- User‑configurable avatar (stored in `app/static/avatars/`).
- User administration panel (admin only) to create accounts, reset
  other users’ passwords, and inspect the storage space used by
  each one.
- Notification bell in the top bar with counter and list of recent
  alerts (malware detected, reports ready, etc.).

### 1.2. Workflow

1. The user logs in.
2. They upload a file from the **Upload file** view.
3. The backend stores the evidence in `instance/uploads/` and creates the `File` record.
4. The **analysis pipeline** is launched in the background on that evidence.
5. When finished, an `Analysis` record is created, the file’s `final_verdict` is updated,
	and **alerts** are generated if applicable.
6. The user reviews the result from:
	- The **Dashboard** (latest analyses and KPIs).
	- The **Files & analyses** view (listings, filters, and report access).
	- The **detailed report** for each analysis (HTML, JSON, PDF).

### 1.3. File management

- Authenticated file uploads with extension and size validation (up to 100 MB).
- Support for office documents (DOC/DOCX/DOCM, XLS/XLSX/XLSM, PPT/PPTX/PPTM),
  executables, PDFs, images, and WAV.
- On‑disk storage with randomized internal filenames and full
  registration in the database.
- Per‑user storage quota configurable via `STORAGE_QUOTA_MB` and computation
  of used space.
- **Storage** section where the user can see their files, the space
  used, and delete evidence (also removing associated analyses
  and alerts).

### 1.4. Analysis pipeline (overview)

After each file upload, a background pipeline is executed that:

- Computes hashes (MD5, SHA1, SHA256), size, and MIME type of the file.
- Extracts basic metadata depending on the type (Office/PDF/images/audio).
- Runs antivirus analysis with ClamAV when available.
- Scans the file with configurable YARA rules (`YARA_ENABLED` / `YARA_RULES_PATH`).
- Optionally integrates VirusTotal lookups with in‑memory cache.
- Can extract text via Apache Tika for supported documents.
- Performs basic macro detection in Office documents.
- Applies simple checks for steganography and suspicious patterns.
- Analyzes audio files (metadata and spectrogram for WAV).
- Optionally invokes a dynamic sandbox hook (mock, sample file, or Hybrid Analysis).
- Consolidates all results into a normalized final verdict and an `Analysis` record
  that powers the HTML/JSON/PDF reports.

### 1.5. Alerts and dashboard (overview)

- `Alert` model associated with files and analyses.
- Automatic alert generation based on verdicts and findings.
- Dashboard with KPIs, charts, and a table of the latest analyzed files.
- `Log` model for auditing actions.

---

## 2. Overall architecture

- Python 3 + Flask (blueprints, application context).
- Flask‑Login for authentication.
- Flask‑SQLAlchemy + PostgreSQL as the database.
- Flask‑Migrate / Alembic for migrations.
- Jinja2 + Bootstrap 5 + Chart.js on the frontend.
- Optional forensic libraries: `oletools`, `yara`, `mutagen`, `Pillow`,
  `numpy`, `matplotlib`, `requests`.

Simplified project structure:

```text
ForenAlyze/
├─ run.py                 # Flask / Gunicorn entry point
├─ create_admin.py        # Creates admin user (admin/admin123)
├─ requirements.txt
├─ docker-compose.yml
├─ Dockerfile
├─ .env.example           # Configuration template
├─ app/
│  ├─ __init__.py         # create_app(), blueprint registration
│  ├─ config.py           # Config class (environment, VT, YARA, Tika, sandbox...)
│  ├─ extensions.py       # db, login_manager, migrate
│  ├─ models.py           # User, File, Analysis, Alert, Log, etc.
│  ├─ analysis/
│  │  ├─ dashboard.py     # Main routes (dashboard, files, logs, storage...)
│  │  ├─ pipeline.py      # Core analysis logic
│  │  └─ ...
│  ├─ auth/               # Authentication blueprint
│  ├─ templates/          # Jinja2 templates
│  └─ static/             # JS, CSS, avatars, spectrograms...
└─ instance/
   └─ uploads/            # Uploaded evidence (outside static)
```

---

## 3. Getting started from scratch

This section describes how to run ForenAlyze both in a
**local Python environment** and using **Docker Compose**.

### 3.1. Prerequisites

- Python 3.11 (or compatible) installed.
- Git.
- PostgreSQL 14+ (if you are going to run without Docker) **or** Docker + Docker Compose.

On Windows it is recommended to use PowerShell.

### 3.2. Clone the repository

```bash
git clone https://github.com/Javivi-MR/ForenAlyze.git
cd ForenAlyze
```

### 3.3. Environment configuration (.env)

1. Copy the example file:

   ```bash
   cp .env.example .env   # In PowerShell: copy .env.example .env
   ```

2. Edit `.env` and review at least these variables:

   - `SECRET_KEY` – change the value to a random one in production.
   - `DATABASE_URL` – PostgreSQL connection URI, for example:

     ```text
     postgresql+psycopg2://forenalyze:forenalyze@localhost:5432/forenalyze
     ```

   - `STORAGE_QUOTA_MB` – per‑user quota in MB (default 2048).
   - `CLAMAV_PATH` – if you have `clamscan` in the PATH, you can leave it empty.
   - `VIRUSTOTAL_API_KEY` – if you want to enable VirusTotal queries.
   - `YARA_ENABLED` / `YARA_RULES_PATH` – to enable YARA rules.
   - `TIKA_ENABLED`, `TIKA_SERVER_URL` – if you are going to use Apache Tika.
   - `SANDBOX_*` – only if you are going to test the sandbox / Hybrid Analysis hook.

### 3.4. Virtual environment and dependencies (local mode)

```bash
python -m venv venv
# On Linux / macOS
source venv/bin/activate
# On Windows PowerShell
venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

### 3.5. Database and migrations

#### 3.5.1. Create the PostgreSQL database

Create an empty database and a user matching your `DATABASE_URL`.
Example (psql):

```sql
CREATE DATABASE forenalyze;
CREATE USER forenalyze WITH PASSWORD 'forenalyze';
GRANT ALL PRIVILEGES ON DATABASE forenalyze TO forenalyze;
```

#### 3.5.2. Apply Alembic migrations

From the project root, with the virtual environment activated:

```bash
# Linux / macOS
export FLASK_APP=run.py
flask db upgrade

# Windows PowerShell
$env:FLASK_APP = "run.py"
flask db upgrade
```

This will create the entire schema defined in `migrations/`.

### 3.6. Create administrator user

Run the `create_admin.py` script once:

```bash
python create_admin.py
```

- If it does not exist, it will create the `admin` user with password `admin123`.
- If it already exists, it will display a message indicating so.

> For security reasons, it is recommended to change the default
> password for the `admin` user on the first login using the
> user profile screen.

### 3.7. Run the application locally

With the virtual environment active:

```bash
python run.py
```

By default, Flask starts on `http://127.0.0.1:5000` with `debug=True`.

Open your browser and log in with credentials `admin` / `admin123`.

---

## 4. Deployment with Docker Compose

The repository includes a `Dockerfile` and a `docker-compose.yml` to quickly
spin up a complete environment with PostgreSQL, Tika, and the web application.

### 4.1. Defined services

In `docker-compose.yml` the following services are defined:

- `postgres` – PostgreSQL 16 container.
- `tika` – `apache/tika:latest` container exposing port 9998.
- `web` – ForenAlyze application image based on `python:3.11-slim` with
  ClamAV installed and `gunicorn` listening on `0.0.0.0:8000`.

### 4.2. Environment variables in Docker

The `web` service already sets some default variables:

```yaml
environment:
  DATABASE_URL: postgresql+psycopg2://forenalyze:forenalyze@postgres:5432/forenalyze
  CLAMAV_PATH: clamscan
  SECRET_KEY: forenalyze-secret-key
  TIKA_ENABLED: "true"
  TIKA_SERVER_URL: http://tika:9998
```

You can complement them by adding a `.env` file or additional
environment variables as needed.

### 4.3. Build and start services

From the project root:

```bash
docker-compose up --build
```

This will start PostgreSQL, Tika, and the application. The first time you
will need to apply the migrations inside the `web` container:

```bash
# In another terminal
docker-compose run --rm web flask db upgrade
```

After that, with `docker-compose up` the schema will already exist.

The application will be available at `http://127.0.0.1:8000`.

> To create the administrator user inside the container you can run:
>
> ```bash
> docker-compose run --rm web python create_admin.py
> ```

---

## 5. Advanced configuration

### 5.1. VirusTotal

- Make sure you have a valid API key and respect the usage limits.
- Set `VIRUSTOTAL_API_KEY` and optionally adjust:
  - `VIRUSTOTAL_ENABLED` (`true`/`false`).
  - `VIRUSTOTAL_CACHE_TTL_SECONDS` for the in‑memory cache.
- The HTML report clearly indicates the integration status
  (valid data, not configured, rate‑limited, etc.).

### 5.2. YARA and external rules

- Install the `yara` (or `yara-python`) library in the environment.
- Enable the module with:

  ```env
  YARA_ENABLED=true
  YARA_RULES_PATH=/path/to/my/rules
  ```

- `YARA_RULES_PATH` can point to:
  - A single rules file (`forenalyze.yar`).
  - A directory with multiple rule files.
- From the **YARA rules** interface (read‑only for all users,
  full management for administrators only) you can:
  - View the current list.
  - Upload new files (directory mode).
  - Edit a file directly from the browser.
  - Delete individual files (directory mode).

To use external rules such as `Neo23x0/signature-base` it is recommended to:

1. Clone that repository **outside** ForenAlyze (to avoid nested repositories).
2. Point `YARA_RULES_PATH` to the appropriate subdirectory (e.g. `.../signature-base/yara`).
3. Document in the thesis the origin and license of those rules.

### 5.3. Apache Tika

- The `tika` container in `docker-compose.yml` exposes the server on port `9998`.
- For a non‑Docker deployment, you can start Tika Server manually and
  set `TIKA_SERVER_URL` to the corresponding URL.
- `TIKA_MAX_TEXT_CHARS` controls the maximum number of characters stored
  in the database for each document’s extracted text (default 20,000).

### 5.4. Sandbox / Hybrid Analysis

The project implements a **generic hook** for dynamic sandboxing:

- `SANDBOX_ENABLED=true` activates the integration.
- `SANDBOX_MODE` defines the operating mode:
  - `disabled` – off.
  - `mock` – generates synthetic results for the demo.
  - `file` – reads a sample JSON from `SANDBOX_MOCK_RESULT_PATH`.
  - `hybrid_analysis` – integrates with Hybrid Analysis / Falcon Sandbox via API.

When `SANDBOX_MODE=hybrid_analysis`, the following are also used:

- `HYBRID_ANALYSIS_API_KEY`
- `HYBRID_ANALYSIS_API_URL`
- `HYBRID_ANALYSIS_PUBLIC_URL`
- `HYBRID_ANALYSIS_ENV_ID`

In the HTML report, a **Sandbox / dynamic analysis** card is displayed with
`score`, `verdict`, family, tags, and, when available, a button to open the
remote report in Hybrid Analysis.

---

## 6. Security and privacy

- The project is oriented to an **academic / lab** context.
- It does not replace certified forensic tools or commercial products.
- Responsibility for using external services (VirusTotal, Hybrid
  Analysis, etc.) and handling evidence lies with the operator.
- Uploading evidence containing personal or sensitive data to
  external services is not recommended without carefully reviewing
  their policies.

---

## 7. License and credits

- ForenAlyze’s source code is published under the license indicated in `LICENSE`.
- YARA rules, AV signatures, and external services (VirusTotal, Hybrid Analysis,
  public rule sets such as `signature-base`, etc.) have their own licenses and
  terms of use that must be respected separately.

If you use this project as a basis for other academic work, it is
recommended to cite the thesis document and this repository.
