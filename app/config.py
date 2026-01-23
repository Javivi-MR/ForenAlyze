import os
import sys


def _load_virustotal_key_from_venv() -> str | None:
    """Intenta leer la API key de VirusTotal desde pyvenv.cfg del venv.

    Esto permite que la clave funcione tal y como la tienes ahora
    (línea virustotal_api_key en venv/pyvenv.cfg), incluso si no
    has exportado la variable de entorno.
    """

    prefix = getattr(sys, "prefix", None)
    if not prefix:
        return None

    cfg_path = os.path.join(prefix, "pyvenv.cfg")
    if not os.path.exists(cfg_path):
        return None

    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("virustotal_api_key"):
                    # formato: virustotal_api_key = valor
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except OSError:
        return None

    return None


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "forenalyze-secret-key")
    # URI de base de datos: por defecto PostgreSQL en local, configurable por env
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://forenalyze:forenalyze@localhost:5432/forenalyze",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Cuota de almacenamiento por defecto (por usuario) en MB
    STORAGE_QUOTA_MB = int(os.environ.get("STORAGE_QUOTA_MB", "2048"))

    # API key de VirusTotal: primero variable de entorno, luego pyvenv.cfg
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") or _load_virustotal_key_from_venv()
    # Permite desactivar completamente las consultas a VirusTotal desde configuración
    VIRUSTOTAL_ENABLED = os.environ.get("VIRUSTOTAL_ENABLED", "true").lower() in {"1", "true", "yes"}
    # TTL de caché en memoria para respuestas de VirusTotal (en segundos)
    VIRUSTOTAL_CACHE_TTL_SECONDS = int(os.environ.get("VIRUSTOTAL_CACHE_TTL_SECONDS", "3600"))

    # Ruta opcional a clamscan/clamscan.exe. Si no se define, se usará
    # simplemente "clamscan" y se dependerá del PATH del sistema.
    CLAMAV_PATH = os.environ.get("CLAMAV_PATH")

    # Configuración de YARA (si está instalada la librería)
    # Se activa con YARA_ENABLED=true y se indica ruta de reglas en YARA_RULES_PATH
    YARA_ENABLED = os.environ.get("YARA_ENABLED", "false").lower() in {"1", "true", "yes"}
    YARA_RULES_PATH = os.environ.get("YARA_RULES_PATH")

    # Configuración de integración con sandbox dinámico (p.ej. Cuckoo)
    # Para el TFM se implementa como un "hook" configurable que puede
    # operar en modo desactivado, modo mock (PoC) o modo externo.
    SANDBOX_ENABLED = os.environ.get("SANDBOX_ENABLED", "false").lower() in {"1", "true", "yes"}
    # SANDBOX_MODE puede ser, por ejemplo: "disabled", "mock", "file" o
    # "hybrid_analysis" (envío a Hybrid Analysis / Falcon Sandbox vía API).
    SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "disabled").lower()
    # Ruta opcional a un fichero JSON con resultados de sandbox para
    # demostraciones offline (PoC). No se usa en producción real.
    SANDBOX_MOCK_RESULT_PATH = os.environ.get("SANDBOX_MOCK_RESULT_PATH")

    # Configuración específica para integración remota con Hybrid Analysis
    # (Falcon Sandbox). Se usa cuando SANDBOX_MODE="hybrid_analysis".
    #
    #   HYBRID_ANALYSIS_API_KEY   -> API key del usuario (cuenta community o similar).
    #   HYBRID_ANALYSIS_API_URL   -> Endpoint base de la API (v2), normalmente
    #                                https://www.hybrid-analysis.com/api/v2
    #   HYBRID_ANALYSIS_PUBLIC_URL -> URL pública para visualizar muestras,
    #                                 normalmente https://www.hybrid-analysis.com
    #   HYBRID_ANALYSIS_ENV_ID    -> ID numérico de entorno (p.ej. 100 para
    #                                determinado perfil de Windows). El valor
    #                                exacto depende de la cuenta y la
    #                                documentación de Hybrid Analysis.
    HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
    HYBRID_ANALYSIS_API_URL = os.environ.get(
        "HYBRID_ANALYSIS_API_URL",
        "https://hybrid-analysis.com/api/v2",
    )
    HYBRID_ANALYSIS_PUBLIC_URL = os.environ.get(
        "HYBRID_ANALYSIS_PUBLIC_URL",
        "https://www.hybrid-analysis.com",
    )
    HYBRID_ANALYSIS_ENV_ID = os.environ.get("HYBRID_ANALYSIS_ENV_ID", "")

    # Integración con Apache Tika para extracción de texto/metadatos
    # desde documentos (PDF, Office, etc.). Requiere un Tika Server
    # accesible vía HTTP (por ejemplo, en http://localhost:9998).
    TIKA_ENABLED = os.environ.get("TIKA_ENABLED", "false").lower() in {"1", "true", "yes"}
    TIKA_SERVER_URL = os.environ.get("TIKA_SERVER_URL", "http://localhost:9998")
    # Timeout para las peticiones al servidor Tika (en segundos).
    TIKA_TIMEOUT_SECONDS = int(os.environ.get("TIKA_TIMEOUT_SECONDS", "30"))
    # Límite máximo de caracteres de texto que se conservarán en
    # additional_results para no inflar en exceso la base de datos.
    TIKA_MAX_TEXT_CHARS = int(os.environ.get("TIKA_MAX_TEXT_CHARS", "20000"))
