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
    SECRET_KEY = os.environ.get("SECRET_KEY", "forenhub-secret-key")
    SQLALCHEMY_DATABASE_URI = "sqlite:///forenhub.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # API key de VirusTotal: primero variable de entorno, luego pyvenv.cfg
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") or _load_virustotal_key_from_venv()
