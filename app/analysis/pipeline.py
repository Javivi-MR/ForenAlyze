"""Pipeline de análisis de ficheros para Forenalyze.

Este módulo implementa el análisis básico solicitado:

- Cálculo de hashes (MD5, SHA1, SHA256)
- Detección de tipo MIME
- Extracción ligera de metadatos
- Análisis antivirus (ClamAV, si está disponible)
- Escaneo con reglas YARA (si están configuradas)
- Detección básica de macros
- Detección muy básica de esteganografía
- Análisis de ficheros de audio

La función principal es `analyze_file`, que devuelve un diccionario
listo para persistir en el modelo Analysis.
"""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import os
import re
import string
import subprocess
import wave
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import current_app

import time

import requests


try:  # type: ignore[unused-ignore]
    import yara  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    yara = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    # oletools/olevba para análisis de macros en documentos Office
    from oletools.olevba import VBA_Parser, VBA_Scanner  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    VBA_Parser = None  # type: ignore[assignment]
    VBA_Scanner = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    from mutagen import File as MutagenFile  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    MutagenFile = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    from PIL import Image, ExifTags  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    Image = None  # type: ignore[assignment]
    ExifTags = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    import matplotlib

    # Usamos un backend no interactivo para evitar problemas con Tkinter
    # en hilos en background ("main thread is not in main loop").
    matplotlib.use("Agg")
    import numpy as np  # type: ignore[import]
    import matplotlib.pyplot as plt  # type: ignore[import]
except Exception:  # pragma: no cover - dependencias opcionales para espectrogramas
    np = None  # type: ignore[assignment]
    plt = None  # type: ignore[assignment]


@dataclass
class YaraConfig:
    enabled: bool
    rules_path: Optional[Path]


def _run_sandbox(path: Path, mime_type: str) -> Dict[str, Any] | None:
    """Hook de integración con sandbox dinámico (p.ej. Cuckoo).

    Para este TFM se implementa como un punto de extensión bien
    definido que puede trabajar en tres modos principales, según la
    configuración de ``current_app.config``:

    - SANDBOX_ENABLED = false  -> devuelve ``None`` y no afecta al
      veredicto (modo desactivado, comportamiento actual).
    - SANDBOX_ENABLED = true y SANDBOX_MODE = "mock" -> genera un
      resultado sintético a partir del tipo de fichero para mostrar
      cómo se integrarían score y etiquetas de sandbox en los
      informes HTML/JSON/PDF.
        - SANDBOX_ENABLED = true y SANDBOX_MODE = "file" -> intenta leer
            un fichero JSON de ejemplo desde SANDBOX_MOCK_RESULT_PATH, que
            puede contener la salida real de una ejecución de Cuckoo u otra
            sandbox externa. Esto permite una PoC offline reutilizando
            resultados capturados previamente.

        - SANDBOX_ENABLED = true y SANDBOX_MODE = "hybrid_analysis" ->
            envía el fichero a un servicio remoto Hybrid Analysis / Falcon
            Sandbox usando su API HTTP (cuenta community con API key) y
            adjunta en los metadatos la URL del informe público.

    El contrato de salida está pensado para mapearse de forma
    directa a los campos ``sandbox_score`` y
    ``additional_results['sandbox']`` en el modelo Analysis:

    {
        "status": "disabled" | "mock" | "ok" | "error" | "submitted",
        "engine": "cuckoo" | "hybrid-analysis" | "other",
        "score": float | None,
        "summary": str,
        "malware_family": str | None,
        "tags": list[str],
        "raw": dict | None,  # resultado original de la sandbox
        # Campos opcionales adicionales para integraciones remotas
        # (por ejemplo Hybrid Analysis):
        # "job_id": str | None,
        # "sha256": str | None,
        # "report_url": str | None,
    }
    """

    cfg = current_app.config if current_app else {}
    if not cfg.get("SANDBOX_ENABLED", False):
        return None

    mode = str(cfg.get("SANDBOX_MODE", "disabled") or "disabled").lower()
    engine_name = "cuckoo"

    # Modo completamente desactivado aunque SANDBOX_ENABLED sea true
    if mode in {"disabled", "off", "none"}:
        return {
            "status": "disabled",
            "engine": engine_name,
            "score": None,
            "summary": "Dynamic sandbox integration is configured as disabled.",
            "malware_family": None,
            "tags": [],
            "raw": None,
        }

    # Modo mock: resultado sintético basado en tipo de fichero.
    if mode == "mock":
        ext = path.suffix.lower()
        base_summary = "Sandbox mock result for demonstration purposes only."
        score: float | None = None
        tags: list[str] = []

        if ext in {".exe", ".dll"}:
            score = 8.2
            tags = ["pe", "executable", "network-activity"]
        elif ext in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"}:
            score = 6.5
            tags = ["office", "macro-potential"]
        elif ext in {".pdf"}:
            score = 4.0
            tags = ["pdf", "document"]
        else:
            score = 2.0
            tags = ["generic"]

        return {
            "status": "mock",
            "engine": engine_name,
            "score": float(score) if score is not None else None,
            "summary": base_summary,
            "malware_family": None,
            "tags": tags,
            "raw": None,
        }

    # Modo "file": PoC leyendo un JSON de ejemplo desde disco.
    if mode == "file":
        path_cfg = cfg.get("SANDBOX_MOCK_RESULT_PATH")
        if not path_cfg:
            return {
                "status": "error",
                "engine": engine_name,
                "score": None,
                "summary": "SANDBOX_MOCK_RESULT_PATH is not configured.",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        json_path = Path(path_cfg)
        if not json_path.exists():
            return {
                "status": "error",
                "engine": engine_name,
                "score": None,
                "summary": f"Sandbox mock result file not found: {json_path}",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        try:
            raw_data = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - E/S demo
            return {
                "status": "error",
                "engine": engine_name,
                "score": None,
                "summary": f"Failed to parse sandbox mock JSON: {exc}",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        # Intentamos extraer algunos campos típicos de Cuckoo-like JSON.
        score_val = None
        family = None
        tags: list[str] = []

        if isinstance(raw_data, dict):
            score_val = raw_data.get("score") or raw_data.get("info", {}).get("score")
            family = raw_data.get("malware_family") or raw_data.get("signature_family")
            tags_val = raw_data.get("tags") or raw_data.get("signatures")
            if isinstance(tags_val, list):
                # Si vienen firmas completas, extraemos nombres
                if tags_val and isinstance(tags_val[0], dict) and "name" in tags_val[0]:
                    tags = [str(s.get("name")) for s in tags_val if isinstance(s, dict)]
                else:
                    tags = [str(t) for t in tags_val]

        try:
            score_f = float(score_val) if score_val is not None else None
        except Exception:
            score_f = None

        return {
            "status": "ok",
            "engine": engine_name,
            "score": score_f,
            "summary": "Sandbox result loaded from JSON file (PoC mode).",
            "malware_family": family,
            "tags": tags,
            "raw": raw_data if isinstance(raw_data, dict) else None,
        }

    # Modo remoto: envío del fichero a Hybrid Analysis / Falcon Sandbox
    # usando su API HTTP. Este modo está pensado para integrarse con
    # una cuenta community, respetando sus límites y términos de uso.
    if mode in {"hybrid_analysis", "hybrid-analysis", "hybrid"}:
        api_key = cfg.get("HYBRID_ANALYSIS_API_KEY")
        api_url = str(cfg.get("HYBRID_ANALYSIS_API_URL") or "").strip()
        public_url = str(cfg.get("HYBRID_ANALYSIS_PUBLIC_URL") or "").strip()
        env_id = str(cfg.get("HYBRID_ANALYSIS_ENV_ID") or "").strip()

        if not api_key:
            return {
                "status": "error",
                "engine": "hybrid-analysis",
                "score": None,
                "summary": "Hybrid Analysis API key is not configured.",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        if not api_url:
            return {
                "status": "error",
                "engine": "hybrid-analysis",
                "score": None,
                "summary": "HYBRID_ANALYSIS_API_URL is not configured.",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        # Normalizamos la URL base para evitar diferencias entre
        # https://www.hybrid-analysis.com y https://hybrid-analysis.com,
        # usando siempre esta última, que es la que muestra la OpenAPI
        if "://www.hybrid-analysis.com" in api_url:
            api_url = api_url.replace("://www.hybrid-analysis.com", "://hybrid-analysis.com")

        # environment_id es obligatorio según la documentación de la
        # API v2; si no está configurado, devolvemos error explícito
        # en lugar de enviar una petición incompleta.
        if not env_id:
            return {
                "status": "error",
                "engine": "hybrid-analysis",
                "score": None,
                "summary": "HYBRID_ANALYSIS_ENV_ID is not configured (environment_id is required by Hybrid Analysis API).",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        submit_url = api_url.rstrip("/") + "/submit/file"
        headers = {
            "api-key": api_key,
            "accept": "application/json",
            "user-agent": str(cfg.get("HYBRID_ANALYSIS_USER_AGENT") or "Forenalyze-TFM"),
        }

        data: dict[str, str] = {"environment_id": env_id}

        try:
            with path.open("rb") as fh:  # pragma: no cover - E/S remota
                files = {"file": (path.name, fh)}
                resp = requests.post(
                    submit_url,
                    headers=headers,
                    files=files,
                    data=data,
                    timeout=60,
                )
        except Exception as exc:  # pragma: no cover - errores de red/API
            return {
                "status": "error",
                "engine": "hybrid-analysis",
                "score": None,
                "summary": f"Error submitting file to Hybrid Analysis: {exc}",
                "malware_family": None,
                "tags": [],
                "raw": None,
            }

        if not resp.ok:
            detail = (resp.text or "")[:500]
            return {
                "status": "error",
                "engine": "hybrid-analysis",
                "score": None,
                "summary": f"Hybrid Analysis API returned HTTP {resp.status_code}.",
                "malware_family": None,
                "tags": ["hybrid-analysis"],
                "raw": {"http_status": resp.status_code, "detail": detail},
            }

        try:
            raw_resp = resp.json()
        except Exception:  # pragma: no cover
            raw_resp = None

        job_id = None
        sample_sha256 = None
        if isinstance(raw_resp, dict):
            job_id = raw_resp.get("job_id") or raw_resp.get("id")
            sample_sha256 = raw_resp.get("sha256") or raw_resp.get("sha2")

        report_url = None
        if sample_sha256:
            base_public = public_url or "https://www.hybrid-analysis.com"
            report_url = base_public.rstrip("/") + f"/sample/{sample_sha256}"

        tags: list[str] = ["hybrid-analysis"]
        if env_id:
            tags.append(f"env:{env_id}")

        # Intentamos obtener un pequeño resumen adicional del
        # análisis usando el endpoint de Overview de Hybrid
        # Analysis. Esto permite mostrar en Forenalyze algunos
        # datos ligeros (p.ej. score/veredicto) sin necesidad de que
        # el usuario abra siempre la sandbox en otra pestaña.
        overview_data: dict[str, Any] | None = None
        verdict: str | None = None
        threat_score: float | None = None

        if sample_sha256:
            overview_url = api_url.rstrip("/") + f"/overview/{sample_sha256}/summary"
            try:  # pragma: no cover - llamada HTTP remota
                oresp = requests.get(
                    overview_url,
                    headers=headers,
                    timeout=30,
                )
                if oresp.ok:
                    try:
                        parsed = oresp.json()
                    except Exception:
                        parsed = None
                    if isinstance(parsed, dict):
                        overview_data = parsed
            except Exception:
                # Si falla el overview no rompemos el análisis
                overview_data = None

        if isinstance(overview_data, dict):
            # Algunos despliegues exponen un campo "verdict" o
            # "threat_level" con una etiqueta tipo
            # "suspicious"/"malicious"/"clean".
            v = overview_data.get("verdict") or overview_data.get("threat_level")
            verdict = str(v) if v is not None else None

            # La API suele exponer un score numérico (e.g.
            # "threat_score"). Si existe e incluye un valor
            # convertible a float, lo usamos como sandbox_score.
            ts_val = overview_data.get("threat_score")
            try:
                if ts_val is not None:
                    threat_score = float(ts_val)
            except Exception:
                threat_score = None

        result: dict[str, Any] = {
            "status": "submitted",
            "engine": "hybrid-analysis",
            "score": threat_score,
            "summary": "File submitted to Hybrid Analysis sandbox.",
            "malware_family": None,
            "tags": tags,
            "raw": raw_resp if isinstance(raw_resp, dict) else None,
            "job_id": job_id,
            "sha256": sample_sha256,
            "report_url": report_url,
        }

        if verdict:
            result["verdict"] = verdict
        if isinstance(overview_data, dict):
            result["overview"] = overview_data

        return result

    # Cualquier otro modo se trata como desactivado pero explícito.
    return {
        "status": "disabled",
        "engine": engine_name,
        "score": None,
        "summary": f"Sandbox mode '{mode}' is not implemented; integration point only.",
        "malware_family": None,
        "tags": [],
        "raw": None,
    }


def _compute_hashes(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as fh:  # pragma: no cover - E/S trivial
        for chunk in iter(lambda: fh.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _detect_mime(path: Path, mime_hint: str | None = None) -> str:
    if mime_hint:
        return mime_hint

    mime, _ = mimetypes.guess_type(str(path))
    return mime or "application/octet-stream"


def _run_clamav(path: Path) -> Dict[str, Any]:
    """Ejecuta clamscan si está disponible.

    Devuelve un dict con:
        status: clean / infected / error / not_available
        detail: texto con salida del comando
    """

    cfg = current_app.config if current_app else {}
    clam_path = cfg.get("CLAMAV_PATH") or "clamscan"

    try:
        proc = subprocess.run(
            [clam_path, "--stdout", "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {
            "status": "not_available",
            "detail": f"clamscan no encontrado (comando: {clam_path})",
        }
    except Exception as exc:  # pragma: no cover - errores raros de entorno
        return {"status": "error", "detail": f"error ejecutando clamscan: {exc}"}

    output = (proc.stdout or proc.stderr or "").strip()
    if "OK" in output and "FOUND" not in output:
        return {"status": "clean", "detail": output}
    if "FOUND" in output:
        return {"status": "infected", "detail": output}
    return {"status": "unknown", "detail": output}


def _load_yara_config() -> YaraConfig:
    """Carga la configuración de YARA desde current_app.config.

    Admite tanto un único fichero de reglas (YARA_RULES_PATH apunta a
    un .yar/.yara/.rule) como un directorio que contenga múltiples
    ficheros de reglas. En este último caso, se compilan todas las
    reglas encontradas bajo ese directorio.
    """

    cfg = current_app.config if current_app else {}
    enabled = bool(cfg.get("YARA_ENABLED", False))
    rules_path_cfg = cfg.get("YARA_RULES_PATH")
    if not yara or not enabled or not rules_path_cfg:
        return YaraConfig(enabled=False, rules_path=None)

    rules_path = Path(rules_path_cfg)
    if not rules_path.exists():
        return YaraConfig(enabled=False, rules_path=None)

    return YaraConfig(enabled=True, rules_path=rules_path)


def _run_yara(path: Path) -> List[Dict[str, Any]]:
    conf = _load_yara_config()
    if not conf.enabled or not conf.rules_path:
        return []

    try:
        # Si YARA_RULES_PATH apunta a un directorio, recopilamos todas las
        # reglas .yar/.yara/.rule de forma recursiva y las compilamos como
        # un conjunto. Si apunta a un fichero, compilamos sólo ese fichero.
        if conf.rules_path.is_dir():
            rule_files: list[Path] = []
            for ext in (".yar", ".yara", ".rule"):
                rule_files.extend(conf.rules_path.rglob(f"*{ext}"))
            if not rule_files:
                return []
            filepaths: dict[str, str] = {}
            for idx, rf in enumerate(sorted(rule_files)):
                namespace = f"ns_{idx}_{rf.stem}"
                filepaths[namespace] = str(rf)
            rules = yara.compile(filepaths=filepaths)  # type: ignore[arg-type]
        else:
            rules = yara.compile(filepath=str(conf.rules_path))  # type: ignore[arg-type]

        matches = rules.match(str(path))
    except Exception as exc:  # pragma: no cover - errores de reglas
        return [{"error": f"error YARA: {exc}"}]

    results: List[Dict[str, Any]] = []
    for m in matches:
        results.append(
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": dict(m.meta),
            }
        )
    return results


def _run_virustotal(sha256: str) -> Dict[str, Any]:
    """Consulta VirusTotal usando el hash SHA256 del fichero.

    Utiliza la API v3 de VirusTotal. Si no hay API key configurada o
    se produce un error de red, devuelve información mínima indicando
    que no está disponible, para no romper el flujo de análisis.
    """

    cfg = current_app.config if current_app else {}

    # Permite desactivar explícitamente VirusTotal desde configuración
    if not cfg.get("VIRUSTOTAL_ENABLED", True):
        return {"status": "disabled"}

    api_key = cfg.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"status": "not_configured"}

    # Caché muy ligera en memoria por hash + TTL, para no repetir
    # consultas sobre el mismo fichero en una misma instancia.
    ttl = int(cfg.get("VIRUSTOTAL_CACHE_TTL_SECONDS", 3600) or 0)
    cache_key = f"__vt_cache_{sha256}"
    cache_entry = cfg.get(cache_key)
    now = int(time.time())
    if isinstance(cache_entry, dict):
        ts = cache_entry.get("ts")
        if isinstance(ts, int) and ttl > 0 and now - ts <= ttl:
            cached_data = cache_entry.get("data")
            if isinstance(cached_data, dict):
                return {"status": "cached", **cached_data}

    headers = {
        "x-apikey": api_key,
    }
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except Exception as exc:  # pragma: no cover - errores de red
        return {"status": "error", "detail": f"error de red VirusTotal: {exc}"}

    if resp.status_code == 404:
        data = {"status": "not_found"}
    elif resp.status_code in {401, 403}:
        data = {
            "status": "auth_error",
            "http_status": resp.status_code,
            "detail": "API key de VirusTotal inválida o sin permisos para esta operación.",
        }
    elif resp.status_code == 429:
        data = {
            "status": "rate_limited",
            "http_status": resp.status_code,
            "detail": "Límite de peticiones de VirusTotal alcanzado para la API key actual.",
        }
    elif not resp.ok:
        data = {
            "status": "error",
            "http_status": resp.status_code,
            "detail": resp.text[:500],
        }
    else:
        try:
            raw = resp.json()
        except Exception:  # pragma: no cover
            data = {"status": "error", "detail": "respuesta no es JSON"}
        else:
            stats = (
                raw.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            data = {
                "status": "ok",
                "stats": stats,
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }

    # Guardamos en caché si hay TTL y el contexto permite mutar config
    if ttl > 0 and isinstance(cfg, dict):  # type: ignore[redundant-cast]
        try:
            cfg[cache_key] = {"ts": now, "data": data}
        except Exception:
            pass

    return data


def _detect_macros(path: Path) -> str:
    """Detección y análisis de macros en documentos Office.

    Utiliza oletools/olevba si está disponible para:

    - Determinar si el documento contiene macros.
    - Extraer el código VBA y algunas métricas básicas.
    - Identificar indicadores potencialmente maliciosos
      (AutoOpen, Shell, URL sospechosas, etc.).

    El resultado detallado se almacena en ``additional_results``
    mediante la función ``_extract_macro_details``; aquí sólo
    devolvemos "yes"/"no"/"unknown" para el campo macro_detected.
    """

    ext = path.suffix.lower()
    if ext not in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".docx", ".xlsx", ".pptx"}:
        return "no"

    # Si oletools no está disponible, hacemos un fallback más robusto
    # para no romper el flujo, aunque la detección será menos fiable.
    if VBA_Parser is None:
        # Para contenedores OOXML (docx/docm/xlsx/xlsm/pptx/pptm) intentamos
        # detectar la presencia de vbaProject.bin dentro del ZIP, que es una
        # señal fuerte de que hay macros incrustadas.
        if ext in {".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx"}:
            try:
                if zipfile.is_zipfile(str(path)):
                    with zipfile.ZipFile(str(path)) as zf:  # pragma: no cover - E/S
                        names = [name.lower() for name in zf.namelist()]
                        if any("vbaproject.bin" in name for name in names):
                            return "yes"
            except Exception:
                # Si falla la inspección del ZIP seguimos con heurísticas
                # ligeras sobre el binario completo.
                pass

        try:
            data = path.read_bytes()
        except Exception:  # pragma: no cover - E/S
            return "unknown"

        patterns = [
            b"VBA",
            b"AutoOpen",
            b"Document_Open",
            b"ThisDocument",
            b"Sub Auto",
            b"Shell(",
            b"CreateObject(\"WScript.Shell\")",
            b"FileSystemObject",
        ]
        for p in patterns:
            if p in data:
                return "yes"
        return "no"

    try:
        vba = VBA_Parser(str(path))  # type: ignore[call-arg]
    except Exception:  # pragma: no cover - errores de parsing
        # Si por algún motivo oletools no puede parsear el archivo,
        # marcamos el estado como desconocido en lugar de forzar "no".
        return "unknown"

    try:
        if vba.detect_vba_macros():
            return "yes"
    except Exception:  # pragma: no cover
        return "unknown"

    # Como salvaguarda adicional, para OOXML macro-enabled comprobamos
    # también la presencia de vbaProject.bin en el ZIP.
    if ext in {".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx"}:
        try:
            if zipfile.is_zipfile(str(path)):
                with zipfile.ZipFile(str(path)) as zf:  # pragma: no cover - E/S
                    names = [name.lower() for name in zf.namelist()]
                    if any("vbaproject.bin" in name for name in names):
                        return "yes"
        except Exception:  # pragma: no cover
            pass

    return "no"


def _extract_macro_details(path: Path) -> Dict[str, Any] | None:
    """Extrae detalles de macros VBA usando oletools.

    Devuelve un diccionario con estructura pensada para ser serializada
    en JSON dentro de ``additional_results['macro_details']``.

    Si oletools no está disponible o el archivo no es soportado,
    devuelve ``None`` para no ensuciar los metadatos.
    """

    ext = path.suffix.lower()
    if ext not in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".docx", ".xlsx", ".pptx"}:
        return None

    if VBA_Parser is None:
        return None

    try:
        vba = VBA_Parser(str(path))  # type: ignore[call-arg]
    except Exception:  # pragma: no cover - errores de parsing
        return None

    try:
        has_macros = vba.detect_vba_macros()
    except Exception:  # pragma: no cover
        return None

    if not has_macros:
        return None

    modules: list[dict] = []
    macro_count = 0
    code_size = 0

    try:
        for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():  # type: ignore[attr-defined]
            text = vba_code or ""
            code_size += len(text)
            macro_count += 1
            preview = text[:800]
            modules.append(
                {
                    "filename": filename,
                    "stream_path": stream_path,
                    "vba_filename": vba_filename,
                    "code_preview": preview,
                    "code_full": text,
                    "length": len(text),
                }
            )
    except Exception:  # pragma: no cover
        # Si falla la extracción, devolvemos lo que tengamos (prob.
        # nada) para no romper el análisis principal.
        pass

    # Escáner de indicadores maliciosos simple basado en oletools
    indicators: list[dict] = []
    try:
        if VBA_Scanner is not None:
            # Construimos un gran bloque concatenando todo el código VBA
            all_code = "\n".join(m.get("code_full") or "" for m in modules)
            scanner = VBA_Scanner(all_code)  # type: ignore[call-arg]
            for kw_type, keyword, description in scanner.scan():  # type: ignore[attr-defined]
                indicators.append(
                    {
                        "type": kw_type,
                        "keyword": keyword,
                        "description": description,
                    }
                )
    except Exception:  # pragma: no cover
        pass

    if not modules and not indicators:
        return None

    return {
        "has_macros": True,
        "macro_count": macro_count,
        "code_size": code_size,
        "modules": modules,
        "indicators": indicators,
    }


def _analyze_audio(path: Path, mime_type: str) -> str:
    """Análisis ligero de audio usando mutagen.

    Extrae metadatos básicos (duración, bitrate, etiquetas comunes) y
    devuelve un JSON serializado. Esta función no realiza detección de
    esteganografía; esa parte se delega a `_analyze_steganography`.
    """

    if not MutagenFile:
        return "Análisis de audio no disponible (mutagen no instalado)."

    try:
        audio = MutagenFile(str(path))
    except Exception:  # pragma: no cover - archivos no soportados
        return "No se han podido extraer metadatos de audio."

    if not audio:
        return "No se han podido extraer metadatos de audio."

    info = getattr(audio, "info", None)
    tags = getattr(audio, "tags", None)

    details: Dict[str, Any] = {
        "mime_type": mime_type,
    }
    if info is not None:
        details["duration_seconds"] = getattr(info, "length", None)
        details["bitrate"] = getattr(info, "bitrate", None)

    if tags:
        # tomamos algunas etiquetas típicas
        for key in ("artist", "album", "title"):
            if key in tags:
                try:
                    details[key] = str(tags[key])
                except Exception:  # pragma: no cover
                    continue

    return json.dumps(details, ensure_ascii=False)


def _generate_audio_spectrogram(path: Path) -> str | None:
    """Genera un espectrograma PNG para audio WAV.

    El archivo resultante se guarda bajo ``static/spectrograms`` y se
    devuelve la ruta relativa (por ejemplo, ``spectrograms/foo.png``)
    para que la vista pueda construir la URL con ``url_for('static')``.

    Si las dependencias opcionales (numpy/matplotlib) no están
    disponibles o el archivo no es un WAV PCM soportado, devuelve
    ``None`` sin interrumpir el flujo de análisis.
    """

    if np is None or plt is None:
        return None

    ext = path.suffix.lower()
    if ext not in {".wav", ".wave"}:
        return None

    try:
        with wave.open(str(path), "rb") as wf:  # pragma: no cover - E/S
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            framerate = wf.getframerate()
            n_frames = wf.getnframes()

            if framerate <= 0 or n_frames == 0:
                return None

            # Limitamos la duración a ~60 segundos para evitar imágenes muy pesadas.
            max_frames = int(min(n_frames, framerate * 60))
            frames = wf.readframes(max_frames)
    except Exception:  # pragma: no cover - errores de parsing WAV
        return None

    if not frames:
        return None

    # Convertimos a array numpy flotante en mono.
    try:
        if sampwidth == 1:
            data = np.frombuffer(frames, dtype=np.uint8).astype(np.float32)
            data = (data - 128.0) / 128.0  # centrado en 0
        elif sampwidth == 2:
            data = np.frombuffer(frames, dtype=np.int16).astype(np.float32) / 32768.0
        else:
            # Fallback genérico para anchos de muestra menos comunes
            # (24/32-bit PCM). No necesitamos amplitud exacta, sólo
            # una forma de onda razonable para el espectrograma.
            data = np.frombuffer(frames, dtype=np.int8).astype(np.float32)

        if n_channels > 1 and sampwidth in (1, 2):
            data = data.reshape(-1, n_channels).mean(axis=1)
    except Exception:  # pragma: no cover
        return None

    try:
        fig, ax = plt.subplots(figsize=(6, 3), dpi=120)
        ax.specgram(data, NFFT=1024, Fs=framerate, noverlap=512, cmap="magma")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Frequency (Hz)")
        ax.set_title("Audio spectrogram preview")
        fig.tight_layout()

        static_dir = Path(current_app.root_path) / "static" / "spectrograms"
        static_dir.mkdir(parents=True, exist_ok=True)

        filename = f"{path.stem}_spectrogram.png"
        out_path = static_dir / filename
        fig.savefig(out_path)
        plt.close(fig)
    except Exception:  # pragma: no cover - errores de renderizado/FS
        try:
            plt.close(fig)  # type: ignore[name-defined]
        except Exception:
            pass
        return None

    # Ruta relativa respecto a /static
    return f"spectrograms/{filename}"


def _extract_long_printable_run(data: bytes, min_len: int = 32) -> str | None:
    """Return the longest run of printable characters in *data*.

    This is used as a heuristic to decide whether LSB bits or other
    extracted bytes contain human-readable text.
    """

    if not data:
        return None

    try:
        decoded = data.decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover
        return None

    best_start = best_end = 0
    cur_start = 0
    for i, ch in enumerate(decoded):
        if ch.isprintable() or ch in "\r\n\t":
            # keep current run
            continue
        else:
            # end current run
            if i - cur_start > best_end - best_start:
                best_start, best_end = cur_start, i
            cur_start = i + 1

    # tail run
    if len(decoded) - cur_start > best_end - best_start:
        best_start, best_end = cur_start, len(decoded)

    if best_end - best_start < min_len:
        return None

    snippet = decoded[best_start:best_end].strip()
    return snippet or None


def _looks_like_human_text(snippet: str) -> bool:
    """Heurística sencilla para diferenciar texto humano de ruido.

    No pretende ser un detector de idioma completo, sólo descartar
    secuencias como "mmmmmmmmmO_6mmmm" que son imprimibles pero no
    parecen frase real. Se basa en:

    - Presencia de espacios (al menos uno)
    - Proporción alta de letras / espacios frente a dígitos y símbolos
    - Proporción razonable de vocales dentro de las letras
    """

    if not snippet:
        return False

    text = snippet.strip()
    if len(text) < 16:
        return False

    # Debe haber al menos un espacio para parecer frase natural.
    if " " not in text:
        return False

    letters = 0
    spaces = 0
    digits = 0
    others = 0
    vowels = 0

    vowel_set = set("aeiouáéíóúAEIOUÁÉÍÓÚ")

    for ch in text:
        if ch.isalpha():
            letters += 1
            if ch in vowel_set:
                vowels += 1
        elif ch.isspace():
            spaces += 1
        elif ch.isdigit():
            digits += 1
        else:
            others += 1

    total = letters + spaces + digits + others
    if total == 0:
        return False

    # Rechazamos secuencias donde la mayor parte son dígitos/símbolos.
    letter_space_ratio = (letters + spaces) / total
    if letter_space_ratio < 0.7:
        return False

    # Entre un 20% y 60% de vocales suele ser razonable para idiomas latinos.
    if letters > 0:
        vowel_ratio = vowels / letters
        if vowel_ratio < 0.18 or vowel_ratio > 0.7:
            return False

    return True


def _try_base64_decode(text: str) -> dict | None:
    """Try to interpret *text* as base64 and return a small summary.

    Returns a dict with decoded preview if decoding looks valid, or
    None otherwise.
    """

    if not text:
        return None

    candidate = "".join(ch for ch in text if not ch.isspace())
    if len(candidate) < 24:
        return None

    base64_charset = set(string.ascii_letters + string.digits + "+/=")
    if any(ch not in base64_charset for ch in candidate):
        return None

    # Allow a small amount of trailing noise: trim up to 3 characters
    # from the end until the length is a multiple of 4 and try to
    # decode. This helps when the carrier introduces extra printable
    # bytes after a valid base64 block.
    decoded_bytes: bytes | None = None
    for trim in range(0, 4):
        if len(candidate) - trim < 24:
            break
        chunk = candidate[: len(candidate) - trim]
        if len(chunk) % 4 != 0:
            continue
        try:
            decoded_bytes = base64.b64decode(chunk, validate=True)
            break
        except Exception:  # pragma: no cover
            decoded_bytes = None

    if not decoded_bytes:
        return None

    if not decoded_bytes:
        return None

    try:
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover
        decoded_text = ""

    preview = (decoded_text or repr(decoded_bytes))[:200]
    return {
        "decoded_preview": preview,
        "decoded_length": len(decoded_text) or len(decoded_bytes),
        # Full decoded content is kept so that the UI can
        # offer a "view full payload" action when needed.
        "decoded_full": decoded_text or None,
    }


def _analyze_code_snippet(snippet: str) -> dict | None:
    """Heurística ligera para detectar lenguaje y llamadas peligrosas.

    No pretende ser un parser completo; sólo marca patrones típicos de
    C/C++, C#, Java, bash y PowerShell y resalta llamadas o comandos que
    suelen implicar ejecución de código o acceso a sistema.
    """

    if not snippet:
        return None

    text = snippet.lower()

    # Reglas muy sencillas por lenguaje
    lang_rules = [
        {
            "name": "powershell",
            "indicators": [
                "param(",
                "write-host",
                "new-object system.net.webclient",
                "new-object net.webclient",
                "invoke-expression",
                "iex ",
                "powershell -",
            ],
            "dangerous": [
                "invoke-expression",
                "iex",
                "downloadfile(",
                "downloadstring(",
                "start-process",
            ],
        },
        {
            "name": "bash/shell",
            "indicators": [
                "#!/bin/bash",
                "#!/bin/sh",
                "#!/usr/bin/env bash",
                "#!/usr/bin/env sh",
                "chmod +x",
                " rm -rf ",
                "curl ",
                "wget ",
            ],
            "dangerous": [
                " rm -rf ",
                "curl ",
                "wget ",
                "nc ",
                "bash -i",
            ],
        },
        {
            "name": "c/c++",
            "indicators": [
                "#include <",
                "int main(",
                "printf(",
                "std::",
            ],
            "dangerous": [
                "system(",
                "popen(",
                "winexec(",
                "createprocess",
            ],
        },
        {
            "name": "c#",
            "indicators": [
                "using system;",
                "namespace ",
                "class program",
                "static void main",
            ],
            "dangerous": [
                "process.start(",
                "new webclient(",
                "downloadfile(",
                "downloadstring(",
            ],
        },
        {
            "name": "java",
            "indicators": [
                "public static void main",
                "system.out.println",
                "import java.",
            ],
            "dangerous": [
                "runtime.getruntime().exec",
                "processbuilder(",
            ],
        },
    ]

    best_lang = None
    best_score = 0
    best_danger: list[str] = []

    for rule in lang_rules:
        ind_count = sum(1 for kw in rule["indicators"] if kw in text)
        if ind_count == 0:
            continue
        if ind_count > best_score:
            best_score = ind_count
            best_lang = rule["name"]
            best_danger = [kw.strip() for kw in rule["dangerous"] if kw in text]

    if not best_lang:
        return None

    return {
        "language": best_lang,
        "suspicious_calls": best_danger,
    }


def _scan_embedded_base64(data: bytes, max_segments: int = 3) -> list[dict]:
    """Scan raw bytes looking for long base64-like strings.

    This is useful for PDF, audio or other containers where data may be
    hidden as long base64 blobs.
    """

    results: list[dict] = []
    if not data:
        return results

    # We limit the scan window for performance in very large files.
    max_window = 2_000_000  # 2 MB
    if len(data) <= max_window:
        windows = [(data, 0)]
    else:
        windows = [
            (data[:max_window], 0),
            (data[-max_window:], max(0, len(data) - max_window)),
        ]

    pattern = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")

    for window, base_offset in windows:
        for match in pattern.finditer(window):
            seq = match.group(0)
            try:
                decoded = base64.b64decode(seq, validate=True)
            except Exception:  # pragma: no cover
                continue

            try:
                decoded_text = decoded.decode("utf-8", errors="ignore")
            except Exception:  # pragma: no cover
                decoded_text = ""

            decoded_type = "binary"
            if decoded_text:
                printable_chars = sum(c in string.printable for c in decoded_text)
                if printable_chars / max(len(decoded_text), 1) > 0.85:
                    decoded_type = "text"
            if decoded.startswith(b"MZ"):
                decoded_type = "windows_executable"
            elif decoded.startswith(b"PK\x03\x04"):
                decoded_type = "zip_or_office"
            elif decoded.lstrip().startswith(b"%PDF"):
                decoded_type = "pdf_document"

            preview = (decoded_text or repr(decoded))[:200]
            try:
                original_full = seq.decode("ascii", errors="ignore")
            except Exception:  # pragma: no cover
                original_full = ""

            language = None
            suspicious_calls: list[str] = []
            if decoded_type == "text" and decoded_text:
                code_info = _analyze_code_snippet(decoded_text)
                if code_info:
                    language = code_info.get("language")
                    suspicious_calls = list(code_info.get("suspicious_calls") or [])
            results.append(
                {
                    "offset": base_offset + match.start(),
                    "length": len(seq),
                    # Preview used in the main report
                    "original": original_full[:400],
                    # Full originals/decoded payloads are kept so the
                    # user can request them explicitly from the UI.
                    "original_full": original_full,
                    "decoded_preview": preview,
                    "decoded_length": len(decoded_text) or len(decoded),
                    "decoded_full": decoded_text or None,
                    "decoded_type": decoded_type,
                    "language": language,
                    "suspicious_calls": suspicious_calls,
                }
            )

            if len(results) >= max_segments:
                return results

    return results


def _bits_to_bytes(bits: list[int], max_bytes: int) -> bytes:
    """Concatena bits en bytes, truncando a ``max_bytes``.

    Se usa para transformar los bits LSB de los canales de la imagen en una
    secuencia de bytes sobre la que podamos buscar texto o base64.
    """

    out = bytearray()
    byte = 0
    count = 0
    for b in bits:
        byte = (byte << 1) | (1 if b else 0)
        count += 1
        if count == 8:
            out.append(byte)
            if len(out) >= max_bytes:
                break
            byte = 0
            count = 0
    return bytes(out)


def _extract_lsb_text_from_image(path: Path) -> dict | None:
    """Extrae texto oculto de los bits menos significativos de una imagen.

    Se prueban varias variantes habituales (R, G, B y RGB combinado) para
    aumentar las probabilidades de detectar el mensaje usado por herramientas
    sencillas de esteganografía LSB (incluida la que has utilizado).
    """

    if Image is None:
        return None

    try:
        with Image.open(path) as img:  # type: ignore[call-arg]
            img = img.convert("RGB")
            pixels = list(img.getdata())
    except Exception:  # pragma: no cover
        return None

    max_bytes = 131_072  # ~128 KB de mensaje máximo
    variants = [
        ("lsb_r", [0]),
        ("lsb_g", [1]),
        ("lsb_b", [2]),
        ("lsb_rgb", [0, 1, 2]),
    ]

    for name, idxs in variants:
        bits: list[int] = []
        for r, g, b in pixels:
            rgb = (r, g, b)
            for i in idxs:
                bits.append(rgb[i] & 1)
                if len(bits) >= max_bytes * 8:
                    break
            if len(bits) >= max_bytes * 8:
                break

        if len(bits) < 8:
            continue

        data = _bits_to_bytes(bits, max_bytes=max_bytes)
        snippet = _extract_long_printable_run(data, min_len=20)
        if not snippet:
            continue

        base64_info = _try_base64_decode(snippet)
        # Si no parece texto humano y tampoco es base64 válido, lo
        # tratamos como ruido y seguimos probando otras variantes.
        if not base64_info and not _looks_like_human_text(snippet):
            continue

        result: dict = {
            "source": name,
            # Preview shown in the main report
            "hidden_text_preview": snippet[:200],
            "hidden_text_length": len(snippet),
            # Full text so the UI can offer a "view full" action
            "hidden_text_full": snippet,
            "encoding": "base64" if base64_info else "plain_or_unknown",
        }

        if base64_info:
            code_info = _analyze_code_snippet(
                base64_info.get("decoded_full") or base64_info["decoded_preview"]
            )
            result.update(
                {
                    "base64_decoded_preview": base64_info["decoded_preview"][:200],
                    "base64_decoded_length": base64_info["decoded_length"],
                    "base64_decoded_full": base64_info.get("decoded_full"),
                    "language": (code_info or {}).get("language"),
                    "suspicious_calls": list((code_info or {}).get("suspicious_calls") or []),
                }
            )

        return result

    return None


def _image_lsb_chi_square(path: Path) -> Dict[str, Any] | None:
    """Simple Chi-square style test over image LSBs.

    This is intentionally lightweight and heuristic: it checks how close
    the distribution of 0/1 LSBs is to a perfectly uniform 50/50 split.

    Natural images tend to deviate more from perfect uniformity, while
    naive LSB embedding often moves the distribution towards 50/50.

    The function returns a small dict with statistics and a boolean
    "suspicious" flag. It never raises and returns None on any error
    or when dependencies are missing.
    """

    if Image is None or np is None:
        return None

    try:
        with Image.open(path) as img:  # type: ignore[call-arg]
            img = img.convert("RGB")
            arr = np.array(img)
    except Exception:  # pragma: no cover
        return None

    # Limit the number of pixels to keep the test fast on very large
    # images. We sample a prefix of the flattened array.
    max_pixels = 512 * 512
    flat = arr.reshape(-1, 3)
    if flat.shape[0] > max_pixels:
        flat = flat[:max_pixels]

    # Use all three channels' LSBs.
    lsb = flat & 1
    bits = lsb.reshape(-1)
    total = int(bits.size)
    if total == 0:
        return None

    zeros = int((bits == 0).sum())
    ones = total - zeros
    expected = total / 2.0
    if expected == 0:
        return None

    # Chi-square for df=1 between observed (zeros, ones) and expected
    # (total/2, total/2).
    chi2 = ((zeros - expected) ** 2) / expected + ((ones - expected) ** 2) / expected

    # Heuristic: if chi2 is very small, the distribution is *too* close
    # to uniform, which can be an indicator of naive LSB replacement.
    # Threshold is tuned conservatively to avoid marking everything.
    suspicious = chi2 < 3.84  # ~p>0.05 for df=1

    return {
        "zeros": zeros,
        "ones": ones,
        "total": total,
        "chi2": float(chi2),
        "suspicious": bool(suspicious),
    }


def _image_lsb_rs_analysis(path: Path) -> Dict[str, Any] | None:
    """Very lightweight RS-style analysis on image LSBs.

    We approximate RS analysis by grouping grayscale pixels and
    comparing the sum of absolute differences before/after flipping
    LSBs. When regular and singular groups become very similar, it
    suggests potential LSB embedding.

    Returns a dict with R/S counts and a "suspicious" flag, or None on
    error / missing dependencies.
    """

    if Image is None or np is None:
        return None

    try:
        with Image.open(path) as img:  # type: ignore[call-arg]
            gray = img.convert("L")
            arr = np.array(gray, dtype=np.uint8)
    except Exception:  # pragma: no cover
        return None

    flat = arr.flatten()
    max_pixels = 512 * 512
    if flat.size > max_pixels:
        flat = flat[:max_pixels]

    # We work on groups of 4 pixels.
    group_size = 4
    n_groups = flat.size // group_size
    if n_groups == 0:
        return None

    data = flat[: n_groups * group_size].reshape(n_groups, group_size).astype(np.int16)

    # Discrimination function: sum of absolute differences between
    # neighbouring pixels.
    diffs = np.abs(np.diff(data, axis=1))
    f_orig = diffs.sum(axis=1)

    # Flip LSBs of all pixels in each group.
    flipped = data ^ 1
    diffs_flipped = np.abs(np.diff(flipped, axis=1))
    f_flip = diffs_flipped.sum(axis=1)

    regular = int((f_orig < f_flip).sum())
    singular = int((f_orig > f_flip).sum())
    total_groups = int(n_groups)
    if total_groups == 0:
        return None

    # If regular and singular counts are *too* close, that is a
    # tell-tale sign in the classic RS method. We use a simple
    # relative delta as heuristic.
    delta = abs(regular - singular) / max(total_groups, 1)
    suspicious = delta < 0.02  # less than 2% difference

    return {
        "regular": regular,
        "singular": singular,
        "total_groups": total_groups,
        "delta": float(delta),
        "suspicious": bool(suspicious),
    }


def _extract_lsb_text_from_wav(path: Path) -> dict | None:
    """Extrae texto oculto de los bits LSB de audio WAV.

    Esta rutina se centra en WAV PCM de 8 o 16 bits. Recorre las
    muestras de todos los canales, toma el bit menos significativo de
    cada muestra y reconstruye una secuencia de bytes sobre la que se
    aplican las mismas heurísticas que para imágenes: búsqueda de
    secuencias imprimibles largas y prueba de decodificación base64.
    """

    ext = path.suffix.lower()
    if ext not in {".wav", ".wave"}:
        return None

    try:
        with wave.open(str(path), "rb") as wf:  # pragma: no cover - E/S
            n_channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            n_frames = wf.getnframes()

            if sampwidth not in (1, 2) or n_frames == 0:
                return None

            # Limitamos el número de frames para evitar leer audios muy largos.
            max_frames = min(n_frames, 2_000_000)
            raw_frames = wf.readframes(max_frames)
    except Exception:  # pragma: no cover - errores de parsing WAV
        return None

    if not raw_frames:
        return None

    # Cada muestra ocupa ``sampwidth`` bytes; como no necesitamos el
    # valor completo, nos basta con el primer byte (LSB en little-endian).
    max_bytes = 131_072  # ~128 KB de mensaje máximo
    max_bits = max_bytes * 8
    bits: list[int] = []

    step = sampwidth  # avanzamos muestra a muestra (canales intercalados)
    for i in range(0, len(raw_frames), step):
        if len(bits) >= max_bits:
            break
        sample = raw_frames[i : i + sampwidth]
        if len(sample) < sampwidth:
            break
        bits.append(sample[0] & 1)

    if len(bits) < 8:
        return None

    data = _bits_to_bytes(bits, max_bytes=max_bytes)

    # Estrategia específica para audio WAV: asumimos que, si hay un
    # mensaje LSB "sencillo", comienza en la primera muestra. Por eso
    # intentamos primero extraer un prefijo continuo de caracteres
    # imprimibles desde el inicio del flujo de bytes, en vez de buscar
    # la racha más larga en cualquier posición.
    try:
        decoded = data.decode("utf-8", errors="ignore")
    except Exception:  # pragma: no cover
        return None

    prefix_chars: list[str] = []
    for ch in decoded:
        if ch.isprintable() or ch in "\r\n\t":
            prefix_chars.append(ch)
        else:
            break

    snippet = "".join(prefix_chars).strip()

    # Si el prefijo imprimible inicial es demasiado corto, lo
    # consideramos ruido y no intentamos recuperar nada.
    if len(snippet) < 16:
        return None

    # Para audio intentamos una decodificación base64 aún más laxa que
    # la heurística genérica: probamos directamente a interpretar el
    # snippet como base64, añadiendo padding si es necesario y usando
    # validate=False. Si la decodificación falla o produce salida
    # vacía, simplemente no se marca como base64.
    base64_info = None
    try:
        candidate = "".join(ch for ch in snippet if not ch.isspace())
        if len(candidate) >= 24:
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=False)
            if decoded_bytes:
                try:
                    decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                except Exception:  # pragma: no cover
                    decoded_text = ""

                preview = (decoded_text or repr(decoded_bytes))[:200]
                base64_info = {
                    "decoded_preview": preview,
                    "decoded_length": len(decoded_text) or len(decoded_bytes),
                    "decoded_full": decoded_text or None,
                }
    except Exception:  # pragma: no cover
        base64_info = None

    result: dict = {
        "source": "audio_lsb",
        "hidden_text_preview": snippet[:200],
        "hidden_text_length": len(snippet),
        "hidden_text_full": snippet,
        "encoding": "base64" if base64_info else "plain_or_unknown",
    }

    if base64_info:
        code_info = _analyze_code_snippet(
            base64_info.get("decoded_full") or base64_info["decoded_preview"]
        )
        result.update(
            {
                "base64_decoded_preview": base64_info["decoded_preview"][:200],
                "base64_decoded_length": base64_info["decoded_length"],
                "base64_decoded_full": base64_info.get("decoded_full"),
                "language": (code_info or {}).get("language"),
                "suspicious_calls": list((code_info or {}).get("suspicious_calls") or []),
            }
        )

    return result


def _analyze_steganography(path: Path, mime_type: str) -> tuple[str, Dict[str, Any] | None]:
    """Perform a deeper steganography-oriented analysis.

    The function returns a tuple (status, details):

    - status: "no", "possible" or "unknown" (kept simple to avoid
      breaking existing logic and visual indicators).
    - details: optional dict with structured information about any
      hidden content or strong indicators found.
    """

    ext = path.suffix.lower()
    is_image = mime_type.startswith("image/") or ext in {".jpg", ".jpeg", ".png", ".bmp", ".gif"}
    is_audio = mime_type.startswith("audio/") or ext in {".wav", ".wave"}
    is_pdf = mime_type == "application/pdf" or ext == ".pdf"

    # Por ahora limitamos el análisis de esteganografía a formatos donde
    # tiene más sentido práctico (imágenes, audio y PDF). En ejecutables
    # u otros binarios genéricos es muy frecuente encontrar patrones que
    # parecen base64 pero no indican realmente esteganografía, lo que
    # genera falsos positivos y veredictos "suspicious" para ficheros
    # perfectamente limpios.
    if not (is_image or is_audio or is_pdf):
        return ("no", None)

    details: Dict[str, Any] = {
        "category": "image" if is_image else "audio" if is_audio else "pdf",
        "status": "no",
        "methods": [],
        "messages": [],
        "base64": [],
        "notes": [],
    }
    status: str = "no"

    # Try to read raw bytes for generic scanning.
    try:
        raw = path.read_bytes()
    except Exception:  # pragma: no cover
        raw = b""

    # 1) LSB-style extraction for images
    if is_image:
        lsb_info = _extract_lsb_text_from_image(path)
        if lsb_info:
            status = "yes"
            details["status"] = "found"
            details["methods"].append(lsb_info.get("source", "image_lsb"))
            details["messages"].append(
                {
                    "source": lsb_info.get("source", "image_lsb"),
                    "preview": lsb_info.get("hidden_text_preview", ""),
                    "length": lsb_info.get("hidden_text_length", 0),
                }
            )
            if "base64_decoded_preview" in lsb_info:
                details["base64"].append(
                    {
                        "source": lsb_info.get("source", "image_lsb"),
                        "original_preview": lsb_info.get("hidden_text_preview", "")[:120],
                        # Full original and decoded payloads for on-demand view
                        "original_full": lsb_info.get("hidden_text_full"),
                        "decoded_preview": lsb_info.get("base64_decoded_preview", ""),
                        "decoded_length": lsb_info.get("base64_decoded_length", 0),
                        "decoded_full": lsb_info.get("base64_decoded_full"),
                        "decoded_type": "text",  # normalmente texto
                        "language": lsb_info.get("language"),
                        "suspicious_calls": list(lsb_info.get("suspicious_calls") or []),
                    }
                )
            details["notes"].append(
                "Printable content extracted from image LSB channels; steganography is very likely present."
            )

        # Chi-square / RS statistics are attached both as extra
        # context when we have a payload and as softer indicators
        # when no payload was recovered.
        chi_stats = _image_lsb_chi_square(path)
        rs_stats = _image_lsb_rs_analysis(path)

        if chi_stats and chi_stats.get("suspicious"):
            if not lsb_info and status == "no":
                status = "possible"
                details["status"] = "suspicious"
            if "chi_square_lsb" not in details["methods"]:
                details["methods"].append("chi_square_lsb")
            # Incluimos siempre los valores numéricos para dar contexto.
            if not lsb_info:
                msg = (
                    "Chi-square LSB test: zeros={zeros}, ones={ones}, total_bits={total}, chi2={chi2:.2f}; "
                    "LSB distribution very close to uniform, naive LSB embedding is possible."
                ).format(
                    zeros=chi_stats.get("zeros"),
                    ones=chi_stats.get("ones"),
                    total=chi_stats.get("total"),
                    chi2=chi_stats.get("chi2", 0.0),
                )
            else:
                msg = (
                    "Chi-square LSB test suggests LSB embedding (zeros={zeros}, ones={ones}, total_bits={total}, chi2={chi2:.2f})."
                ).format(
                    zeros=chi_stats.get("zeros"),
                    ones=chi_stats.get("ones"),
                    total=chi_stats.get("total"),
                    chi2=chi_stats.get("chi2", 0.0),
                )
            details["notes"].append(msg)

        if rs_stats and rs_stats.get("suspicious"):
            if not lsb_info and status == "no":
                status = "possible"
                details["status"] = "suspicious"
            if "rs_analysis" not in details["methods"]:
                details["methods"].append("rs_analysis")
            details["notes"].append(
                "RS analysis shows regular/singular groups are unusually balanced; LSB steganography is possible."
            )

    # 1b) LSB-style extraction for WAV audio
    if is_audio:
        wav_lsb_info = _extract_lsb_text_from_wav(path)
        if wav_lsb_info:
            if status != "yes":
                status = "yes"
            details["status"] = "found"
            details["methods"].append(wav_lsb_info.get("source", "audio_lsb"))
            details["messages"].append(
                {
                    "source": wav_lsb_info.get("source", "audio_lsb"),
                    "preview": wav_lsb_info.get("hidden_text_preview", ""),
                    "length": wav_lsb_info.get("hidden_text_length", 0),
                }
            )
            if "base64_decoded_preview" in wav_lsb_info:
                details["base64"].append(
                    {
                        "source": wav_lsb_info.get("source", "audio_lsb"),
                        "original_preview": wav_lsb_info.get("hidden_text_preview", "")[:120],
                        "original_full": wav_lsb_info.get("hidden_text_full"),
                        "decoded_preview": wav_lsb_info.get("base64_decoded_preview", ""),
                        "decoded_length": wav_lsb_info.get("base64_decoded_length", 0),
                        "decoded_full": wav_lsb_info.get("base64_decoded_full"),
                        "decoded_type": "text",
                        "language": wav_lsb_info.get("language"),
                        "suspicious_calls": list(wav_lsb_info.get("suspicious_calls") or []),
                    }
                )
            details["notes"].append(
                "Printable content extracted from audio sample LSBs; audio steganography is very likely present."
            )

    # 2) Generic scan for embedded base64 blobs (PDF, audio, others)
    if raw:
        base64_segments = _scan_embedded_base64(raw)

        # Para audio reducimos ruido: sólo consideramos interesantes
        # los blobs que se decodifican como texto o como un formato
        # de fichero reconocible (EXE, ZIP/Office, PDF). Muchos MP3
        # contienen patrones que parecen base64 pero que al decodificarse
        # son simplemente datos binarios repetitivos.
        if is_audio and base64_segments:
            filtered: list[dict] = []
            for seg in base64_segments:
                dtype = seg.get("decoded_type")
                if dtype in {"text", "windows_executable", "zip_or_office", "pdf_document"}:
                    filtered.append(seg)
            base64_segments = filtered

        if base64_segments:
            status = "possible" if status != "yes" else status
            details["status"] = "found" if status == "yes" else "suspicious"
            details["methods"].append("embedded_base64")
            for seg in base64_segments:
                details["base64"].append(
                    {
                        "source": "embedded_base64",
                        "original_preview": seg.get("original", "")[:120],
                        "original_full": seg.get("original_full"),
                        "decoded_preview": seg.get("decoded_preview", ""),
                        "decoded_length": seg.get("decoded_length", 0),
                        "decoded_full": seg.get("decoded_full"),
                        "decoded_type": seg.get("decoded_type", "text"),
                        "language": seg.get("language"),
                        "suspicious_calls": list(seg.get("suspicious_calls") or []),
                    }
                )
            details["notes"].append(
                "Large base64-like blobs were found and decoded from the file contents."
            )

    # 3) Keep the previous size-based heuristic as an additional hint
    try:
        size = path.stat().st_size
    except Exception:  # pragma: no cover
        return ("unknown", details or None)

    if is_image and Image is not None:
        try:
            with Image.open(path) as img:  # type: ignore[call-arg]
                w, h = img.size
            expected = w * h * 3
            if size > expected * 3:
                if status == "no":
                    status = "possible"
                details["notes"].append(
                    "Image file is significantly larger than a simple RGB bitmap would suggest; could hide additional data."
                )
                if "size_heuristic" not in details["methods"]:
                    details["methods"].append("size_heuristic")
        except Exception:  # pragma: no cover
            if not status:
                return ("unknown", details or None)

    if is_audio:
        if size > 50 * 1024 * 1024:  # > 50MB
            if status == "no":
                status = "possible"
            details["notes"].append(
                "Audio file is very large; may contain hidden data in unused frames or metadata."
            )
            if "size_heuristic" not in details["methods"]:
                details["methods"].append("size_heuristic")

    if is_pdf and not details and size > 10 * 1024 * 1024:
        # Large PDFs with no explicit hidden blobs still get a mild hint.
        if status == "no":
            status = "possible"
        details["notes"].append(
            "PDF file is unusually large; manual review recommended for potential embedded payloads."
        )
        if "size_heuristic" not in details["methods"]:
            details["methods"].append("size_heuristic")

    return (status, details or None)


def _extract_basic_metadata(path: Path, mime_type: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "size": path.stat().st_size,
        "mime_type": mime_type,
    }

    if Image is not None and mime_type.startswith("image/"):
        try:
            with Image.open(path) as img:  # type: ignore[call-arg]
                meta["image_width"], meta["image_height"] = img.size
                exif_data = getattr(img, "_getexif", lambda: None)()  # type: ignore[call-arg]
                if exif_data and ExifTags is not None:
                    exif_readable = {}
                    for tag, value in exif_data.items():
                        name = ExifTags.TAGS.get(tag, str(tag))  # type: ignore[attr-defined]
                        exif_readable[name] = value
                    meta["exif"] = exif_readable
        except Exception:  # pragma: no cover
            pass

    return meta


def _extract_document_text_via_tika(path: Path, mime_type: str) -> Dict[str, Any] | None:
    """Extrae texto y metadatos de documentos usando Apache Tika.

    Esta función actúa como un pequeño adaptador frente a un servidor
    Apache Tika accesible vía HTTP. Si la integración está desactivada
    en configuración o el servidor no responde, devuelve ``None`` para
    no interferir con el resto del pipeline.

    El resultado está pensado para almacenarse bajo
    ``additional_results['document_text']`` y tener esta forma
    aproximada:

    {
        "status": "ok" | "error",
        "engine": "tika",
        "content_preview": str | None,
        "content_length": int | None,
        "content_truncated": bool,
        "content_full": str | None,
        "metadata": {"key": "value", ...},
        "error": str | None,
    }
    """

    cfg = current_app.config if current_app else {}
    if not cfg.get("TIKA_ENABLED", False):
        return None

    base_url = str(cfg.get("TIKA_SERVER_URL") or "").strip()
    if not base_url:
        return None

    timeout = int(cfg.get("TIKA_TIMEOUT_SECONDS", 30) or 30)
    max_chars = int(cfg.get("TIKA_MAX_TEXT_CHARS", 20000) or 0)

    base_url = base_url.rstrip("/")
    text_url = base_url + "/tika"
    meta_url = base_url + "/meta"

    text_content: str | None = None
    meta_data: dict[str, Any] | None = None
    errors: list[str] = []

    # Primera petición: contenido de texto plano
    try:
        with path.open("rb") as fh:  # pragma: no cover - E/S remota
            resp = requests.put(
                text_url,
                data=fh,
                headers={"Accept": "text/plain"},
                timeout=timeout,
            )
        if resp.ok:
            text_content = (resp.text or "").strip()
        else:
            errors.append(f"Tika text HTTP {resp.status_code}")
    except Exception as exc:  # pragma: no cover - errores de red/API
        errors.append(f"Tika text error: {exc}")

    # Segunda petición: metadatos en JSON
    try:
        with path.open("rb") as fh:  # pragma: no cover - E/S remota
            resp = requests.put(
                meta_url,
                data=fh,
                headers={"Accept": "application/json"},
                timeout=timeout,
            )
        if resp.ok:
            try:
                parsed = resp.json()
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                meta_data = parsed
        else:
            errors.append(f"Tika meta HTTP {resp.status_code}")
    except Exception as exc:  # pragma: no cover
        errors.append(f"Tika meta error: {exc}")

    if text_content is None and meta_data is None:
        if not errors:
            return None
        return {
            "status": "error",
            "engine": "tika",
            "content_preview": None,
            "content_length": None,
            "content_truncated": False,
            "content_full": None,
            "metadata": None,
            "error": "; ".join(errors)[:500],
        }

    text_content = (text_content or "").strip()
    length = len(text_content) if text_content else None

    if max_chars and text_content and length and length > max_chars:
        full = text_content[:max_chars]
        truncated = True
    else:
        full = text_content or None
        truncated = False

    preview = None
    if full:
        preview = full[:1000]

    # Normalizamos metadatos para evitar estructuras profundas y ruido.
    # Nos quedamos con un subconjunto "forensemente" interesante en una
    # whitelist y ordenado.
    simple_meta: dict[str, Any] | None = None
    if isinstance(meta_data, dict):
        # Lista de claves que suelen aportar valor en análisis de
        # documentos. Se muestran en este orden cuando estén
        # disponibles; el resto se ignora para no saturar el informe.
        preferred_keys: list[str] = [
            "dc:creator",
            "meta:last-author",
            "dcterms:created",
            "dcterms:modified",
            "Content-Type",
            "language",
            "meta:page-count",
            "xmpTPg:NPages",
            "meta:word-count",
            "meta:character-count",
            "meta:character-count-with-spaces",
            "meta:paragraph-count",
            "meta:line-count",
            "extended-properties:Application",
            "extended-properties:AppVersion",
            "extended-properties:Company",
            "extended-properties:Template",
            "extended-properties:TotalTime",
        ]

        buffer: dict[str, Any] = {}
        for k, v in meta_data.items():
            if k not in preferred_keys:
                continue
            try:
                vs = str(v)
            except Exception:
                continue
            if len(vs) > 2000:
                continue
            buffer[str(k)] = vs

        if buffer:
            # Respetamos el orden de preferred_keys y sólo añadimos
            # aquellas claves que efectivamente estén presentes.
            simple_meta = {k: buffer[k] for k in preferred_keys if k in buffer}

        if not simple_meta:
            simple_meta = None

    result: dict[str, Any] = {
        "status": "ok",
        "engine": "tika",
        "content_preview": preview,
        "content_length": length,
        "content_truncated": bool(truncated),
        "content_full": full,
        "metadata": simple_meta,
    }

    if errors:
        result["error"] = "; ".join(errors)[:500]

    return result


def _decide_verdict(
    clam: Dict[str, Any], yara_matches: List[Dict[str, Any]], macro: str, stego: str
) -> str:
    """Calcula veredicto global en función de señales individuales."""

    if clam.get("status") == "infected":
        return "malicious"

    if yara_matches and any("critical" in (m.get("tags") or []) for m in yara_matches):
        return "critical"

    if macro == "yes" or stego in {"possible", "yes"} or yara_matches:
        return "suspicious"

    if clam.get("status") in {"clean", "not_available"} and not yara_matches:
        return "clean"

    return "suspicious"


def analyze_file(file_path: str | os.PathLike[str], mime_hint: str | None = None) -> Dict[str, Any]:
    """Ejecuta el análisis completo sobre un fichero.

    Devuelve un diccionario con todos los campos necesarios para
    rellenar el modelo Analysis.
    """

    path = Path(file_path)

    hashes = _compute_hashes(path)
    mime_type = _detect_mime(path, mime_hint=mime_hint)

    clam = _run_clamav(path)
    yara_matches = _run_yara(path)
    macro = _detect_macros(path)
    stego_status, stego_info = _analyze_steganography(path, mime_type)

    # Integración con sandbox dinámico (hook). El resultado se usa para
    # rellenar sandbox_score y se adjunta completo en additional_results
    # bajo la clave "sandbox" para que los informes puedan mostrar
    # detalles adicionales (tags, familia, resumen, etc.).
    sandbox_result = _run_sandbox(path, mime_type)
    sandbox_score: float | None = None
    if isinstance(sandbox_result, dict):
        try:
            val = sandbox_result.get("score")
            sandbox_score = float(val) if val is not None else None
        except Exception:  # pragma: no cover
            sandbox_score = None

    audio_analysis = ""
    # Audio avanzado sólo para WAV/WAVE, para alinearlo con la
    # detección de esteganografía basada en LSB y evitar MP3.
    if path.suffix.lower() in {".wav", ".wave"}:
        audio_analysis = _analyze_audio(path, mime_type)

    metadata = _extract_basic_metadata(path, mime_type)

    # Extracción opcional de texto y metadatos ricos de documentos
    # (PDF, Office, etc.) mediante Apache Tika. Se limita a tipos de
    # fichero donde esta información aporta valor práctico.
    ext = path.suffix.lower()
    is_pdf = mime_type == "application/pdf" or ext == ".pdf"
    is_office = ext in {
        ".doc",
        ".docx",
        ".docm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptx",
        ".pptm",
    }
    if is_pdf or is_office:
        doc_text = _extract_document_text_via_tika(path, mime_type)
        if doc_text:
            metadata["document_text"] = doc_text

    # Detalles de macros (si existen) se guardan en additional_results
    macro_details = _extract_macro_details(path)
    if macro_details:
        metadata["macro_details"] = macro_details

    # Espectrograma de audio opcional (sólo WAV/WAVE soportados)
    audio_spectrogram = None
    if path.suffix.lower() in {".wav", ".wave"}:
        audio_spectrogram = _generate_audio_spectrogram(path)
        if audio_spectrogram:
            metadata["audio_spectrogram"] = audio_spectrogram

    # Attach detailed steganography information (if any) into the
    # generic additional metadata structure so that the report can show
    # a dedicated block for it without changing the database schema.
    if stego_info:
        metadata["steganography"] = stego_info

    # Attach sandbox dynamic analysis information (if any) into
    # additional_results so that reports can render a dedicated block
    # without modificar el esquema de base de datos.
    if sandbox_result:
        metadata["sandbox"] = sandbox_result

    # VirusTotal: trabajamos sólo con el hash para no subir archivos.
    vt_result = _run_virustotal(hashes["sha256"]) if hashes.get("sha256") else {"status": "no_hash"}
    verdict = _decide_verdict(clam, yara_matches, macro, stego_status)

    summary_parts = [
        f"Veredicto: {verdict}",
        f"ClamAV: {clam.get('status')}",
        f"YARA: {len(yara_matches)} coincidencia(s)",
    ]
    if macro == "yes":
        summary_parts.append("Macros sospechosas detectadas")
    if stego_status in {"possible", "yes"}:
        summary_parts.append("Indicadores de esteganografía detectados")
    if sandbox_score is not None:
        summary_parts.append(f"Sandbox score: {sandbox_score}")

    cfg = current_app.config if current_app else {}
    engine_version = str(cfg.get("FORENALYZE_ENGINE_VERSION", "1.0"))
    ruleset_version = str(cfg.get("FORENALYZE_RULESET_VERSION", "default"))

    return {
        **hashes,
        "mime_type": mime_type,
        "yara_result": json.dumps(yara_matches, ensure_ascii=False) if yara_matches else None,
        "antivirus_result": json.dumps(clam, ensure_ascii=False),
        "virustotal_result": json.dumps(vt_result, ensure_ascii=False) if vt_result else None,
        "macro_detected": macro,
        "stego_detected": stego_status,
        "audio_analysis": audio_analysis or None,
        "sandbox_score": sandbox_score,
        "final_verdict": verdict,
        "summary": "; ".join(summary_parts),
        "engine_version": engine_version,
        "ruleset_version": ruleset_version,
        "additional_results": json.dumps(metadata, ensure_ascii=False),
    }
