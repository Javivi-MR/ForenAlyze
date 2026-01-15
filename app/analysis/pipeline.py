"""Pipeline de análisis de ficheros para ForenHub.

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

import hashlib
import json
import mimetypes
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import current_app

import requests


try:  # type: ignore[unused-ignore]
    import yara  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    yara = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    from mutagen import File as MutagenFile  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    MutagenFile = None  # type: ignore[assignment]

try:  # type: ignore[unused-ignore]
    from PIL import Image, ExifTags  # type: ignore[import]
except Exception:  # pragma: no cover - dependencia opcional
    Image = None  # type: ignore[assignment]
    ExifTags = None  # type: ignore[assignment]


@dataclass
class YaraConfig:
    enabled: bool
    rules_path: Optional[Path]


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

    try:
        proc = subprocess.run(
            ["clamscan", "--stdout", "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {"status": "not_available", "detail": "clamscan no encontrado"}
    except Exception as exc:  # pragma: no cover - errores raros de entorno
        return {"status": "error", "detail": f"error ejecutando clamscan: {exc}"}

    output = (proc.stdout or proc.stderr or "").strip()
    if "OK" in output and "FOUND" not in output:
        return {"status": "clean", "detail": output}
    if "FOUND" in output:
        return {"status": "infected", "detail": output}
    return {"status": "unknown", "detail": output}


def _load_yara_config() -> YaraConfig:
    cfg = current_app.config if current_app else {}
    enabled = bool(cfg.get("YARA_ENABLED", False))
    rules_path_cfg = cfg.get("YARA_RULES_PATH")
    rules_path = Path(rules_path_cfg) if rules_path_cfg else None
    if not yara or not enabled or not rules_path or not rules_path.exists():
        return YaraConfig(enabled=False, rules_path=None)
    return YaraConfig(enabled=True, rules_path=rules_path)


def _run_yara(path: Path) -> List[Dict[str, Any]]:
    conf = _load_yara_config()
    if not conf.enabled or not conf.rules_path:
        return []

    try:
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
    api_key = cfg.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"status": "not_configured"}

    headers = {
        "x-apikey": api_key,
    }
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except Exception as exc:  # pragma: no cover - errores de red
        return {"status": "error", "detail": f"error de red VirusTotal: {exc}"}

    if resp.status_code == 404:
        return {"status": "not_found"}

    if not resp.ok:
        return {
            "status": "error",
            "http_status": resp.status_code,
            "detail": resp.text[:500],
        }

    try:
        data = resp.json()
    except Exception:  # pragma: no cover
        return {"status": "error", "detail": "respuesta no es JSON"}

    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    result = {
        "status": "ok",
        "stats": stats,
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
    }
    return result


def _detect_macros(path: Path) -> str:
    """Detección muy básica de macros buscando patrones comunes en binario."""

    ext = path.suffix.lower()
    if ext not in {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm"}:
        return "no"

    try:
        data = path.read_bytes()
    except Exception:  # pragma: no cover - E/S
        return "unknown"

    patterns = [b"VBA", b"AutoOpen", b"Document_Open", b"ThisDocument"]
    for p in patterns:
        if p in data:
            return "yes"
    return "no"


def _analyze_audio(path: Path, mime_type: str) -> str:
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


def _analyze_steganography(path: Path, mime_type: str) -> str:
    """Heurística muy básica de posible esteganografía.

    No pretende ser una detección real, sólo un indicador simple.
    """

    ext = path.suffix.lower()
    is_image = mime_type.startswith("image/") or ext in {".jpg", ".jpeg", ".png", ".bmp", ".gif"}
    is_audio = mime_type.startswith("audio/") or ext in {".wav", ".mp3", ".flac"}

    try:
        size = path.stat().st_size
    except Exception:  # pragma: no cover
        return "unknown"

    if is_image and Image is not None:
        try:
            with Image.open(path) as img:  # type: ignore[call-arg]
                w, h = img.size
            # si el tamaño del fichero es muy superior al esperado para RGB simple
            expected = w * h * 3
            if size > expected * 3:
                return "possible"
        except Exception:  # pragma: no cover
            return "unknown"

    if is_audio:
        # heurística simplista: tamaños muy grandes para audios muy cortos se marcan como posibles
        # (si hay mutagen, podríamos refinar con duración real)
        if size > 50 * 1024 * 1024:  # > 50MB
            return "possible"

    return "no"


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


def _decide_verdict(
    clam: Dict[str, Any], yara_matches: List[Dict[str, Any]], macro: str, stego: str
) -> str:
    """Calcula veredicto global en función de señales individuales."""

    if clam.get("status") == "infected":
        return "malicious"

    if yara_matches and any("critical" in (m.get("tags") or []) for m in yara_matches):
        return "critical"

    if macro == "yes" or stego == "possible" or yara_matches:
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
    stego = _analyze_steganography(path, mime_type)

    audio_analysis = ""
    if mime_type.startswith("audio/") or path.suffix.lower() in {".wav", ".mp3", ".flac"}:
        audio_analysis = _analyze_audio(path, mime_type)

    metadata = _extract_basic_metadata(path, mime_type)

    # VirusTotal: trabajamos sólo con el hash para no subir archivos.
    vt_result = _run_virustotal(hashes["sha256"]) if hashes.get("sha256") else {"status": "no_hash"}
    verdict = _decide_verdict(clam, yara_matches, macro, stego)

    summary_parts = [
        f"Veredicto: {verdict}",
        f"ClamAV: {clam.get('status')}",
        f"YARA: {len(yara_matches)} coincidencia(s)",
    ]
    if macro == "yes":
        summary_parts.append("Macros sospechosas detectadas")
    if stego == "possible":
        summary_parts.append("Posible esteganografía detectada")

    cfg = current_app.config if current_app else {}
    engine_version = str(cfg.get("FORENHUB_ENGINE_VERSION", "1.0"))
    ruleset_version = str(cfg.get("FORENHUB_RULESET_VERSION", "default"))

    return {
        **hashes,
        "mime_type": mime_type,
        "yara_result": json.dumps(yara_matches, ensure_ascii=False) if yara_matches else None,
        "antivirus_result": json.dumps(clam, ensure_ascii=False),
        "virustotal_result": json.dumps(vt_result, ensure_ascii=False) if vt_result else None,
        "macro_detected": macro,
        "stego_detected": stego,
        "audio_analysis": audio_analysis or None,
        "sandbox_score": None,
        "final_verdict": verdict,
        "summary": "; ".join(summary_parts),
        "engine_version": engine_version,
        "ruleset_version": ruleset_version,
        "additional_results": json.dumps(metadata, ensure_ascii=False),
    }
