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

import base64
import hashlib
import json
import mimetypes
import os
import re
import string
import subprocess
import wave
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

try:  # type: ignore[unused-ignore]
    import numpy as np  # type: ignore[import]
    import matplotlib.pyplot as plt  # type: ignore[import]
except Exception:  # pragma: no cover - dependencias opcionales para espectrogramas
    np = None  # type: ignore[assignment]
    plt = None  # type: ignore[assignment]


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
            result.update(
                {
                    "base64_decoded_preview": base64_info["decoded_preview"][:200],
                    "base64_decoded_length": base64_info["decoded_length"],
                    "base64_decoded_full": base64_info.get("decoded_full"),
                }
            )

        return result

    return None


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
        result.update(
            {
                "base64_decoded_preview": base64_info["decoded_preview"][:200],
                "base64_decoded_length": base64_info["decoded_length"],
                "base64_decoded_full": base64_info.get("decoded_full"),
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

    details: Dict[str, Any] = {
        "category": "image" if is_image else "audio" if is_audio else "pdf" if is_pdf else "other",
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
                    }
                )
            details["notes"].append(
                "Printable content extracted from image LSB channels; steganography is very likely present."
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

    # Si seguimos sin nada relevante y el tipo no tiene análisis específico,
    # devolvemos None en los detalles para no ensuciar metadatos.
    if status == "no" and details["category"] == "other":
        return ("no", None)

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

    audio_analysis = ""
    # Audio avanzado sólo para WAV/WAVE, para alinearlo con la
    # detección de esteganografía basada en LSB y evitar MP3.
    if path.suffix.lower() in {".wav", ".wave"}:
        audio_analysis = _analyze_audio(path, mime_type)

    metadata = _extract_basic_metadata(path, mime_type)

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
        "stego_detected": stego_status,
        "audio_analysis": audio_analysis or None,
        "sandbox_score": None,
        "final_verdict": verdict,
        "summary": "; ".join(summary_parts),
        "engine_version": engine_version,
        "ruleset_version": ruleset_version,
        "additional_results": json.dumps(metadata, ensure_ascii=False),
    }
