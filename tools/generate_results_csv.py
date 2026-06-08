"""Generate the evaluation summary CSV requested for the ForenAlyze paper.

Reads ground-truth metadata from ``samples/evaluation_manifest.csv``, runs the
analysis pipeline on each sample, and writes ``results.csv`` with one row per
file.

Usage (from repo root, inside venv or Docker container):

    python tools/generate_results_csv.py

    python tools/generate_results_csv.py --output evaluation_dataset/results.csv

    # Create / refresh manifest skeleton from files currently in samples/
    python tools/generate_results_csv.py --init-manifest

    # Validate manifest and list missing files without running analysis
    python tools/generate_results_csv.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_MANIFEST = REPO_ROOT / "samples" / "evaluation_manifest.csv"
DEFAULT_OUTPUT = REPO_ROOT / "evaluation_dataset" / "results.csv"
DEFAULT_REPORTS_JSON = REPO_ROOT / "evaluation_dataset" / "reports_json"
DEFAULT_REPORTS_PDF = REPO_ROOT / "evaluation_dataset" / "reports_pdf"
DEFAULT_EXPECTED_COUNT = 19

ALLOWED_GROUND_TRUTH_LABELS = {
    "clean",
    "macro",
    "stego",
    "suspicious",
    "malicious",
}

MANIFEST_FIELDS = [
    "sample_id",
    "filename",
    "file_type",
    "file_hash_sha256",
    "file_size_bytes",
    "source",
    "created_with",
    "ground_truth_label",
    "expected_signal",
    "notes",
    "final_confidence",
]

RESULT_FIELDS = [
    "sample_id",
    "filename",
    "file_type",
    "file_hash_sha256",
    "file_size_bytes",
    "source",
    "created_with",
    "ground_truth_label",
    "expected_signal",
    "notes",
    "final_verdict_forenalyze",
    "final_confidence",
    "clamav_detection",
    "yara_matches",
    "macro_detected",
    "stego_detected",
    "virustotal_used",
    "sandbox_used",
    "alert_generated",
    "report_exported_json",
    "report_exported_pdf",
    "analysis_time_seconds",
    "comments",
]

SKIP_SUFFIXES = {
    ".csv",
    ".md",
    ".txt",
    ".yar",
    ".py",
    ".cpp",
    ".json",
    ".winmd",
}

SKIP_FILENAMES = {
    "evaluation_manifest.csv",
    "alarm_manifest.csv",
    "README.txt",
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_ground_truth_label(value: str) -> str:
    label = value.strip().lower()
    aliases = {
        "benign": "clean",
        "safe": "clean",
        "malware": "malicious",
        "trojan": "malicious",
        "hidden_payload": "stego",
        "embedded_content": "stego",
    }
    return aliases.get(label, label)


def _manifest_defaults(sample_path: Path, row: dict[str, str] | None = None) -> dict[str, str]:
    row = row or {}
    label, signal = _guess_ground_truth(sample_path.name)
    final_label = _normalise_ground_truth_label(row.get("ground_truth_label") or label)
    return {
        "sample_id": row.get("sample_id") or _make_sample_id(sample_path.name, 0),
        "filename": row.get("filename") or sample_path.name,
        "file_type": row.get("file_type") or _guess_file_type(sample_path.name),
        "file_hash_sha256": row.get("file_hash_sha256") or _file_sha256(sample_path),
        "file_size_bytes": row.get("file_size_bytes") or str(sample_path.stat().st_size),
        "source": row.get("source") or "local_lab_sample",
        "created_with": row.get("created_with") or "ForenAlyze lab sample set",
        "ground_truth_label": final_label,
        "expected_signal": row.get("expected_signal") or signal,
        "notes": row.get("notes") or "",
        "final_confidence": row.get("final_confidence") or "high",
    }


def _guess_ground_truth(filename: str) -> tuple[str, str]:
    """Infer a default label and expected signal from the filename."""

    name = filename.lower()
    if "eicar" in name or "malware" in name:
        return "malicious", "Antivirus test signature or malware marker"
    if "macro" in name or "malicious document" in name or name.endswith(".docm"):
        return "macro", "VBA macros present"
    if "stego" in name or "lsb" in name:
        if name.endswith((".wav", ".wave", ".mp3")):
            return "stego", "Hidden content in audio (LSB or metadata)"
        if name.endswith((".png", ".jpg", ".jpeg", ".bmp", ".gif")):
            return "stego", "LSB hidden text present"
        if name.endswith(".pdf"):
            return "stego", "Embedded base64 or hidden payload in PDF"
    if name.startswith("lab_") and name.endswith(".exe"):
        return "suspicious", "Lab marker for controlled YARA/critical demo"
    if "clean" in name or "benign" in name or "sample_clean" in name:
        return "clean", "No malicious indicators expected"
    if name.endswith((".exe", ".dll", ".com", ".scr")):
        return "suspicious", "Executable requires manual ground-truth review"
    if name.endswith((".docm", ".xlsm", ".pptm")):
        return "macro", "Macro-enabled Office document"
    return "clean", "Benign reference sample (verify manually)"


def _guess_file_type(filename: str, mime_type: str | None = None) -> str:
    ext = Path(filename).suffix.lower()
    mapping = {
        ".pdf": "application/pdf",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".docm": "application/vnd.ms-word.document.macroEnabled.12",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
        ".exe": "application/x-msdownload",
        ".com": "application/x-msdownload",
        ".dll": "application/x-msdownload",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".wav": "audio/x-wav",
        ".wave": "audio/x-wav",
    }
    if mime_type:
        return mime_type
    return mapping.get(ext, ext.lstrip(".") or "unknown")


def _discover_sample_files(samples_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(samples_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name in SKIP_FILENAMES:
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(path)
    return files


def _make_sample_id(filename: str, index: int) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", Path(filename).stem).strip("_").upper()
    if not stem:
        stem = f"SAMPLE_{index:02d}"
    return stem[:40]


def init_manifest(samples_dir: Path, manifest_path: Path) -> None:
    files = _discover_sample_files(samples_dir)
    if not files:
        raise SystemExit(f"No sample files found in {samples_dir}")

    rows: list[dict[str, str]] = []
    for idx, path in enumerate(files, start=1):
        label, signal = _guess_ground_truth(path.name)
        rows.append(
            _manifest_defaults(
                path,
                {
                    "sample_id": _make_sample_id(path.name, idx),
                    "ground_truth_label": label,
                    "expected_signal": signal,
                },
            )
        )

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote manifest with {len(rows)} samples -> {manifest_path}")
    print("Review ground_truth_label and expected_signal before generating results.")


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    if not manifest_path.exists():
        raise SystemExit(
            f"Manifest not found: {manifest_path}\n"
            "Run with --init-manifest to create it from files in samples/."
        )

    with manifest_path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        base_fields = ["sample_id", "filename", "file_type", "ground_truth_label", "expected_signal"]
        missing = [f for f in base_fields if f not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"Manifest missing columns: {', '.join(missing)}")

        rows = []
        for row in reader:
            if not (row.get("filename") or "").strip():
                continue
            sample_path = manifest_path.parent / (row.get("filename") or "").strip()
            clean_row = {k: (row.get(k) or "").strip() for k in MANIFEST_FIELDS}
            clean_row["ground_truth_label"] = _normalise_ground_truth_label(clean_row["ground_truth_label"])
            if sample_path.exists():
                clean_row = _manifest_defaults(sample_path, clean_row)
            rows.append(clean_row)
        return rows


def validate_manifest(rows: list[dict[str, str]], samples_dir: Path, expected_count: int | None) -> None:
    errors: list[str] = []

    if expected_count is not None and len(rows) != expected_count:
        errors.append(f"Manifest has {len(rows)} rows; expected {expected_count}.")

    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    for row in rows:
        sample_id = row["sample_id"]
        filename = row["filename"]
        label = row["ground_truth_label"]
        path = samples_dir / filename

        if sample_id in seen_ids:
            errors.append(f"Duplicate sample_id: {sample_id}")
        seen_ids.add(sample_id)

        if filename in seen_names:
            errors.append(f"Duplicate filename: {filename}")
        seen_names.add(filename)

        if label not in ALLOWED_GROUND_TRUTH_LABELS:
            errors.append(
                f"[{sample_id}] invalid ground_truth_label={label!r}; "
                f"use one of {', '.join(sorted(ALLOWED_GROUND_TRUTH_LABELS))}"
            )

        if not path.exists():
            errors.append(f"[{sample_id}] missing file: {filename}")
            continue

        actual_hash = _file_sha256(path)
        if row.get("file_hash_sha256") and row["file_hash_sha256"] != actual_hash:
            errors.append(f"[{sample_id}] file_hash_sha256 does not match current file")

        actual_size = str(path.stat().st_size)
        if row.get("file_size_bytes") and row["file_size_bytes"] != actual_size:
            errors.append(f"[{sample_id}] file_size_bytes does not match current file")

    if errors:
        raise SystemExit("Manifest validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


def _parse_json_field(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _clamav_detection(antivirus_result: str | None) -> str:
    data = _parse_json_field(antivirus_result)
    if not isinstance(data, dict):
        return "unknown"
    status = data.get("status")
    if status == "infected":
        detail = data.get("detail") or data.get("signature") or "infected"
        return f"infected: {detail}"
    return str(status or "unknown")


def _yara_match_count(yara_result: str | None) -> int:
    data = _parse_json_field(yara_result)
    if isinstance(data, list):
        return len(data)
    return 0


def _virustotal_used(virustotal_result: str | None) -> str:
    data = _parse_json_field(virustotal_result)
    if not isinstance(data, dict):
        return "no"
    status = str(data.get("status") or "")
    if status in {"ok", "cached"}:
        stats = data.get("stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        total = malicious + suspicious + harmless + undetected
        detections = malicious + suspicious
        return f"yes ({detections}/{total})" if total else "yes"
    if status in {"disabled", "not_configured"}:
        return f"no ({status})"
    return f"no ({status or 'unknown'})"


def _sandbox_used(additional_results: str | None, sandbox_score) -> str:
    data = _parse_json_field(additional_results)
    sandbox = data.get("sandbox") if isinstance(data, dict) else None
    if isinstance(sandbox, dict):
        status = sandbox.get("status")
        score = sandbox.get("score", sandbox_score)
        if status in {"disabled", "not_configured", "error", "failed", "timeout"}:
            return f"no ({status})"
        if status:
            if score is not None:
                return f"yes ({status}, score={score})"
            return f"yes ({status})"
    if sandbox_score is not None:
        return f"yes (score={sandbox_score})"
    return "no"


def _security_alert_generated(
    final_verdict: str | None,
    macro_detected: str | None,
    stego_detected: str | None,
) -> str:
    """Mirror app.services.alerts.create_alerts_for_analysis (security alerts only)."""

    alerts: list[str] = []
    if final_verdict in {"malicious", "critical"}:
        alerts.append("malware")
    if macro_detected == "yes":
        alerts.append("macros")
    if stego_detected in {"possible", "yes"}:
        alerts.append("stego")
    return "yes (" + ", ".join(alerts) + ")" if alerts else "no"


def _export_exists(base_dir: Path | None, sample_id: str, suffix: str) -> str:
    if base_dir is None or not base_dir.exists():
        return "no"
    exact = base_dir / f"{sample_id}{suffix}"
    if exact.exists():
        return "yes"
    matches = sorted(base_dir.glob(f"{sample_id}*{suffix}"))
    return "yes" if matches else "no"


def _build_comments(
    ground_truth: str,
    expected_signal: str,
    result: dict,
    yara_count: int,
) -> str:
    notes: list[str] = []
    verdict = result.get("final_verdict") or "unknown"
    macro = result.get("macro_detected") or "no"
    stego = result.get("stego_detected") or "no"

    benign_labels = {"clean", "benign"}
    malicious_labels = {"malicious", "suspicious", "stego", "macro"}

    if ground_truth in benign_labels and verdict not in {"clean", "unknown"}:
        notes.append(f"possible false positive (ground_truth={ground_truth}, verdict={verdict})")
    elif ground_truth in malicious_labels and verdict == "clean":
        notes.append(f"possible false negative (ground_truth={ground_truth}, verdict={verdict})")

    if ground_truth == "macro" and macro != "yes":
        notes.append("macro expected but macro_detected != yes")
    if ground_truth == "stego" and stego not in {"possible", "yes"}:
        notes.append("stego expected but stego_detected not triggered")
    if ground_truth == "suspicious" and yara_count == 0 and verdict not in {"suspicious", "malicious", "critical"}:
        notes.append("suspicious/YARA signal expected but not observed")

    av = _parse_json_field(result.get("antivirus_result"))
    if isinstance(av, dict) and av.get("status") == "error":
        notes.append(f"ClamAV error: {av.get('detail', 'unknown')}")

    vt = _parse_json_field(result.get("virustotal_result"))
    if isinstance(vt, dict) and vt.get("status") in {"error", "auth_error", "rate_limited"}:
        notes.append(f"VirusTotal issue: {vt.get('status')}")

    if expected_signal and expected_signal.lower() not in (result.get("summary") or "").lower():
        # Keep this lightweight: only flag obvious mismatches via verdict fields.
        pass

    return "; ".join(notes)


def _find_export_json(exports_dir: Path, sample_id: str, filename: str) -> Path | None:
    candidates = [
        exports_dir / f"{sample_id}.json",
        exports_dir / f"{Path(filename).stem}.json",
        exports_dir / f"{filename.replace(' ', '_')}.json",
    ]
    for path in candidates:
        if path.exists():
            return path
    matches = sorted(exports_dir.glob(f"*{sample_id}*.json"))
    if matches:
        return matches[0]
    stem = Path(filename).stem.lower().replace(" ", "_")
    for path in sorted(exports_dir.glob("*.json")):
        if stem in path.stem.lower():
            return path
    return None


def row_from_export_json(
    row: dict[str, str],
    export_path: Path,
    reports_json_dir: Path | None,
    reports_pdf_dir: Path | None,
) -> dict[str, str]:
    payload = json.loads(export_path.read_text(encoding="utf-8"))
    analysis = payload.get("analysis") if isinstance(payload, dict) else None
    if not isinstance(analysis, dict):
        raise ValueError(f"Invalid export JSON structure: {export_path}")

    yara = analysis.get("yara_result")
    yara_count = len(yara) if isinstance(yara, list) else 0

    pseudo_result = {
        "final_verdict": analysis.get("final_verdict"),
        "macro_detected": analysis.get("macro_detected"),
        "stego_detected": analysis.get("stego_detected"),
        "antivirus_result": json.dumps(analysis.get("antivirus_result"))
        if analysis.get("antivirus_result") is not None
        else None,
        "virustotal_result": json.dumps(analysis.get("virustotal_result"))
        if analysis.get("virustotal_result") is not None
        else None,
        "additional_results": json.dumps(analysis.get("additional_results"))
        if analysis.get("additional_results") is not None
        else None,
        "sandbox_score": analysis.get("sandbox_score"),
        "summary": analysis.get("summary") or "",
    }

    json_flag = "yes"
    return {
        "sample_id": row["sample_id"],
        "filename": row["filename"],
        "file_type": analysis.get("mime_type") or row.get("file_type") or _guess_file_type(row["filename"]),
        "file_hash_sha256": row["file_hash_sha256"],
        "file_size_bytes": row["file_size_bytes"],
        "source": row["source"],
        "created_with": row["created_with"],
        "ground_truth_label": row["ground_truth_label"],
        "expected_signal": row["expected_signal"],
        "notes": row["notes"],
        "final_verdict_forenalyze": analysis.get("final_verdict") or "",
        "final_confidence": row["final_confidence"],
        "clamav_detection": _clamav_detection(pseudo_result.get("antivirus_result")),
        "yara_matches": str(yara_count),
        "macro_detected": analysis.get("macro_detected") or "no",
        "stego_detected": analysis.get("stego_detected") or "no",
        "virustotal_used": _virustotal_used(pseudo_result.get("virustotal_result")),
        "sandbox_used": _sandbox_used(
            pseudo_result.get("additional_results"),
            analysis.get("sandbox_score"),
        ),
        "alert_generated": _security_alert_generated(
            analysis.get("final_verdict"),
            analysis.get("macro_detected"),
            analysis.get("stego_detected"),
        ),
        "report_exported_json": json_flag,
        "report_exported_pdf": _export_exists(reports_pdf_dir, row["sample_id"], ".pdf"),
        "analysis_time_seconds": str(analysis.get("analysis_time_seconds") or ""),
        "comments": _build_comments(
            row["ground_truth_label"],
            row["expected_signal"],
            pseudo_result,
            yara_count,
        ),
    }


def analyze_manifest_row(
    samples_dir: Path,
    row: dict[str, str],
    reports_json_dir: Path | None,
    reports_pdf_dir: Path | None,
) -> dict[str, str]:
    from app import create_app
    from app.analysis.pipeline import analyze_file

    filename = row["filename"]
    sample_path = samples_dir / filename
    if not sample_path.exists():
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    app = create_app()
    started = time.perf_counter()
    with app.app_context():
        result = analyze_file(str(sample_path))
    elapsed_seconds = time.perf_counter() - started

    yara_count = _yara_match_count(result.get("yara_result"))
    comments = _build_comments(
        row["ground_truth_label"],
        row["expected_signal"],
        result,
        yara_count,
    )

    mime = result.get("mime_type") or row.get("file_type") or _guess_file_type(filename)

    return {
        "sample_id": row["sample_id"],
        "filename": filename,
        "file_type": mime,
        "file_hash_sha256": row["file_hash_sha256"],
        "file_size_bytes": row["file_size_bytes"],
        "source": row["source"],
        "created_with": row["created_with"],
        "ground_truth_label": row["ground_truth_label"],
        "expected_signal": row["expected_signal"],
        "notes": row["notes"],
        "final_verdict_forenalyze": result.get("final_verdict") or "",
        "final_confidence": row["final_confidence"],
        "clamav_detection": _clamav_detection(result.get("antivirus_result")),
        "yara_matches": str(yara_count),
        "macro_detected": result.get("macro_detected") or "no",
        "stego_detected": result.get("stego_detected") or "no",
        "virustotal_used": _virustotal_used(result.get("virustotal_result")),
        "sandbox_used": _sandbox_used(result.get("additional_results"), result.get("sandbox_score")),
        "alert_generated": _security_alert_generated(
            result.get("final_verdict"),
            result.get("macro_detected"),
            result.get("stego_detected"),
        ),
        "report_exported_json": _export_exists(reports_json_dir, row["sample_id"], ".json"),
        "report_exported_pdf": _export_exists(reports_pdf_dir, row["sample_id"], ".pdf"),
        "analysis_time_seconds": f"{elapsed_seconds:.3f}",
        "comments": comments,
    }


def write_results_csv(output_path: Path, rows: list[dict[str, str]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {output_path}")


def write_readme_stub(output_dir: Path, manifest_path: Path, config_notes: str) -> None:
    readme = output_dir / "README.txt"
    if readme.exists():
        return
    text = (
        "ForenAlyze evaluation dataset\n"
        "=============================\n\n"
        f"Generated at (UTC): {datetime.now(timezone.utc).isoformat()}\n"
        f"Manifest: {manifest_path.relative_to(REPO_ROOT)}\n"
        f"Results: results.csv\n\n"
        "Configuration notes:\n"
        f"{config_notes}\n"
    )
    readme.write_text(text, encoding="utf-8")
    print(f"Wrote README stub -> {readme}")


def _config_summary() -> str:
    import os

    lines = [
        f"YARA_ENABLED={os.environ.get('YARA_ENABLED', 'false')}",
        f"YARA_RULES_PATH={os.environ.get('YARA_RULES_PATH', '(not set)')}",
        f"CLAMAV_PATH={os.environ.get('CLAMAV_PATH', 'clamscan')}",
        f"VIRUSTOTAL_ENABLED={os.environ.get('VIRUSTOTAL_ENABLED', 'true')}",
        f"VIRUSTOTAL_API_KEY={'set' if os.environ.get('VIRUSTOTAL_API_KEY') else 'not set'}",
        f"SANDBOX_ENABLED={os.environ.get('SANDBOX_ENABLED', 'false')}",
        f"SANDBOX_MODE={os.environ.get('SANDBOX_MODE', 'disabled')}",
        f"TIKA_ENABLED={os.environ.get('TIKA_ENABLED', 'false')}",
        f"TIKA_SERVER_URL={os.environ.get('TIKA_SERVER_URL', '(not set)')}",
    ]
    return "\n".join(f"- {line}" for line in lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate ForenAlyze evaluation results.csv")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--samples-dir", type=Path, default=REPO_ROOT / "samples")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--reports-json-dir", type=Path, default=DEFAULT_REPORTS_JSON)
    parser.add_argument("--reports-pdf-dir", type=Path, default=DEFAULT_REPORTS_PDF)
    parser.add_argument("--init-manifest", action="store_true", help="Create manifest from samples/ and exit")
    parser.add_argument("--dry-run", action="store_true", help="Validate manifest/files only")
    parser.add_argument(
        "--expected-count",
        type=int,
        default=DEFAULT_EXPECTED_COUNT,
        help="Expected number of manifest rows. Use 0 to disable the count check.",
    )
    parser.add_argument("--write-readme", action="store_true", help="Create evaluation_dataset/README.txt stub")
    parser.add_argument(
        "--from-json-dir",
        type=Path,
        default=None,
        help="Build results from exported JSON files instead of running the pipeline",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.init_manifest:
        init_manifest(args.samples_dir, args.manifest)
        return

    rows = load_manifest(args.manifest)
    if not rows:
        raise SystemExit("Manifest is empty.")

    expected_count = args.expected_count if args.expected_count > 0 else None
    validate_manifest(rows, args.samples_dir, expected_count)

    if args.dry_run:
        print(f"Manifest OK: {len(rows)} samples found in {args.samples_dir}")
        for row in rows:
            print(
                f"  [{row['sample_id']}] {row['filename']} "
                f"({row['ground_truth_label']}, {row['file_size_bytes']} bytes)"
            )
        return

    result_rows: list[dict[str, str]] = []
    for row in rows:
        if args.from_json_dir:
            export_path = _find_export_json(args.from_json_dir, row["sample_id"], row["filename"])
            if export_path is None:
                raise SystemExit(
                    f"No export JSON found for [{row['sample_id']}] {row['filename']} in {args.from_json_dir}"
                )
            print(f"Reading export [{row['sample_id']}] <- {export_path.name}")
            result_rows.append(
                row_from_export_json(
                    row,
                    export_path,
                    args.reports_json_dir,
                    args.reports_pdf_dir,
                )
            )
        else:
            print(f"Analyzing [{row['sample_id']}] {row['filename']} ...")
            result_rows.append(
                analyze_manifest_row(
                    args.samples_dir,
                    row,
                    args.reports_json_dir,
                    args.reports_pdf_dir,
                )
            )

    write_results_csv(args.output, result_rows)

    if args.write_readme:
        write_readme_stub(args.output.parent, args.manifest, _config_summary())


if __name__ == "__main__":
    main()
