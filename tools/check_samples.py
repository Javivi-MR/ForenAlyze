from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_MANIFEST = REPO_ROOT / "samples" / "evaluation_manifest.csv"


def _load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    with manifest_path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"sample_id", "filename", "ground_truth_label", "expected_signal"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise SystemExit(f"Manifest missing columns: {', '.join(missing)}")
        return [
            {k: (row.get(k) or "").strip() for k in reader.fieldnames or []}
            for row in reader
            if (row.get("filename") or "").strip()
        ]


def _parse_json(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _yara_match_names(yara_result: str | None) -> str:
    data = _parse_json(yara_result)
    if not isinstance(data, list):
        return "0"
    names: list[str] = []
    for item in data:
        if isinstance(item, dict):
            names.append(str(item.get("rule") or item.get("name") or "match"))
        else:
            names.append(str(item))
    return ";".join(names) if names else "0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run ForenAlyze over samples from evaluation_manifest.csv")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--samples-dir", type=Path, default=REPO_ROOT / "samples")
    parser.add_argument(
        "--label",
        choices=["clean", "macro", "stego", "suspicious", "malicious"],
        default=None,
        help="Only analyze samples with this ground-truth label.",
    )
    parser.add_argument("--sample-id", default=None, help="Only analyze one sample_id.")
    parser.add_argument("--limit", type=int, default=0, help="Analyze at most N rows.")
    return parser.parse_args()


def main() -> None:
    from app import create_app
    from app.analysis.pipeline import analyze_file

    args = parse_args()
    rows = _load_manifest(args.manifest)
    if args.label:
        rows = [row for row in rows if row.get("ground_truth_label") == args.label]
    if args.sample_id:
        rows = [row for row in rows if row.get("sample_id") == args.sample_id]
    if args.limit > 0:
        rows = rows[: args.limit]

    app = create_app()
    for row in rows:
        sample_id = row["sample_id"]
        filename = row["filename"]
        path = args.samples_dir / filename
        if not path.exists():
            print(f"MISSING [{sample_id}] {filename}")
            continue
        started = time.perf_counter()
        with app.app_context():
            r = analyze_file(str(path))
        elapsed = time.perf_counter() - started

        print(f"\n=== [{sample_id}] {filename}")
        print("ground_truth_label:", row.get("ground_truth_label"))
        print("expected_signal:", row.get("expected_signal"))
        print("mime_type:", r.get("mime_type"))
        print("final_verdict:", r.get("final_verdict"))
        print("macro_detected:", r.get("macro_detected"))
        print("stego_detected:", r.get("stego_detected"))
        av = _parse_json(r.get("antivirus_result"))
        clam_status = av.get("status") if isinstance(av, dict) else None
        print("clam_status:", clam_status)
        print("yara_matches:", _yara_match_names(r.get("yara_result")))
        print("analysis_time_seconds:", f"{elapsed:.3f}")


if __name__ == "__main__":
    main()
