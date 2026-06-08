from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.analysis.pipeline import analyze_file

SAMPLES = [
    "samples/stego_image_1.png",
    "samples/stego_image_2.png",
    "samples/stego_audio_lsb.wav",
    "samples/audio_sample_stego.wav",
    "samples/This is a malicious document.docm",
    "samples/lab_pdf_stego_base64_marker.pdf",
    "samples/lab_exe_marker_dummy.exe",
]


def main() -> None:
    for rel in SAMPLES:
        p = Path(rel)
        if not p.exists():
            print("MISSING", rel)
            continue
        r = analyze_file(str(p))
        print("\n===", rel)
        print("mime_type:", r.get("mime_type"))
        print("final_verdict:", r.get("final_verdict"))
        print("macro_detected:", r.get("macro_detected"))
        print("stego_detected:", r.get("stego_detected"))
        av = json.loads(r.get("antivirus_result")) if r.get("antivirus_result") else None
        clam_status = av.get("status") if isinstance(av, dict) else None
        print("clam_status:", clam_status)
        yara = json.loads(r.get("yara_result")) if r.get("yara_result") else []
        yara_count = len(yara) if isinstance(yara, list) else None
        print("yara_matches:", yara_count)


if __name__ == "__main__":
    main()
