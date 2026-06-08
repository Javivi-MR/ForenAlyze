from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LabSample:
    relpath: str
    description: str


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"
YARA_RULE_PATH = REPO_ROOT / "yara-signature-base" / "yara" / "lab_yara_rules_critical.yar"

MARKER = "FORENALYZE_LAB_CRITICAL"


def _write_bytes(path: Path, data: bytes, force: bool) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        return False
    path.write_bytes(data)
    return True


def _make_minimal_pdf_with_base64_and_marker(marker: str) -> bytes:
    """Create a small, valid PDF that contains:

    - A visible marker text on the page (marker)
    - A long base64 blob in a comment (benign text), so the stego heuristic
      (_scan_embedded_base64) can flag it as embedded_base64.

    This is intended for lab evaluation only.
    """

    benign_text = (
        "ForenAlyze lab dataset: embedded base64 payload (benign).\n"
        "This is NOT malware; it is used to test the steganography heuristic.\n"
        "Marker: "
        + marker
        + "\n"
    )
    b64 = base64.b64encode(benign_text.encode("utf-8")).decode("ascii")
    # ensure the sequence is long enough for the regex {40,}
    if len(b64) < 80:
        b64 = b64 * (80 // max(len(b64), 1) + 1)

    # PDF objects (we'll compute offsets for xref)
    parts: list[bytes] = []

    def add(s: str) -> None:
        parts.append(s.encode("latin-1"))

    add("%PDF-1.4\n")
    add(f"% LAB_BASE64:{b64}\n")

    offsets: list[int] = [0]  # object 0 is special

    def add_obj(obj_num: int, body: str) -> None:
        # record offset where this object starts in final buffer
        offsets.append(sum(len(p) for p in parts))
        add(f"{obj_num} 0 obj\n{body}\nendobj\n")

    # 1) Catalog
    add_obj(1, "<< /Type /Catalog /Pages 2 0 R >>")

    # 2) Pages
    add_obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")

    # 3) Page
    add_obj(
        3,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> >>",
    )

    # 4) Content stream
    content = f"BT /F1 24 Tf 72 720 Td ({marker}) Tj ET\n"
    content_bytes = content.encode("latin-1")
    stream = b"stream\n" + content_bytes + b"endstream"
    add_obj(4, f"<< /Length {len(content_bytes)} >>\n" + stream.decode("latin-1"))

    # 5) Font
    add_obj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    # xref
    xref_offset = sum(len(p) for p in parts)
    add("xref\n")
    add(f"0 {len(offsets)}\n")
    add("0000000000 65535 f \n")
    # objects 1..N
    for off in offsets[1:]:
        add(f"{off:010d} 00000 n \n")

    # trailer
    add("trailer\n")
    add(f"<< /Size {len(offsets)} /Root 1 0 R >>\n")
    add("startxref\n")
    add(f"{xref_offset}\n")
    add("%%EOF\n")

    return b"".join(parts)


def _make_dummy_mz_exe_with_marker(marker: str) -> bytes:
    """Create a non-functional MZ-like binary containing a marker.

    This is NOT a working executable; it's a harmless byte container
    useful for YARA matching in controlled tests.
    """

    # Minimal DOS header signature
    blob = bytearray(b"MZ")
    blob.extend(b"\x00" * 58)  # pad typical header size
    blob.extend(b"This is a ForenAlyze lab dummy binary.\x00")
    blob.extend(marker.encode("ascii"))
    blob.extend(b"\x00" * 256)
    return bytes(blob)


def _write_lab_yara_rule(path: Path, force: bool) -> bool:
    rule = f"""rule ForenAlyze_Lab_Critical_Marker
{{
    meta:
        description = "ForenAlyze controlled lab marker for critical YARA alert tests"
        severity = "critical"
    strings:
        $marker = "{MARKER}" ascii
    condition:
        $marker
}}
"""
    return _write_bytes(path, rule.encode("utf-8"), force)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create controlled ForenAlyze lab alarm samples")
    parser.add_argument("--samples-dir", type=Path, default=SAMPLES_DIR)
    parser.add_argument("--yara-rule-path", type=Path, default=YARA_RULE_PATH)
    parser.add_argument("--force", action="store_true", help="Overwrite existing lab samples/rule")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    created: list[LabSample] = []
    skipped: list[LabSample] = []

    # PDF that triggers embedded-content/stego heuristics and contains marker.
    pdf_path = args.samples_dir / "pdf_hidden_payload_01.pdf"
    pdf_sample = LabSample(
        relpath=str(pdf_path.relative_to(REPO_ROOT)).replace("\\", "/"),
        description="Valid PDF with embedded base64 (benign) + marker text; triggers hidden-payload/stego heuristic.",
    )
    if _write_bytes(pdf_path, _make_minimal_pdf_with_base64_and_marker(MARKER), args.force):
        created.append(pdf_sample)
    else:
        skipped.append(pdf_sample)

    # Dummy EXE for YARA-critical demonstrations.
    exe_path = args.samples_dir / "exe_suspicious_01.exe"
    exe_sample = LabSample(
        relpath=str(exe_path.relative_to(REPO_ROOT)).replace("\\", "/"),
        description="Harmless MZ-like dummy containing marker; intended for YARA tag=critical demos.",
    )
    if _write_bytes(exe_path, _make_dummy_mz_exe_with_marker(MARKER), args.force):
        created.append(exe_sample)
    else:
        skipped.append(exe_sample)

    rule_sample = LabSample(
        relpath=str(args.yara_rule_path.relative_to(REPO_ROOT)).replace("\\", "/"),
        description="YARA rule that matches the controlled lab marker and marks it as critical.",
    )
    if _write_lab_yara_rule(args.yara_rule_path, args.force):
        created.append(rule_sample)
    else:
        skipped.append(rule_sample)

    if created:
        print("Created lab artifacts:")
        for sample in created:
            print(f"- {sample.relpath}: {sample.description}")
    if skipped:
        print("Skipped existing artifacts (use --force to overwrite):")
        for sample in skipped:
            print(f"- {sample.relpath}: {sample.description}")

    print(
        "\nAfter using --force, refresh samples/evaluation_manifest.csv with "
        "tools/generate_results_csv.py --init-manifest or update the affected "
        "hash/size fields manually."
    )


if __name__ == "__main__":
    main()
