from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LabSample:
    relpath: str
    description: str


REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"

MARKER = "FORENALYZE_LAB_CRITICAL"


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


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


def main() -> None:
    created: list[LabSample] = []

    # PDF that triggers stego (embedded base64) and contains marker
    pdf_path = SAMPLES_DIR / "lab_pdf_stego_base64_marker.pdf"
    _write_bytes(pdf_path, _make_minimal_pdf_with_base64_and_marker(MARKER))
    created.append(
        LabSample(
            relpath=str(pdf_path.relative_to(REPO_ROOT)).replace("\\", "/"),
            description="Valid PDF with embedded base64 (benign) + marker text; triggers stego heuristic.",
        )
    )

    # Optional dummy EXE for YARA-critical demonstrations
    exe_path = SAMPLES_DIR / "lab_exe_marker_dummy.exe"
    _write_bytes(exe_path, _make_dummy_mz_exe_with_marker(MARKER))
    created.append(
        LabSample(
            relpath=str(exe_path.relative_to(REPO_ROOT)).replace("\\", "/"),
            description="Harmless MZ-like dummy containing marker; intended for YARA tag=critical demos.",
        )
    )

    print("Created lab samples:")
    for s in created:
        print(f"- {s.relpath}: {s.description}")


if __name__ == "__main__":
    main()
