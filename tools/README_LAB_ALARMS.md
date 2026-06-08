# ForenAlyze lab alarm samples

This folder contains **lab / evaluation-only** samples designed to reliably trigger ForenAlyze alerts **without using real malware**.

## Quick start

- Upload the files listed in `alarm_manifest.csv` using the normal UI (`/upload`).
- For each sample, export:
  - JSON: `/analysis/<id>/export/json`
  - PDF: `/analysis/<id>/export/pdf`
- Capture screenshots:
  - File list / upload confirmation
  - Verdict in the list/dashboard
  - Final HTML report (`/analysis/<id>/report`)

## What triggers alerts

ForenAlyze generates alerts when:

- `macro_detected == "yes"` (Office macros)
- `stego_detected in {"possible", "yes"}` (steganography heuristics)
- `final_verdict in {"malicious", "critical"}` (e.g. ClamAV infected or YARA critical tag)

## Optional: enable a controlled `critical` case with YARA

A lab-only YARA rule is provided:

- `lab_yara_rules_critical.yar`

To enable it, set environment variables before starting the app:

- `YARA_ENABLED=true`
- `YARA_RULES_PATH=./samples/lab_yara_rules_critical.yar`

When enabled, uploading `lab_exe_marker_dummy.exe` should produce:

- `yara_matches >= 1`
- `final_verdict = "critical"`

Notes:

- The EXE is a **non-functional dummy** (harmless byte container). It is only meant to be matched by the YARA rule.
- If `yara-python` is not installed, YARA scanning will be disabled automatically by the pipeline.

## Manifest

See `alarm_manifest.csv` for ground-truth labels and expected signals.
