import argparse
import sys
import wave
from pathlib import Path


def embed_message_lsb(input_wav: Path, output_wav: Path, message: str) -> None:
    """Embed *message* into the LSB of samples in a WAV file.

    This uses the same pattern that the ForenHub pipeline expects when
    extracting from audio:

    - Work on the raw frame bytes as returned by wave.readframes.
    - Modify the least significant bit of the first byte of each sample.
    - Step size is the sample width in bytes (so for 16-bit stereo we
      touch every channel sample, exactly as the analyzer does).

    The message is encoded as UTF-8 and written bit by bit from the
    beginning of the audio. No explicit terminator is added; the
    analyzer will look for the longest printable run, so the message
    should be reasonably longer than random noise (e.g. > 16 chars).
    """

    with wave.open(str(input_wav), "rb") as wf:
        params = wf.getparams()
        n_frames = wf.getnframes()
        sampwidth = wf.getsampwidth()
        frames = wf.readframes(n_frames)

    if sampwidth not in (1, 2):
        raise ValueError(f"Unsupported sample width: {sampwidth} bytes. Use 8-bit or 16-bit PCM WAV.")

    data = bytearray(frames)

    # Prepare message bits (UTF-8)
    msg_bytes = message.encode("utf-8")
    bits = []
    for b in msg_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    max_samples = len(data) // sampwidth
    if len(bits) > max_samples:
        raise ValueError(
            f"Message too long for this audio: need {len(bits)} samples, only {max_samples} available."
        )

    # Embed bits into the LSB of the first byte of each sample
    idx = 0
    for bit in bits:
        if idx >= len(data):
            break
        data[idx] = (data[idx] & 0xFE) | bit
        idx += sampwidth

    with wave.open(str(output_wav), "wb") as wf_out:
        wf_out.setparams(params)
        wf_out.writeframes(bytes(data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Embed a secret message into a WAV file using simple LSB "
            "steganography compatible with ForenHub's audio analyzer."
        )
    )
    parser.add_argument("input", type=str, help="Input WAV file (8/16-bit PCM).")
    parser.add_argument("output", type=str, help="Output WAV file with embedded message.")
    parser.add_argument(
        "message",
        type=str,
        help=(
            "Message to embed. Use quotes if it contains spaces. "
            "Should be at least ~16 printable characters for easier detection."
        ),
    )

    args = parser.parse_args(argv)

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"Input file does not exist: {in_path}", file=sys.stderr)
        return 1

    try:
        embed_message_lsb(in_path, out_path, args.message)
    except Exception as exc:  # pragma: no cover - simple CLI utility
        print(f"Error embedding message: {exc}", file=sys.stderr)
        return 1

    print(f"Message embedded successfully into: {out_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
