#!/usr/bin/env python3
"""
68HC16 disassembly regression harness.

Feeds known instruction byte sequences through the *installed* Ghidra
68HC16 language and checks the disassembly text against expected values.

Each corpus file (tests/corpus/*.disasm) holds one vector per line:

    HEXBYTES | EXPECTED_DISASM | comment

with an optional `@base 0xADDR` pragma (default 0x010000) that sets the
load/disassemble address for the vectors that follow it (the base matters:
branch targets are rendered as absolute addresses).

Vectors are laid out one-per-slot on a fixed stride (>= the longest CPU16
instruction) so a decode bug in one vector can never desync the next.

Usage:
    GHIDRA_INSTALL_DIR=/path/to/ghidra  python3 tests/run_disasm_tests.py
    python3 tests/run_disasm_tests.py --update          # (re)seed EXPECTED from Ghidra
    python3 tests/run_disasm_tests.py --no-allow-skip    # fail (not skip) if no Ghidra

Exit codes: 0 = all pass (or skipped), 1 = mismatch, 2 = harness error.

NOTE: the 68HC16 module must be installed in the Ghidra pointed to by
GHIDRA_INSTALL_DIR (drop MC68HC16Z3/ into <ghidra>/Ghidra/Processors/), so the
language id 68HC16:BE:24:default resolves.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE / "corpus"
SCRIPTS_DIR = HERE / "ghidra_scripts"
GEN_DIR = HERE / "generated"
LANGUAGE_ID = "68HC16:BE:24:default"
STRIDE = 10          # bytes per slot; >= longest CPU16 instruction
DEFAULT_BASE = 0x010000
EXIT_SKIP = 0        # treat "no Ghidra" as success unless --no-allow-skip


def norm(s: str) -> str:
    """Collapse whitespace so human-edited expected text matches Ghidra output."""
    return re.sub(r"\s+", " ", s.strip())


def find_headless():
    gid = os.environ.get("GHIDRA_INSTALL_DIR")
    if not gid:
        return None
    base = Path(gid)
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    hl = base / "support" / name
    return hl if hl.exists() else None


def parse_corpus(path: Path):
    """Return (base, [ (hexbytes, expected, comment, raw_line) ... ])."""
    base = DEFAULT_BASE
    vectors = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@base"):
            base = int(line.split()[1], 16)
            continue
        parts = [p.strip() for p in line.split("|")]
        hexbytes = re.sub(r"\s+", "", parts[0])
        expected = parts[1] if len(parts) > 1 else "?"
        comment = parts[2] if len(parts) > 2 else ""
        if len(hexbytes) % 2 != 0:
            raise ValueError(f"{path.name}: odd hex digits in {parts[0]!r}")
        vectors.append((hexbytes, expected, comment))
    return base, vectors


def build_blob(vectors, path: Path):
    buf = bytearray(len(vectors) * STRIDE)
    for i, (hexbytes, _, _) in enumerate(vectors):
        data = bytes.fromhex(hexbytes)
        if len(data) > STRIDE:
            raise ValueError(f"vector {i} is {len(data)} bytes (> stride {STRIDE})")
        buf[i * STRIDE: i * STRIDE + len(data)] = data
    path.write_bytes(buf)


def run_headless(headless: Path, blob: Path, base: int, count: int, out: Path):
    proj = Path(tempfile.mkdtemp(prefix="hc16_", dir=str(GEN_DIR)))
    try:
        cmd = [
            str(headless), str(proj), "HC16Test",
            "-import", str(blob),
            "-processor", LANGUAGE_ID,
            "-loader", "BinaryLoader",
            "-loader-baseAddr", hex(base),
            "-scriptPath", str(SCRIPTS_DIR),
            "-postScript", "DumpDisasm.java", f"{base:06x}", str(STRIDE), str(count), str(out),
            "-noanalysis", "-deleteProject", "-overwrite",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if not out.exists():
            sys.stderr.write(res.stdout[-4000:] + "\n" + res.stderr[-4000:] + "\n")
            raise RuntimeError("DumpDisasm produced no output (see headless log above)")
    finally:
        shutil.rmtree(proj, ignore_errors=True)


def read_dump(out: Path):
    """Parse DumpDisasm output lines `@OFFSET|HEX|TEXT` -> list of (hex, text)."""
    rows = []
    for line in out.read_text().splitlines():
        if not line.startswith("@"):
            continue
        _, hexb, text = line.split("|", 2)
        rows.append((hexb, text))
    return rows


def main():
    ap = argparse.ArgumentParser(description="68HC16 disassembly regression harness")
    ap.add_argument("--update", action="store_true",
                    help="rewrite the EXPECTED column from Ghidra output (review before commit!)")
    ap.add_argument("--no-allow-skip", action="store_true",
                    help="exit non-zero (not skip) when GHIDRA_INSTALL_DIR is unset")
    ap.add_argument("--lint", action="store_true",
                    help="parse/validate corpus files without Ghidra (CI self-check)")
    ap.add_argument("files", nargs="*", help="specific corpus files (default: all)")
    args = ap.parse_args()

    corpus_files = [Path(f) for f in args.files] if args.files else sorted(CORPUS_DIR.glob("*.disasm"))

    if args.lint:
        n = 0
        for cf in corpus_files:
            base, vectors = parse_corpus(cf)
            for hexbytes, _, _ in vectors:
                bytes.fromhex(hexbytes)  # raises on bad hex
                if len(hexbytes) // 2 > STRIDE:
                    raise ValueError(f"{cf.name}: vector {hexbytes} exceeds stride {STRIDE}")
            n += len(vectors)
            print(f"[{cf.name}] {len(vectors)} vectors OK (base {base:#08x})")
        print(f"Lint OK: {n} vectors across {len(corpus_files)} file(s).")
        return 0

    headless = find_headless()
    if headless is None:
        msg = "SKIP: set GHIDRA_INSTALL_DIR to a Ghidra install (with the 68HC16 module) to run."
        print(msg)
        return 2 if args.no_allow_skip else EXIT_SKIP

    GEN_DIR.mkdir(exist_ok=True)
    if not corpus_files:
        print("No corpus files found.")
        return 2

    total = fails = 0
    for cf in corpus_files:
        base, vectors = parse_corpus(cf)
        if not vectors:
            continue
        blob = GEN_DIR / (cf.stem + ".bin")
        out = GEN_DIR / (cf.stem + ".out")
        build_blob(vectors, blob)
        run_headless(headless, blob, base, len(vectors), out)
        rows = read_dump(out)
        if len(rows) != len(vectors):
            print(f"[{cf.name}] ERROR: got {len(rows)} disasm rows for {len(vectors)} vectors")
            fails += 1
            continue

        if args.update:
            _rewrite(cf, base, vectors, rows)
            print(f"[{cf.name}] updated {len(vectors)} expected value(s) — REVIEW before committing")
            continue

        for (hexb, expected, comment), (_, actual) in zip(vectors, rows):
            total += 1
            if norm(expected) != norm(actual):
                fails += 1
                print(f"[{cf.name}] MISMATCH {hexb}")
                print(f"    expected: {norm(expected)}")
                print(f"    actual:   {norm(actual)}")
                if comment:
                    print(f"    ({comment})")

    if args.update:
        return 0
    print(f"\n{total - fails}/{total} vectors passed.")
    return 1 if fails else 0


def _rewrite(cf: Path, base: int, vectors, rows):
    """Rewrite a corpus file's EXPECTED column from Ghidra output, preserving structure."""
    out_lines, vi = [], 0
    for raw in cf.read_text().splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("@base"):
            out_lines.append(raw)
            continue
        hexbytes, _, comment = vectors[vi]
        actual = norm(rows[vi][1])
        line = f"{hexbytes} | {actual}"
        if comment:
            line += f" | {comment}"
        out_lines.append(line)
        vi += 1
    cf.write_text("\n".join(out_lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
