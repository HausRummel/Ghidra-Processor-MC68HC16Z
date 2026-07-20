# 68HC16 disassembly regression tests

A lightweight harness that checks known instruction byte sequences disassemble to the expected
text through the **installed** Ghidra 68HC16 language. It guards against future `.slaspec` edits
silently breaking instruction decoding.

It does **not** test p-code/emulation semantics (flag math, MAC accumulation) — only disassembly
text. Semantic validation would need Ghidra's emulator test rig and a CPU16 toolchain, which is out
of scope here.

## Requirements

- Python 3 (standard library only).
- A Ghidra install with **this module installed** (drop `MC68HC16Z3/` into
  `<GhidraInstallDir>/Ghidra/Processors/`), so language id `68HC16:BE:24:default` resolves.
- `GHIDRA_INSTALL_DIR` pointing at that install.

## Running

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_xx.y_PUBLIC
python3 tests/run_disasm_tests.py            # run all corpus files
python3 tests/run_disasm_tests.py tests/corpus/30_branches.disasm   # a subset
```

Exit codes: `0` = all pass (or skipped when no Ghidra), `1` = mismatch, `2` = harness/error or
`--no-allow-skip` with no Ghidra. Without `GHIDRA_INSTALL_DIR` the harness prints `SKIP` and exits
`0`, so a CI box without Ghidra stays green; pass `--no-allow-skip` to make "no Ghidra" a failure.

## Corpus format

`tests/corpus/*.disasm`, one vector per line:

```
HEXBYTES | EXPECTED_DISASM | comment
```

- `HEXBYTES` — the instruction bytes (spaces optional).
- `EXPECTED_DISASM` — the ratified disassembly text (whitespace is normalized before comparison).
- `comment` — provenance/notes, ignored by the runner.
- `@base 0xADDR` sets the load/disassemble address for following vectors (default `0x010000`).
  The base matters: branch targets render as absolute addresses (`inst_start + 6 + offset`, the
  CPU16 3-word pipeline), so a vector's expected text depends on where it sits.

Vectors are laid out one-per-slot on a fixed 10-byte stride, so a decode bug in one vector can't
desync the next.

## Adding vectors and the trust model

The owner's standalone **HC16 assembler is the encoding ground truth**; Ghidra is the **decoder
under test**. Do not blindly trust Ghidra's output as "golden" — that would happily bless a decoder
bug forever. Workflow:

1. Add lines with the trusted **bytes** (from the assembler, or the manual) and `?` for the
   expected text. Put the source/manual reference in the comment column.
2. Seed candidate text:
   ```sh
   python3 tests/run_disasm_tests.py --update      # fills '?' from Ghidra — candidates only
   ```
3. **Review** each candidate against the assembler source intent and the CPU16 manual
   (`MC68HC16Z3/data/Manual/`). Accept only when they agree (allowing deliberate display choices
   like the `bank:addr,X` form for IND20). A disagreement is a decoder bug found *before* commit.
4. Commit the corpus with the ratified expected values. From then on, a plain run is a pure
   regression gate. **Never run `--update` in CI.**

## Notes / caveats

- **Radix.** The `.slaspec` doesn't pin an immediate display radix; the installed Ghidra renders hex
  here (e.g. `LDAA #0x10`). The runner normalizes whitespace but compares the rendered text as-is,
  so a future change to the display radix would (correctly) require re-ratifying the goldens.
- **Context dependence.** The harness runs the `68HC16:BE:24:default` (generic) language, whose
  bank context defaults are `ctxEK=0`, `ctxZK=0`. Those defaults set the *bank* of the effective
  address in the p-code for `,Z` and `EXT16` operands, but the disassembly **text** the harness
  compares shows only the offset (e.g. `LDAA 0x2,Z`), so it is unaffected by the bank value. The
  JTEC preset (`68HC16:BE:24:JTEC`) uses `ctxZK=15` instead; it decodes to the same text.
- `tests/generated/` is scratch (blobs, headless projects) and is git-ignored.
