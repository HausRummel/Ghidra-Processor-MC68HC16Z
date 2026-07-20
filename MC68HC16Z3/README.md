# MC68HC16 (CPU16) processor module

Ghidra SLEIGH processor module for the Motorola/Freescale MC68HC16 (CPU16) core. Drop this
`MC68HC16Z3/` folder into `<GhidraInstallDir>/Ghidra/Processors/` and select language **68HC16**
on import.

Three profiles share the same instruction set, layered from bare core to firmware preset:

- `68HC16:BE:24:cpu16` — bare CPU16 core (exception-vector names + register model only, no
  peripheral map). For a non-Z2/Z3 MC68HC16 or a clean slate.
- `68HC16:BE:24:default` — generic MC68HC16Z2/Z3 (adds this chip's peripheral map; no firmware
  assumptions).
- `68HC16:BE:24:JTEC` — Chrysler JTEC+ PCM/TCM preset (adds firmware entry points, memory blocks,
  bank defaults, and the IZ-preserving calling convention).

See the [repository README](../README.md) for installation, the CPU16 banking model, the two
profiles and their limitations, and licensing (Apache-2.0).
