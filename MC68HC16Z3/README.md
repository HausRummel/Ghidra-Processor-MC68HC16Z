# MC68HC16 (CPU16) processor module

Ghidra SLEIGH processor module for the Motorola/Freescale MC68HC16 (CPU16) core. Drop this
`MC68HC16Z3/` folder into `<GhidraInstallDir>/Ghidra/Processors/` and select language **68HC16**
on import.

Two profiles share the same instruction set:

- `68HC16:BE:24:default` — generic MC68HC16Z2/Z3 (chip peripheral map, no firmware assumptions).
- `68HC16:BE:24:JTEC` — Chrysler JTEC+ PCM/TCM preset (adds firmware entry points, memory blocks,
  bank defaults, and the IZ-preserving calling convention).

See the [repository README](../README.md) for installation, the CPU16 banking model, the two
profiles and their limitations, and licensing (Apache-2.0).
