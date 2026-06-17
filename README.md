# Ghidra Processor Module — Motorola/Freescale MC68HC16 (CPU16)

A [Ghidra](https://ghidra-sre.org/) processor (SLEIGH) module for the **Motorola/Freescale
MC68HC16** family (CPU16 core), originally built to reverse-engineer the **Chrysler JTEC+
PCM/TCM** firmware (MC68HC16Z2/Z3). It provides disassembly, p-code, and decompiler support,
including the CPU16's 20-bit banked addressing, MAC/DSP instructions, and the full
PSHM/PULM register set.

- **Language id:** `68HC16:BE:24:default` (big-endian, 24-bit / 1 MB address space)
- **Target parts:** MC68HC16Z2 / MC68HC16Z3 (the `.pspec` ships the Z3 memory map)
- **Status:** in active use on real firmware; see *Scope & limitations* below.

> ⚠️ **Read *Scope & limitations* before using this on non-Chrysler firmware.** The instruction
> set is generic CPU16, but the bundled **processor spec is tuned for the JTEC+ PCM** (memory map,
> entry points, peripheral symbols, bank defaults).

---

## Installation

This module installs as a **drop-in processor**, no build step required (a precompiled
`68HC16.sla` is included):

1. Copy the `MC68HC16Z3/` folder into your Ghidra installation under
   `<GhidraInstallDir>/Ghidra/Processors/`.
2. Restart Ghidra.
3. Import your binary. When prompted for the language, choose **68HC16** (`68HC16:BE:24:default`),
   set the base address appropriately for your dump, and proceed with disassembly.

If you edit `68HC16.slaspec`, Ghidra recompiles `68HC16.sla` automatically on next load (or run
`<GhidraInstallDir>/support/sleigh 68HC16.slaspec` yourself).

---

## CPU16 model at a glance

- **20-bit banked addressing.** The CPU16 forms 20-bit (1 MB) addresses from a 16-bit value plus
  a 4-bit bank/extension register (`EK`, `XK`, `YK`, `ZK`, `SK`, `PK`). Addresses are computed to
  the full 20 bits so Ghidra builds correct cross-references across banks.
- **Static bank resolution via context.** `EXT16` and Z-indexed modes read the `ctxEK` / `ctxZK`
  context variables (set in the `.pspec`) at disassembly time, so banked operands resolve to real
  addresses. This assumes the bank registers are effectively constant in the target firmware (true
  for JTEC+); see limitations.
- **Pipeline-relative branches.** Branch targets are computed as `inst_start + 6 + offset` to match
  the CPU16's 3-word instruction prefetch.
- **Registers** are modeled with their natural sub-register relationships (A/B as halves of D, E:D
  for 32-bit values, composite `SSP` = `SK:SP` for the 20-bit stack) and the CCR flags as
  bit-ranges (`N`, `Z`, `V`, `C`, `H`, `S`, `MV`, `EV`, plus the MAC `SM` and interrupt-priority
  field).

---

## Scope & limitations

The **instruction set, registers, and addressing modes are generic CPU16** and should apply to any
MC68HC16. However, the **`MC68HC16Z3/data/languages/68HC16.pspec` is specific to the Chrysler JTEC+
PCM** and bakes in assumptions that are *not* universal:

| JTEC+-specific assumption | Where | If your target differs |
|---|---|---|
| `ctxEK = 0`, `ctxZK = 15` bank defaults | `.pspec` `<context_data>` | Change these to your reset values |
| Entry points seeded at `0x010000`, `0x020000` | `.pspec` `RESET_ENTRY` / `STARTUP` | Remove/replace with your vectors |
| Interrupt-handler addresses | `.pspec` `IRQ_*` symbols | From your own vector-table scan |
| Chrysler peripheral (MMIO) symbol map | `.pspec` `default_symbols` | Generic to the Z3 SIM/QSM/GPT/ADC; verify |
| `IZ = 0x8000` global pointer (kept callee-saved) | `.cspec` `__pcm_default` | Drop if your firmware doesn't do this |

**If you analyze a different HC16 binary, review/replace the `.pspec` (and possibly the `.cspec`
calling convention) first**, or you will get spurious entry points and incorrect peripheral labels.

**Calling convention.** The JTEC+ firmware is **hand-written assembly** (no C compiler was used), so
there is no formal ABI. The default `__pcm_default` convention in the `.cspec` is an *empirical*
best-effort model of the register usage observed in the firmware — a reasonable starting point for
the decompiler, not a guarantee. Reassign a per-function convention (right-click → *Edit Function
Signature*) where a routine clearly deviates. Two register-heavy table-lookup conventions
(`__table_1d`, `__table_2d`) are also provided.

**Known follow-ups** (intentionally not yet done): a couple of control instructions are modeled
minimally (`BGND` has an empty body; `WAI`/`LPSTOP` share one pseudo-op); immediate operands use
SLEIGH's default display radix rather than a pinned hex format.

---

## What's included

```
MC68HC16Z3/
  data/languages/      SLEIGH spec: .slaspec, .sinc, .ldefs, .pspec, .cspec, compiled .sla
  data/GhidraScripts/  helper scripts (see below)
  data/Manual/         CPU16RM.pdf and MC68HC16ZUM.pdf reference manuals
tests/                 disassembly regression harness (see tests/README.md)
```

**Helper scripts** (`MC68HC16Z3/data/GhidraScripts/`, run via Ghidra's Script Manager):

- **`DisassembleBanks.java`** — scans banks 1–3 and disassembles code regions up to the `0xFF`
  padding boundary, to bootstrap analysis of a banked dump.
- **`ApplyRegisterBitEquates.java`** + **`MC68HC16Z3_regs.h`** — apply symbolic bit-mask equates to
  MMIO register accesses (e.g. `SIMCR`, `SYNCR`) for readable peripheral code.

---

## Tests

A lightweight disassembly regression harness lives in [`tests/`](tests/). It checks that known
instruction byte sequences disassemble to the expected text, using your local Ghidra install. See
[`tests/README.md`](tests/README.md) for how to run it and add vectors.

---

## License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE).

The bundled PDFs under `MC68HC16Z3/data/Manual/` are Motorola/Freescale reference manuals included
for convenience and remain the property of their respective copyright holders.
