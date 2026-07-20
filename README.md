# Ghidra Processor Module — Motorola/Freescale MC68HC16 (CPU16)

A [Ghidra](https://ghidra-sre.org/) processor (SLEIGH) module for the **Motorola/Freescale
MC68HC16** family (CPU16 core). It provides disassembly, p-code, and decompiler support,
including the CPU16's 20-bit banked addressing, MAC/DSP instructions, and the full
PSHM/PULM register set. The module was originally built to reverse-engineer the **Chrysler
JTEC+ PCM/TCM** firmware (MC68HC16Z2/Z3), and that profile is preserved — but the default is
now a clean, chip-generic profile you can use on **any** MC68HC16Z binary.

The instruction set is generic CPU16; the difference between the profiles is entirely in the
bundled processor/compiler spec (memory map, symbols, entry points, bank defaults, calling
convention). They layer from bare core to firmware preset:

| Language id | Profile | Use for |
|---|---|---|
| `68HC16:BE:24:cpu16` | **Bare CPU16 core** — exception-vector names + register model only, no peripheral map | a non-Z2/Z3 MC68HC16, or a clean slate |
| `68HC16:BE:24:default` | **Generic MC68HC16Z2/Z3** — the core PLUS this chip's on-chip peripheral map, neutral bank defaults, no seeded entry points | any HC16Z binary |
| `68HC16:BE:24:JTEC` | **Chrysler JTEC+ PCM/TCM preset** — the Z2/Z3 map PLUS firmware entry points, memory blocks, `ZK=0x0F` default, and the IZ-preserving calling convention | JTEC+ PCM/TCM firmware |

All three are big-endian, 24-bit (1 MB address space), and share the same compiled `68HC16.sla`.

- **Target parts:** MC68HC16Z2 / MC68HC16Z3 (the `.pspec` ships the Z2/Z3 peripheral map)
- **Status:** in active use on real firmware; see *Profiles & limitations* below.

---

## Installation

This module installs as a **drop-in processor**, no build step required (a precompiled
`68HC16.sla` is included):

1. Copy the `MC68HC16Z3/` folder into your Ghidra installation under
   `<GhidraInstallDir>/Ghidra/Processors/`.
2. Restart Ghidra.
3. Import your binary. When prompted for the language, choose **68HC16** and pick the variant:
   `68HC16:BE:24:default` for a generic HC16Z binary, `68HC16:BE:24:JTEC` for Chrysler JTEC+
   firmware, or `68HC16:BE:24:cpu16` for a non-Z2/Z3 part or a clean slate. Set the base address
   appropriately for your dump, and proceed with disassembly.

If you edit `68HC16.slaspec`, Ghidra recompiles `68HC16.sla` automatically on next load (or run
`<GhidraInstallDir>/support/sleigh 68HC16.slaspec` yourself).

**Existing JTEC projects:** a program already imported under `68HC16:BE:24:default` keeps the
spec it was created with — its analysis is unaffected. To adopt the JTEC preset explicitly, use
*Set Language* and choose `68HC16:BE:24:JTEC`.

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

## Profiles & limitations

The **instruction set, registers, and addressing modes are generic CPU16** and apply to any
MC68HC16 (shared `.slaspec`/`.sla`). The three profiles differ only in the environment they set up,
layering from bare core outward:

| Concern | `cpu16` (bare core) | `default` (Z2/Z3) | `JTEC` preset | Files |
|---|---|---|---|---|
| Exception-vector names | ✅ CPU16 table | ✅ + Z2/Z3 `VEC_PICR` | ✅ same | `.pspec` `default_symbols` |
| Peripheral (MMIO) symbol map | ✖ none | ✅ Z2/Z3 map (from the manual) | ✅ same map | `.pspec` `default_symbols` |
| I/O register memory blocks | ✖ none | ✅ on-chip blocks | ✅ + `EXT_PERIPH`, `INT_SRAM` | `.pspec` `default_memory_blocks` |
| Bank context defaults | `ctxEK=0`, `ctxZK=0` | `ctxEK=0`, `ctxZK=0` (reset) | `ctxEK=0`, `ctxZK=15` (JTEC startup) | `.pspec` `<context_data>` |
| Seeded entry points | none | none | `RESET_ENTRY`/`STARTUP`/`IRQ_*` | `.pspec` `default_symbols` |
| Default calling convention | `__asmcall` (IZ clobbered) | `__asmcall` (IZ clobbered) | `__pcm_default` (IZ preserved) | `.cspec` `<default_proto>` |

So both `cpu16` and `default` **carry no firmware assumptions** — no spurious entry points, no
external memory blocks, neutral bank defaults. Use `cpu16` for a part whose peripheral layout is
*not* the Z2/Z3 (or when you want to define the map yourself); use `default` for any HC16Z binary.
Either way, add your own entry points, memory map, and (if your firmware fixes a data bank at
startup) bank context via *Set Register Values*.

**Peripheral map caveat.** In the `default`/`JTEC` profiles the MMIO symbol map and register blocks
are chip-generic to the MC68HC16Z2/Z3 (SIM/QSM/GPT/ADC/MRM/SRAM), taken from the MC68HC16ZUM
manual — verify against your exact part. The `cpu16` profile omits them entirely.

**Calling convention.** MC68HC16 firmware of this era is typically **hand-written assembly** with no
formal ABI, so both conventions are *empirical* best-effort models — reasonable starting points for
the decompiler, not guarantees. The generic `__asmcall` passes the first arg in `D`/`E:D`, returns
in `D`/`E:D`, and preserves `IX` plus the sticky bank registers; it treats `IZ` as clobbered. The
JTEC `__pcm_default` is identical except it keeps `IZ` callee-saved (that firmware dedicates
`IZ=0x8000` as a global data pointer). Both specs also offer `__pcm_default`, `__table_1d`, and
`__table_2d` as selectable per-function conventions — reassign via right-click → *Edit Function
Signature* where a routine clearly deviates.

**Modeling notes**: the control instructions `BGND`, `WAI`, and `LPSTOP` lift to distinct opaque
pseudo-ops (`background_debug()`, `wait_for_interrupt()`, `low_power_stop()`) — accurate for
disassembly and control flow, though fine-grained side effects (e.g. WAI's context stacking) are
intentionally not modeled. Immediate/offset operands are pinned to hexadecimal display.

---

## What's included

```
MC68HC16Z3/
  data/languages/      SLEIGH spec: .slaspec, .sinc, .ldefs, compiled .sla
                       68HC16_cpu16.pspec                    (bare CPU16 core)
                       68HC16.pspec / 68HC16.cspec           (generic Z2/Z3)
                       68HC16_JTEC.pspec / 68HC16_JTEC.cspec (JTEC+ preset)
  data/GhidraScripts/  helper scripts (see below)
  data/Manual/         CPU16RM.pdf and MC68HC16ZUM.pdf reference manuals
tests/                 disassembly regression harness (see tests/README.md)
```

**Helper scripts** (`MC68HC16Z3/data/GhidraScripts/`, run via Ghidra's Script Manager):

- **`DisassembleBanks.java`** — disassembles code regions up to the `0xFF` padding boundary, to
  bootstrap analysis of a banked dump. Prompts for the bank ranges and FF-run threshold (defaults
  to the common `0x10000`/`0x20000`/`0x30000` layout).
- **`ApplyRegisterBitEquates.java`** + **`MC68HC16Z3_regs.h`** — apply symbolic bit-mask equates to
  MMIO register accesses (e.g. `SIMCR`, `SYNCR`) for readable peripheral code. Chip-generic to the
  Z2/Z3, so usable on any HC16Z binary.

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
