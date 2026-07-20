// Apply symbolic equates for MC68HC16Z3 peripheral register bit masks.
//
// For every cross-reference to a known I/O register (SIMCR, SYNCR, SCCR1, etc.)
// this script scans nearby instructions for immediate values that match
// documented bit masks and applies Ghidra equates so the listing and
// decompiler show "SIMCR_EXOFF" instead of "0x8000".
//
// Handles three access patterns the firmware uses:
//   1. Word access:  LDD SIMCR / ANDA #0x80   (high byte of 16-bit mask)
//   2. Byte access:  LDAB SYPCR / ANDB #0x80   (direct 8-bit mask)
//   3. Init stores:  LDD #0x81CF / STD SIMCR   (full composite value)
//
// Safe to run multiple times -- existing equates are reused, not duplicated.
//
// The register set and bit masks are chip-generic (MC68HC16Z2/Z3 User's
// Manual), so this works on any HC16Z binary, not just JTEC+ firmware.
//
// Source: MC68HC16Z3 User's Manual register definitions
//
// @author  Claude (Anthropic) + David
// @category MC68HC16

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class ApplyRegisterBitEquates extends GhidraScript {

    // How many instructions before/after a register xref to scan for masks
    private static final int SEARCH_WINDOW = 8;

    // ---------------------------------------------------------------
    //  Internal data structures
    // ---------------------------------------------------------------

    /** One bit-mask definition tied to a specific register address. */
    private static class MaskDef {
        final long  regAddr;    // I/O register address (e.g. 0x0FFA00 for SIMCR)
        final long  value;      // Mask value as it appears in the instruction scalar
        final String name;      // Equate name (e.g. "SIMCR_EXOFF")

        MaskDef(long regAddr, long value, String name) {
            this.regAddr = regAddr;
            this.value   = value;
            this.name    = name;
        }
    }

    // Master table:  register address -> masks that apply at that address.
    // For 16-bit registers we also add entries for regAddr+1 (low byte access).
    private final Map<Long, List<MaskDef>> addrToMasks = new LinkedHashMap<>();

    // Mnemonics that typically carry bit-mask immediates
    private static final Set<String> MASK_MNEMONICS = new HashSet<>(Arrays.asList(
        "ANDA", "ANDB", "ORA", "ORAA", "ORAB", "ORB",
        "EORA", "EORB", "BITA", "BITB",
        "CMPA", "CMPB", "CPD",
        "LDAA", "LDAB", "LDD",
        "ADDA", "ADDB", "ADDD",
        "SUBA", "SUBB", "SUBD",
        // ANDP/ORP modify CCR, not general regs, but include for completeness
        "ANDP", "ORP"
    ));

    // ---------------------------------------------------------------
    //  Main entry point
    // ---------------------------------------------------------------

    @Override
    public void run() throws Exception {
        populateAllMasks();

        EquateTable eqTable  = currentProgram.getEquateTable();
        Listing     listing  = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        int totalEquates   = 0;
        int totalRegisters = 0;

        // Process each registered address
        for (Map.Entry<Long, List<MaskDef>> entry : addrToMasks.entrySet()) {
            long regAddrVal        = entry.getKey();
            List<MaskDef> masks    = entry.getValue();
            Address regAddr        = toAddr(regAddrVal);

            Reference[] refs = getReferencesTo(regAddr);
            if (refs.length == 0) continue;

            totalRegisters++;
            int applied = 0;

            for (Reference ref : refs) {
                Address refAddr = ref.getFromAddress();
                Instruction refInstr = listing.getInstructionAt(refAddr);
                if (refInstr == null) continue;

                // Scan a window of instructions around this xref
                applied += scanWindow(refInstr, masks, eqTable, listing);
            }

            if (applied > 0) {
                String regName = getSymbolNameAt(regAddr);
                if (regName == null) regName = String.format("0x%06X", regAddrVal);
                printf("  %-10s : %d equates applied across %d xrefs\n",
                       regName, applied, refs.length);
            }

            totalEquates += applied;
        }

        println("=======================================================");
        printf("ApplyRegisterBitEquates complete.\n");
        printf("  Registers with xrefs: %d\n", totalRegisters);
        printf("  Total equates applied: %d\n", totalEquates);
        println("=======================================================");
    }

    // ---------------------------------------------------------------
    //  Window scanner
    // ---------------------------------------------------------------

    /**
     * Walk backward and forward from the xref instruction looking for
     * immediates that match any of the supplied mask definitions.
     * Returns count of equates applied.
     */
    private int scanWindow(Instruction center, List<MaskDef> masks,
                           EquateTable eqTable, Listing listing) throws Exception {
        int applied = 0;

        // Scan backward (including the xref instruction itself)
        Instruction instr = center;
        for (int i = 0; i <= SEARCH_WINDOW && instr != null; i++) {
            applied += tryApplyEquates(instr, masks, eqTable);
            instr = instr.getPrevious();
        }

        // Scan forward (skip center -- already checked above)
        instr = center.getNext();
        for (int i = 0; i < SEARCH_WINDOW && instr != null; i++) {
            applied += tryApplyEquates(instr, masks, eqTable);
            instr = instr.getNext();
        }

        return applied;
    }

    /**
     * Check a single instruction for scalar operands matching known masks.
     * Only considers instructions whose mnemonic suggests bit manipulation
     * or immediate loading (AND, OR, BIT, LD, CMP, etc.).
     */
    private int tryApplyEquates(Instruction instr, List<MaskDef> masks,
                                EquateTable eqTable) throws Exception {
        String mnem = instr.getMnemonicString().toUpperCase();
        if (!MASK_MNEMONICS.contains(mnem)) return 0;

        int applied = 0;
        int numOps  = instr.getNumOperands();

        for (int op = 0; op < numOps; op++) {
            // Walk all sub-objects in the operand looking for scalars
            for (Object obj : instr.getOpObjects(op)) {
                if (!(obj instanceof Scalar)) continue;
                Scalar scalar = (Scalar) obj;
                long sval = scalar.getUnsignedValue();

                // Skip trivial values -- these appear everywhere and aren't
                // register-specific masks (0, 1, 0xFF, 0xFFFF)
                if (sval == 0 || sval == 1 || sval == 0xFF || sval == 0xFFFF) continue;

                // Check against every mask for the nearby register
                for (MaskDef md : masks) {
                    if (sval == md.value) {
                        // Check if this instruction+operand already has an equate
                        // with this name (prevents duplicates on re-run)
                        boolean alreadyApplied = false;
                        List<Equate> existingEqs = eqTable.getEquates(instr.getAddress(), op);
                        for (Equate ex : existingEqs) {
                            if (ex.getName().equals(md.name)) {
                                alreadyApplied = true;
                                break;
                            }
                        }
                        if (alreadyApplied) break;

                        // Create or reuse the named equate
                        Equate eq = eqTable.getEquate(md.name);
                        if (eq == null) {
                            eq = eqTable.createEquate(md.name, md.value);
                        }
                        eq.addReference(instr.getAddress(), op);
                        applied++;
                        break;  // first match wins for this scalar
                    }
                }
            }
        }
        return applied;
    }

    // ---------------------------------------------------------------
    //  Helper: get symbol name at an address, or null
    // ---------------------------------------------------------------
    private String getSymbolNameAt(Address addr) {
        Symbol sym = getSymbolAt(addr);
        return (sym != null) ? sym.getName() : null;
    }

    // ---------------------------------------------------------------
    //  16-bit register helper: registers the full value, PLUS the
    //  high-byte and low-byte portions so we catch byte-level access.
    //
    //    addMask16(0x0FFA00, 0x8000, "SIMCR_EXOFF")
    //  produces:
    //    addr 0x0FFA00, value 0x8000, name "SIMCR_EXOFF"       (word ops)
    //    addr 0x0FFA00, value 0x80,   name "SIMCR_EXOFF_H"     (ANDA on high byte)
    //    addr 0x0FFA01, value 0x00     -- skipped (zero byte)
    //
    //  For a low-byte mask like SIMCR_IARB_MASK (0x000F):
    //    addr 0x0FFA00, value 0x000F, name "SIMCR_IARB_MASK"   (word ops)
    //    addr 0x0FFA00, value 0x00     -- skipped (zero hi byte)
    //    addr 0x0FFA01, value 0x0F,   name "SIMCR_IARB_MASK_L" (ANDB on low byte)
    // ---------------------------------------------------------------
    private void addMask16(long regAddr, long value, String name) {
        // Full 16-bit value at the word address
        addEntry(regAddr, value, name);

        // High byte at the word address (byte access to first byte)
        long hi = (value >> 8) & 0xFF;
        if (hi > 1 && hi != 0xFF) {
            addEntry(regAddr, hi, name + "_H");
        }

        // Low byte at word address + 1
        long lo = value & 0xFF;
        if (lo > 1 && lo != 0xFF) {
            addEntry(regAddr + 1, lo, name + "_L");
        }
    }

    /** 8-bit register: single direct entry. */
    private void addMask8(long regAddr, long value, String name) {
        addEntry(regAddr, value, name);
    }

    /** Raw entry insertion. */
    private void addEntry(long regAddr, long value, String name) {
        addrToMasks.computeIfAbsent(regAddr, k -> new ArrayList<>())
                   .add(new MaskDef(regAddr, value, name));
    }

    // ---------------------------------------------------------------
    //  JTEC+ composite init values -- the exact values written during
    //  startup at FUN_020000.  Matching these gives instant clarity
    //  to the initialization sequence.
    // ---------------------------------------------------------------
    private void addJtecInitValues() {
        // SYPCR = 0xB4: SWE=1, SWT=3(longest), BME=1
        addMask8 (0x0FFA21L, 0xB4, "SYPCR_JTEC_INIT");

        // SYNCR = 0x95 (initial, before PLL lock): W=0,X=0,Y=0x25
        // Low byte of SYNCR (0x0FFA05), or full word if loaded as 16-bit
        addEntry (0x0FFA04L, 0x0095, "SYNCR_JTEC_INIT");
        addEntry (0x0FFA05L, 0x95,   "SYNCR_JTEC_INIT_L");

        // SIMCR = 0x81CF: EXOFF=1,SHEN=3,SUPV=1,MM=1,IARB=0xF
        addEntry (0x0FFA00L, 0x81CF, "SIMCR_JTEC_INIT");

        // ADCTL0 = 0x00EA
        addEntry (0x0FF70AL, 0x00EA, "ADCTL0_JTEC_INIT");
        addEntry (0x0FF70BL, 0xEA,   "ADCTL0_JTEC_INIT_L");

        // SPCR0 = 0x810B: MSTR=1, 16-bit, SPBR=0x0B
        addEntry (0x0FFC18L, 0x810B, "SPCR0_JTEC_INIT");

        // SCCR0 baud = 0x0058: baud divisor 88
        addEntry (0x0FFC08L, 0x0058, "SCCR0_JTEC_BAUD");
        addEntry (0x0FFC09L, 0x58,   "SCCR0_JTEC_BAUD_L");

        // SCCR1 = 0x000C: TE=1, RE=1
        addEntry (0x0FFC0AL, 0x000C, "SCCR1_JTEC_INIT");
        addEntry (0x0FFC0BL, 0x0C,   "SCCR1_JTEC_INIT_L");

        // QIVR = 0x4E: SCI vector base
        addMask8 (0x0FFC05L, 0x4E, "QIVR_JTEC_INIT");

        // PICR = 0x0338: PIRQL=3, PIV=0x38
        addEntry (0x0FFA22L, 0x0338, "PICR_JTEC_INIT");

        // GPTMCR = 0x008C: SUPV=1, IARB=0xC
        addEntry (0x0FF900L, 0x008C, "GPTMCR_JTEC_INIT");
        addEntry (0x0FF901L, 0x8C,   "GPTMCR_JTEC_INIT_L");

        // ICR = 0x0440
        addEntry (0x0FF904L, 0x0440, "ICR_JTEC_INIT");

        // PITR = 0x0002
        addEntry (0x0FFA24L, 0x0002, "PITR_JTEC_INIT");

        // Watchdog service sequence bytes
        addMask8 (0x0FFA27L, 0x55, "SWSR_SERVICE_1");
        addMask8 (0x0FFA27L, 0xAA, "SWSR_SERVICE_2");
    }

    // ===============================================================
    //  REGISTER MASK DATABASE
    //  Source: MC68HC16Z3_regs.h + MC68HC16ZUM Appendix D
    // ===============================================================

    private void populateAllMasks() {

        // ---- SIM: System Integration Module (0x0FFA00) ----

        // SIMCR (0x0FFA00, 16-bit)
        addMask16(0x0FFA00L, 0x8000, "SIMCR_EXOFF");
        addMask16(0x0FFA00L, 0x4000, "SIMCR_FRZSW");
        addMask16(0x0FFA00L, 0x2000, "SIMCR_FRZBM");
        addMask16(0x0FFA00L, 0x0800, "SIMCR_SLOCK");
        addMask16(0x0FFA00L, 0x0300, "SIMCR_SHEN_MASK");
        addMask16(0x0FFA00L, 0x0080, "SIMCR_SUPV");
        addMask16(0x0FFA00L, 0x0040, "SIMCR_MM");
        addMask16(0x0FFA00L, 0x000F, "SIMCR_IARB_MASK");

        // SYNCR (0x0FFA04, 16-bit)
        addMask16(0x0FFA04L, 0x8000, "SYNCR_W");
        addMask16(0x0FFA04L, 0x4000, "SYNCR_X");
        addMask16(0x0FFA04L, 0x3F00, "SYNCR_Y_MASK");
        addMask16(0x0FFA04L, 0x0080, "SYNCR_EDIV");
        addMask16(0x0FFA04L, 0x0010, "SYNCR_SLIMP");
        addMask16(0x0FFA04L, 0x0008, "SYNCR_SLOCK");
        addMask16(0x0FFA04L, 0x0004, "SYNCR_RSTEN");
        addMask16(0x0FFA04L, 0x0002, "SYNCR_STSIM");

        // RSR (0x0FFA07, 8-bit)
        addMask8(0x0FFA07L, 0x80, "RSR_EXT");
        addMask8(0x0FFA07L, 0x40, "RSR_POW");
        addMask8(0x0FFA07L, 0x20, "RSR_SW");
        addMask8(0x0FFA07L, 0x10, "RSR_HLT");
        addMask8(0x0FFA07L, 0x04, "RSR_LOC");
        addMask8(0x0FFA07L, 0x02, "RSR_SYS");

        // SYPCR (0x0FFA21, 8-bit)
        addMask8(0x0FFA21L, 0x80, "SYPCR_SWE");
        addMask8(0x0FFA21L, 0x40, "SYPCR_SWP");
        addMask8(0x0FFA21L, 0x30, "SYPCR_SWT_MASK");
        addMask8(0x0FFA21L, 0x08, "SYPCR_HME");
        addMask8(0x0FFA21L, 0x04, "SYPCR_BME");
        addMask8(0x0FFA21L, 0x03, "SYPCR_BMT_MASK");

        // PICR (0x0FFA22, 16-bit)
        addMask16(0x0FFA22L, 0x0700, "PICR_PIRQL_MASK");
        addMask16(0x0FFA22L, 0x00FF, "PICR_PIV_MASK");

        // PITR (0x0FFA24, 16-bit)
        addMask16(0x0FFA24L, 0x0100, "PITR_PTP");
        addMask16(0x0FFA24L, 0x00FF, "PITR_PITM_MASK");

        // CSPAR common encodings (generic, used across CSPAR0/CSPAR1)
        // These are 2-bit field values, more useful as comments than equates

        // CSBAR common fields
        addMask16(0x0FFA4CL, 0xFFE0, "CSBAR_ADDR_MASK");
        addMask16(0x0FFA4CL, 0x001F, "CSBAR_BLKSZ_MASK");

        // CSOR common fields (applied to CSOR0 as representative)
        addMask16(0x0FFA4EL, 0x8000, "CSOR_MODE");
        addMask16(0x0FFA4EL, 0x6000, "CSOR_BYTE_MASK");
        addMask16(0x0FFA4EL, 0x1800, "CSOR_RW_MASK");
        addMask16(0x0FFA4EL, 0x0400, "CSOR_STRB");
        addMask16(0x0FFA4EL, 0x03C0, "CSOR_DSACK_MASK");
        addMask16(0x0FFA4EL, 0x0030, "CSOR_SPACE_MASK");
        addMask16(0x0FFA4EL, 0x0008, "CSOR_IPL_MASK");
        addMask16(0x0FFA4EL, 0x0004, "CSOR_AVEC");

        // ---- GPT: General-Purpose Timer (0x0FF900) ----

        // GPTMCR (0x0FF900, 16-bit)
        addMask16(0x0FF900L, 0xC000, "GPTMCR_STOP_MASK");
        addMask16(0x0FF900L, 0x3000, "GPTMCR_FRZ_MASK");
        addMask16(0x0FF900L, 0x0080, "GPTMCR_SUPV");
        addMask16(0x0FF900L, 0x000F, "GPTMCR_IARB_MASK");

        // ICR (0x0FF904, 16-bit)
        addMask16(0x0FF904L, 0x0700, "ICR_ICF_MASK");
        addMask16(0x0FF904L, 0x0070, "ICR_OCF_MASK");
        addMask16(0x0FF904L, 0x0007, "ICR_TOF_MASK");

        // PACTL (0x0FF90C, 8-bit)
        addMask8(0x0FF90CL, 0x40, "PACTL_PAIS");
        addMask8(0x0FF90CL, 0x20, "PACTL_PAMOD");
        addMask8(0x0FF90CL, 0x10, "PACTL_PEDGE");
        addMask8(0x0FF90CL, 0x04, "PACTL_I4O5");
        addMask8(0x0FF90CL, 0x03, "PACTL_CLK_MASK");

        // TCTL1 (0x0FF91E, 8-bit)
        addMask8(0x0FF91EL, 0xC0, "TCTL1_OM2_OL2_MASK");
        addMask8(0x0FF91EL, 0x30, "TCTL1_OM3_OL3_MASK");
        addMask8(0x0FF91EL, 0x0C, "TCTL1_OM4_OL4_MASK");
        addMask8(0x0FF91EL, 0x03, "TCTL1_OM5_OL5_MASK");

        // TCTL2 (0x0FF91F, 8-bit)
        addMask8(0x0FF91FL, 0xC0, "TCTL2_EDG1_MASK");
        addMask8(0x0FF91FL, 0x30, "TCTL2_EDG2_MASK");
        addMask8(0x0FF91FL, 0x0C, "TCTL2_EDG3_MASK");

        // TMSK1 (0x0FF920, 8-bit)
        addMask8(0x0FF920L, 0x80, "TMSK1_OC1I");
        addMask8(0x0FF920L, 0x40, "TMSK1_OC2I");
        addMask8(0x0FF920L, 0x20, "TMSK1_OC3I");
        addMask8(0x0FF920L, 0x10, "TMSK1_OC4I");
        addMask8(0x0FF920L, 0x08, "TMSK1_I4O5I");
        addMask8(0x0FF920L, 0x04, "TMSK1_IC1I");
        addMask8(0x0FF920L, 0x02, "TMSK1_IC2I");

        // TMSK2 (0x0FF921, 8-bit)
        addMask8(0x0FF921L, 0x80, "TMSK2_TOI");
        addMask8(0x0FF921L, 0x20, "TMSK2_PAOVI");
        addMask8(0x0FF921L, 0x10, "TMSK2_PAII");
        addMask8(0x0FF921L, 0x03, "TMSK2_PR_MASK");

        // TFLG1 (0x0FF922, 8-bit)
        addMask8(0x0FF922L, 0x80, "TFLG1_OC1F");
        addMask8(0x0FF922L, 0x40, "TFLG1_OC2F");
        addMask8(0x0FF922L, 0x20, "TFLG1_OC3F");
        addMask8(0x0FF922L, 0x10, "TFLG1_OC4F");
        addMask8(0x0FF922L, 0x08, "TFLG1_I4O5F");
        addMask8(0x0FF922L, 0x04, "TFLG1_IC1F");
        addMask8(0x0FF922L, 0x02, "TFLG1_IC2F");

        // TFLG2 (0x0FF923, 8-bit)
        addMask8(0x0FF923L, 0x80, "TFLG2_TOF");
        addMask8(0x0FF923L, 0x20, "TFLG2_PAOVF");
        addMask8(0x0FF923L, 0x10, "TFLG2_PAIF");

        // PWMC (0x0FF925, 8-bit)
        addMask8(0x0FF925L, 0xC0, "PWMC_PCLK_MASK");
        addMask8(0x0FF925L, 0x30, "PWMC_PPOL_MASK");
        addMask8(0x0FF925L, 0x08, "PWMC_PSWAI");
        addMask8(0x0FF925L, 0x07, "PWMC_PCKB_MASK");

        // ---- QSM: Queued Serial Module (0x0FFC00) ----

        // QSMCR (0x0FFC00, 16-bit)
        addMask16(0x0FFC00L, 0xC000, "QSMCR_STOP_MASK");
        addMask16(0x0FFC00L, 0x3000, "QSMCR_FRZ_MASK");
        addMask16(0x0FFC00L, 0x0080, "QSMCR_SUPV");
        addMask16(0x0FFC00L, 0x000F, "QSMCR_IARB_MASK");

        // QILR (0x0FFC04, 8-bit)
        addMask8(0x0FFC04L, 0x70, "QILR_ILSPI_MASK");
        addMask8(0x0FFC04L, 0x07, "QILR_ILSCI_MASK");

        // SCCR0 (0x0FFC08, 16-bit)
        addMask16(0x0FFC08L, 0x1FFF, "SCCR0_SCBR_MASK");

        // SCCR1 (0x0FFC0A, 16-bit)
        addMask16(0x0FFC0AL, 0x4000, "SCCR1_LOOPS");
        addMask16(0x0FFC0AL, 0x2000, "SCCR1_WOMS");
        addMask16(0x0FFC0AL, 0x1000, "SCCR1_ILT");
        addMask16(0x0FFC0AL, 0x0800, "SCCR1_PT");
        addMask16(0x0FFC0AL, 0x0400, "SCCR1_PE");
        addMask16(0x0FFC0AL, 0x0200, "SCCR1_M");
        addMask16(0x0FFC0AL, 0x0100, "SCCR1_WAKE");
        addMask16(0x0FFC0AL, 0x0080, "SCCR1_TIE");
        addMask16(0x0FFC0AL, 0x0040, "SCCR1_TCIE");
        addMask16(0x0FFC0AL, 0x0020, "SCCR1_RIE");
        addMask16(0x0FFC0AL, 0x0010, "SCCR1_ILIE");
        addMask16(0x0FFC0AL, 0x0008, "SCCR1_TE");
        addMask16(0x0FFC0AL, 0x0004, "SCCR1_RE");
        addMask16(0x0FFC0AL, 0x0002, "SCCR1_RWU");

        // SCSR (0x0FFC0C, 16-bit)
        addMask16(0x0FFC0CL, 0x0100, "SCSR_TDRE");
        addMask16(0x0FFC0CL, 0x0080, "SCSR_TC");
        addMask16(0x0FFC0CL, 0x0040, "SCSR_RDRF");
        addMask16(0x0FFC0CL, 0x0020, "SCSR_RAF");
        addMask16(0x0FFC0CL, 0x0010, "SCSR_IDLE");
        addMask16(0x0FFC0CL, 0x0008, "SCSR_OR");
        addMask16(0x0FFC0CL, 0x0004, "SCSR_NF");
        addMask16(0x0FFC0CL, 0x0002, "SCSR_FE");

        // SPCR0 (0x0FFC18, 16-bit)
        addMask16(0x0FFC18L, 0x8000, "SPCR0_MSTR");
        addMask16(0x0FFC18L, 0x4000, "SPCR0_WOMQ");
        addMask16(0x0FFC18L, 0x3C00, "SPCR0_BITS_MASK");
        addMask16(0x0FFC18L, 0x0200, "SPCR0_CPOL");
        addMask16(0x0FFC18L, 0x0100, "SPCR0_CPHA");
        addMask16(0x0FFC18L, 0x00FF, "SPCR0_SPBR_MASK");

        // SPCR1 (0x0FFC1A, 16-bit)
        addMask16(0x0FFC1AL, 0x8000, "SPCR1_SPE");
        addMask16(0x0FFC1AL, 0x7F00, "SPCR1_DSCKL_MASK");
        addMask16(0x0FFC1AL, 0x00FF, "SPCR1_DTL_MASK");

        // SPCR2 (0x0FFC1C, 16-bit)
        addMask16(0x0FFC1CL, 0x8000, "SPCR2_SPIFIE");
        addMask16(0x0FFC1CL, 0x4000, "SPCR2_WREN");
        addMask16(0x0FFC1CL, 0x2000, "SPCR2_WRTO");
        addMask16(0x0FFC1CL, 0x0F00, "SPCR2_ENDQP_MASK");
        addMask16(0x0FFC1CL, 0x000F, "SPCR2_NEWQP_MASK");

        // SPCR3 (0x0FFC1E, 8-bit)
        addMask8(0x0FFC1EL, 0x04, "SPCR3_LOOPQ");
        addMask8(0x0FFC1EL, 0x02, "SPCR3_HMIE");

        // SPSR (0x0FFC1F, 8-bit)
        addMask8(0x0FFC1FL, 0x80, "SPSR_SPIF");
        addMask8(0x0FFC1FL, 0x40, "SPSR_MODF");
        addMask8(0x0FFC1FL, 0x20, "SPSR_HALTA");
        addMask8(0x0FFC1FL, 0x0F, "SPSR_CPTQP_MASK");

        // QSPI Command RAM entries (generic, for any command RAM address)
        // These are byte values used in the 16 command RAM slots
        // We'll register them for the command RAM base range
        for (int i = 0; i < 16; i++) {
            long cmdAddr = 0x0FFD40L + (i * 2);
            addMask8(cmdAddr, 0x80, "QSPI_CMD_CONT");
            addMask8(cmdAddr, 0x40, "QSPI_CMD_BITSE");
            addMask8(cmdAddr, 0x20, "QSPI_CMD_DT");
            addMask8(cmdAddr, 0x10, "QSPI_CMD_DSCK");
            addMask8(cmdAddr, 0x0F, "QSPI_CMD_PCS_MASK");
        }

        // ---- ADC: Analog-to-Digital Converter (0x0FF700) ----

        // ADCMCR (0x0FF700, 16-bit)
        addMask16(0x0FF700L, 0xC000, "ADCMCR_STOP_MASK");
        addMask16(0x0FF700L, 0x3000, "ADCMCR_FRZ_MASK");
        addMask16(0x0FF700L, 0x0080, "ADCMCR_SUPV");
        addMask16(0x0FF700L, 0x000F, "ADCMCR_IARB_MASK");

        // ADCTL0 (0x0FF70A, 16-bit)
        addMask16(0x0FF70AL, 0x1F00, "ADCTL0_PRS_MASK");
        addMask16(0x0FF70AL, 0x00E0, "ADCTL0_STS_MASK");
        addMask16(0x0FF70AL, 0x0010, "ADCTL0_RES10");

        // ADCTL1 (0x0FF70C, 16-bit)
        addMask16(0x0FF70CL, 0x0080, "ADCTL1_SCAN");
        addMask16(0x0FF70CL, 0x0040, "ADCTL1_MULT");
        addMask16(0x0FF70CL, 0x0020, "ADCTL1_S8CM");
        addMask16(0x0FF70CL, 0x001F, "ADCTL1_CD_CA_MASK");

        // ADCSTAT (0x0FF70E, 16-bit)
        addMask16(0x0FF70EL, 0x8000, "ADCSTAT_CCF");
        addMask16(0x0FF70EL, 0x00FF, "ADCSTAT_SCF_MASK");

        // ---- SRAM Module (0x0FFB00) ----

        // RAMMCR (0x0FFB00, 16-bit)
        addMask16(0x0FFB00L, 0xC000, "RAMMCR_STOP_MASK");
        addMask16(0x0FFB00L, 0x0300, "RAMMCR_RASP_MASK");
        addMask16(0x0FFB00L, 0x000F, "RAMMCR_IARB_MASK");

        // ---- MRM: Masked ROM Module (0x0FF820) ----

        // MRMCR (0x0FF820, 16-bit)
        addMask16(0x0FF820L, 0xC000, "MRMCR_STOP_MASK");
        addMask16(0x0FF820L, 0x000F, "MRMCR_IARB_MASK");

        // ---- JTEC+ specific composite init values ----
        addJtecInitValues();

        // Print summary
        int totalMasks = 0;
        for (List<MaskDef> list : addrToMasks.values()) {
            totalMasks += list.size();
        }
        printf("Loaded %d mask definitions across %d register addresses.\n",
               totalMasks, addrToMasks.size());
    }
}
