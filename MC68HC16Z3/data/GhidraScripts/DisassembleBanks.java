// DisassembleBanks.java
// Ghidra script for JTEC+ 68HC16 firmware
// Scans banks 1, 2, and 3 to find the end of real code (where 0xFF padding begins)
// then disassembles everything from the bank start up to that point.
//
// Run via: Script Manager > DisassembleBanks.java
// @author David (JTEC RE project)
// @category Analysis
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class DisassembleBanks extends GhidraScript {

    // Each pair is: { bank_start, bank_end }
    // bank_end is the maximum possible end of the bank
    private static final long[][] BANKS = {
        { 0x10000L, 0x1FFFFL },
        { 0x20000L, 0x2FFFFL },
        { 0x30000L, 0x3FFFFL }
    };

    // How many consecutive 0xFF bytes signals the end of real code
    private static final int FF_RUN_THRESHOLD = 16;

    @Override
    public void run() throws Exception {
        AddressFactory addrFactory = currentProgram.getAddressFactory();
        AddressSpace addrSpace = addrFactory.getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();

        int totalDisassembled = 0;

        for (long[] bank : BANKS) {
            long bankStart = bank[0];
            long bankEnd = bank[1];

            Address startAddr = makeAddr(addrSpace, bankStart);
            Address endAddr = makeAddr(addrSpace, bankEnd);

            println("============================================================");
            println(String.format("Scanning bank: 0x%05X - 0x%05X", bankStart, bankEnd));

            // Find where the FF padding starts
            Address ffBoundary = findFFStart(mem, startAddr, endAddr);

            if (ffBoundary.equals(startAddr)) {
                println("  WARNING: FF bytes found immediately at bank start, skipping.");
                continue;
            }

            Address codeEnd = ffBoundary.subtract(1);

            println(String.format("  FF padding starts at: 0x%05X", ffBoundary.getOffset()));
            println(String.format("  Disassembling:        0x%05X - 0x%05X",
                    startAddr.getOffset(), codeEnd.getOffset()));

            // Build an address set for this range
            AddressSet addrSet = new AddressSet(startAddr, codeEnd);

            // Run disassembly
            DisassembleCommand cmd = new DisassembleCommand(addrSet, null, true);
            cmd.enableCodeAnalysis(false); // don't run full analysis yet, just disassemble
            boolean result = cmd.applyTo(currentProgram, monitor);

            if (result) {
                println("  Disassembly complete.");
                totalDisassembled++;
            } else {
                println("  Disassembly FAILED or partially completed.");
            }
        }

        println("============================================================");
        println(String.format("Done. Processed %d bank(s).", totalDisassembled));
        println("Tip: Run 'Auto Analyze' afterward to pick up cross-references and functions.");
    }

    private Address makeAddr(AddressSpace space, long offset) {
        return space.getAddress(offset);
    }

    /**
     * Scans forward from startAddr.
     * Returns the address where a run of FF_RUN_THRESHOLD consecutive 0xFF bytes begins.
     * If no padding is found, returns endAddr.
     */
    private Address findFFStart(Memory mem, Address startAddr, Address endAddr) {
        Address addr = startAddr;
        Address ffRunStart = null;
        int ffCount = 0;

        while (addr.compareTo(endAddr) <= 0) {
            int b;
            try {
                b = mem.getByte(addr) & 0xFF;
            } catch (MemoryAccessException e) {
                // treat unmapped as FF
                b = 0xFF;
            }

            if (b == 0xFF) {
                if (ffCount == 0) {
                    ffRunStart = addr; // remember where this run started
                }
                ffCount++;
                if (ffCount >= FF_RUN_THRESHOLD) {
                    return ffRunStart; // found the padding boundary
                }
            } else {
                ffCount = 0;
                ffRunStart = null;
            }

            addr = addr.add(1);
        }

        // no FF padding found, use entire bank
        return endAddr;
    }

    /**
     * Optional: Java version of find_code_end from the Python script.
     * Not used in the main flow, but included for completeness.
     */
    @SuppressWarnings("unused")
    private Address findCodeEnd(Memory mem, Address startAddr, Address endAddr) {
        Address addr = endAddr;
        int ffRun = 0;
        Address lastNonFF = null;

        while (addr.compareTo(startAddr) >= 0) {
            int b;
            try {
                b = mem.getByte(addr) & 0xFF;
            } catch (MemoryAccessException e) {
                // Address not in memory, skip
                addr = addr.subtract(1);
                continue;
            }

            if (b == 0xFF) {
                ffRun++;
            } else {
                ffRun = 0;
                if (lastNonFF == null) {
                    lastNonFF = addr; // high-water mark
                }
            }

            addr = addr.subtract(1);
        }

        return lastNonFF;
    }
}