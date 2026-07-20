// DisassembleBanks.java
// Ghidra script for banked 68HC16 firmware.
// Scans a set of code banks to find the end of real code (where a run of
// 0xFF padding begins) then disassembles from each bank start up to that point.
//
// The bank ranges and the FF-run threshold are prompted for at run time and
// default to the common 0x10000/0x20000/0x30000 layout; override them for your
// own dump. In headless mode without script properties, the defaults are used.
//
// Run via: Script Manager > DisassembleBanks.java
// @author David
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
import java.util.ArrayList;
import java.util.List;

public class DisassembleBanks extends GhidraScript {

    // Default bank layout (start-end pairs), used when the prompt is accepted
    // as-is or when running headless without script properties. Each pair is
    // { bank_start, bank_end }, bank_end being the maximum possible end.
    private static final String DEFAULT_BANKS =
        "0x10000-0x1FFFF, 0x20000-0x2FFFF, 0x30000-0x3FFFF";

    // How many consecutive 0xFF bytes signals the end of real code
    private static final int DEFAULT_FF_RUN_THRESHOLD = 16;

    @Override
    public void run() throws Exception {
        AddressFactory addrFactory = currentProgram.getAddressFactory();
        AddressSpace addrSpace = addrFactory.getDefaultAddressSpace();
        Memory mem = currentProgram.getMemory();

        long[][] banks = promptForBanks();
        int ffThreshold = promptForFFThreshold();

        int totalDisassembled = 0;

        for (long[] bank : banks) {
            long bankStart = bank[0];
            long bankEnd = bank[1];

            Address startAddr = makeAddr(addrSpace, bankStart);
            Address endAddr = makeAddr(addrSpace, bankEnd);

            println("============================================================");
            println(String.format("Scanning bank: 0x%05X - 0x%05X", bankStart, bankEnd));

            // Find where the FF padding starts
            Address ffBoundary = findFFStart(mem, startAddr, endAddr, ffThreshold);

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
     * Prompt for the bank ranges as a comma-separated list of "start-end"
     * pairs (hex or decimal). Falls back to DEFAULT_BANKS if the prompt is
     * cancelled or unavailable (e.g. headless with no script properties).
     */
    private long[][] promptForBanks() {
        String spec = DEFAULT_BANKS;
        try {
            spec = askString("DisassembleBanks",
                "Bank ranges (comma-separated start-end pairs)", DEFAULT_BANKS);
        } catch (Exception e) {
            println("  Using default bank ranges: " + DEFAULT_BANKS);
        }
        return parseBanks(spec);
    }

    /** Parse "0x10000-0x1FFFF, 0x20000-0x2FFFF" into { {start,end}, ... }. */
    private long[][] parseBanks(String spec) {
        List<long[]> banks = new ArrayList<>();
        for (String part : spec.split(",")) {
            part = part.trim();
            if (part.isEmpty()) {
                continue;
            }
            String[] ends = part.split("-");
            if (ends.length != 2) {
                println("  Skipping malformed bank range: " + part);
                continue;
            }
            long start = Long.decode(ends[0].trim());
            long end = Long.decode(ends[1].trim());
            banks.add(new long[] { start, end });
        }
        return banks.toArray(new long[0][]);
    }

    /**
     * Prompt for the consecutive-0xFF run length that marks the end of code.
     * Falls back to DEFAULT_FF_RUN_THRESHOLD if unavailable.
     */
    private int promptForFFThreshold() {
        try {
            return askInt("DisassembleBanks",
                "Consecutive 0xFF bytes that mark end of code");
        } catch (Exception e) {
            println("  Using default FF-run threshold: " + DEFAULT_FF_RUN_THRESHOLD);
            return DEFAULT_FF_RUN_THRESHOLD;
        }
    }

    /**
     * Scans forward from startAddr.
     * Returns the address where a run of ffThreshold consecutive 0xFF bytes begins.
     * If no padding is found, returns endAddr.
     */
    private Address findFFStart(Memory mem, Address startAddr, Address endAddr, int ffThreshold) {
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
                if (ffCount >= ffThreshold) {
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