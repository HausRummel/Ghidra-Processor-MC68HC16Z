// DumpDisasm.java
// Headless helper for the 68HC16 disassembly regression harness.
//
// Disassembles a fixed-stride grid of instruction "slots" in the imported
// blob and writes one normalized line per slot:  @OFFSET|HEXBYTES|TEXT
// Driven by tests/run_disasm_tests.py via analyzeHeadless -postScript.
//
// Script args: <baseHex> <stride> <count> <outFile>
//   baseHex  : load/disassemble base address (hex, e.g. 010000)
//   stride   : bytes between slots (>= longest instruction, e.g. 10)
//   count    : number of slots
//   outFile  : absolute path to write results to
//
// @category Test
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

import java.nio.file.Files;
import java.nio.file.Paths;

public class DumpDisasm extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) {
            println("DumpDisasm: expected <baseHex> <stride> <count> <outFile>");
            return;
        }
        long base = Long.parseLong(args[0].replaceFirst("^0[xX]", ""), 16);
        int stride = Integer.parseInt(args[1]);
        int count = Integer.parseInt(args[2]);
        String outFile = args[3];

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();
        StringBuilder out = new StringBuilder();

        for (int i = 0; i < count; i++) {
            long off = base + (long) i * stride;
            Address at = space.getAddress(off);
            AddressSet set = new AddressSet(at, at.add(stride - 1));

            DisassembleCommand cmd = new DisassembleCommand(set, null, false);
            cmd.enableCodeAnalysis(false);
            cmd.applyTo(currentProgram, monitor);

            Instruction insn = listing.getInstructionAt(at);
            String text;
            String hex;
            if (insn == null) {
                text = "<BAD:no-instruction>";
                hex = "??";
            } else {
                text = insn.toString();
                StringBuilder sb = new StringBuilder();
                for (byte b : insn.getBytes()) {
                    sb.append(String.format("%02X", b & 0xFF));
                }
                hex = sb.toString();
            }
            out.append(String.format("@%06X|%s|%s%n", off, hex, text));
        }

        Files.writeString(Paths.get(outFile), out.toString());
        println("DumpDisasm: wrote " + count + " slots to " + outFile);
    }
}
