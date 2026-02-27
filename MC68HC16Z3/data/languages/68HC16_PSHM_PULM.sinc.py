def generate_68hc16_pshm_pulm_sinc(filename):
    # PSHM: Bit 0=D, 1=E, 2=IX, 3=IY, 4=IZ, 5=K, 6=CCR
    pshm_regs = ["D", "E", "IX", "IY", "IZ", "K", "CCR"]

    # PULM (Mirrored): Bit 0=CCR, 1=K, 2=IZ, 3=IY, 4=IX, 5=E, 6=D
    pulm_regs = ["CCR", "K", "IZ", "IY", "IX", "E", "D"]

    with open(filename, 'w') as f:
        f.write("# 68HC16 PSHM/PULM Register Mapping\n\n")
        f.write("# --- PSHM: Forward Display (D->CCR), Reverse P-Code (CCR->D) ---\n")

        for i in range(256):
            # Only bits 0-6 are used for registers
            active = [pshm_regs[b] for b in range(7) if (i >> b) & 1]
            pshm_pcode = []

            # Hardware Push Order (Descending): CCR -> K -> IZ -> IY -> IX -> E -> D
            if (i & 0x40): pshm_pcode.append("packCCR(); push16(CCR);")
            if (i & 0x20): pshm_pcode.append("local pk:2=(zext(EK:1)<<12)|(zext(XK:1)<<8)|(zext(YK:1)<<4)|zext(ZK:1); push16(pk);")
            if (i & 0x10): pshm_pcode.append("push16(IZ);")
            if (i & 0x08): pshm_pcode.append("push16(IY);")
            if (i & 0x04): pshm_pcode.append("push16(IX);")
            if (i & 0x02): pshm_pcode.append("push16(E);")
            if (i & 0x01): pshm_pcode.append("push16(D);")

            f.write(f'pshmList: "{",".join(active)}" is regmask={i} {{ {" ".join(pshm_pcode)} }}\n')

        f.write("\n")
        f.write("# --- PULM: Forward Display (CCR->D), Reverse P-Code (D->CCR) ---\n")

        for i in range(256):
            # Mirrored Mapping: Bit 0 is CCR, Bit 6 is D
            active = [pulm_regs[b] for b in range(7) if (i >> b) & 1]
            pulm_pcode = []

            # Hardware Pull Order (Ascending): D -> E -> IX -> IY -> IZ -> K -> CCR
            if (i & 0x40): pulm_pcode.append("pull16(D);")
            if (i & 0x20): pulm_pcode.append("pull16(E);")
            if (i & 0x10): pulm_pcode.append("pull16(IX);")
            if (i & 0x08): pulm_pcode.append("pull16(IY);")
            if (i & 0x04): pulm_pcode.append("pull16(IZ);")
            if (i & 0x02): pulm_pcode.append("local un:2; pull16(un); EK=un[12,4]; XK=un[8,4]; YK=un[4,4]; ZK=un[0,4];")
            if (i & 0x01): pulm_pcode.append("pull16(CCR); unpackCCR();")

            f.write(f'pulmList: "{",".join(active)}" is regmask={i} {{ {" ".join(pulm_pcode)} }}\n')

    print(f"Generated {filename}")

if __name__ == "__main__":
    generate_68hc16_pshm_pulm_sinc("68HC16_PSHM_PULM.sinc")