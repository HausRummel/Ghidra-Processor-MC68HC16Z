/*
 * MC68HC16Z3 Peripheral Register Definitions
 * For use with Ghidra 68HC16 processor module
 *
 * Source: MC68HC16Z Series User Manual (MC68HC16ZUM/AD)
 *         Tables D-2, D-19, D-21, D-24, D-31, D-42
 *
 * Import into Ghidra: File > Parse C Source > select this file
 *
 * Register naming follows Motorola EQUATES.ASM conventions.
 * Bit definitions use register_FIELD_MASK / register_FIELD_SHIFT format.
 *
 * The register/bit definitions are chip-generic (MC68HC16Z2/Z3). The
 * "Typical JTEC+ init" comments are illustrative example values observed
 * in that firmware; they are not required and will differ on other targets.
 */

#ifndef MC68HC16Z3_REGS_H
#define MC68HC16Z3_REGS_H

typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef signed   char   int8;
typedef signed   short  int16;

/* ======================================================================
 * BASE ADDRESSES (Y = bank nibble, typically 0xF for HC16Z3)
 * All addresses shown with Y=0xF prefix
 * ====================================================================== */

#define ADC_BASE    0x0FF700   /* Analog-to-Digital Converter          */
#define MRM_BASE    0x0FF820   /* Masked ROM Module (Z2/Z3 only)       */
#define GPT_BASE    0x0FF900   /* General-Purpose Timer                */
#define SIM_BASE    0x0FFA00   /* System Integration Module            */
#define SRAM_BASE   0x0FFB00   /* Standby RAM Module                   */
#define QSM_BASE    0x0FFC00   /* Queued Serial Module                 */


/* ======================================================================
 * SIM - System Integration Module  (0x0FFA00 - 0x0FFA7F)
 * Source: MC68HC16ZUM Table D-2
 * ====================================================================== */

/* --- SIMCR: SIM Configuration Register (0x0FFA00, 16-bit) --- */
#define SIMCR_EXOFF         0x8000  /* External clock off                  */
#define SIMCR_FRZSW         0x4000  /* Freeze software watchdog            */
#define SIMCR_FRZBM         0x2000  /* Freeze bus monitor                  */
#define SIMCR_SLOCK          0x0800  /* Slave mode lock (read-only)         */
#define SIMCR_SHEN_MASK      0x0300  /* Show cycle enable                   */
#define SIMCR_SHEN_SHIFT     8
#define SIMCR_SUPV           0x0080  /* Supervisor/unrestricted data space  */
#define SIMCR_MM             0x0040  /* Module mapping (0=bank F, 1=bank 0) */
#define SIMCR_IARB_MASK      0x000F  /* Interrupt arbitration ID            */
/* Typical JTEC+ init: SIMCR = 0x81CF
 *   EXOFF=1, SHEN=3 (show all), SUPV=1, MM=1, IARB=0xF */

/* --- SYNCR: Clock Synthesizer Control Register (0x0FFA04, 16-bit) --- */
#define SYNCR_W              0x8000  /* Frequency control (VCO freq)        */
#define SYNCR_X              0x4000  /* Frequency control (prescaler)       */
#define SYNCR_Y_MASK         0x3F00  /* Frequency control (multiplier)      */
#define SYNCR_Y_SHIFT        8
#define SYNCR_EDIV           0x0080  /* E-clock divide rate                 */
#define SYNCR_SLIMP          0x0010  /* Limp status (read-only)             */
#define SYNCR_SLOCK          0x0008  /* Synthesizer lock status (read-only) */
#define SYNCR_RSTEN          0x0004  /* Reset enable                        */
#define SYNCR_STSIM          0x0002  /* Stop mode SIM clock                 */
#define SYNCR_STEXT          0x0001  /* Stop mode external clock            */
/* Typical JTEC+ init: SYNCR = 0x95 (then set SLOCK bit after PLL lock) */

/* --- RSR: Reset Status Register (0x0FFA07, 8-bit) --- */
#define RSR_EXT              0x80    /* External reset                      */
#define RSR_POW              0x40    /* Power-on reset                      */
#define RSR_SW               0x20    /* Software watchdog reset             */
#define RSR_HLT              0x10    /* Halt monitor reset                  */
#define RSR_LOC              0x04    /* Loss of clock reset                 */
#define RSR_SYS              0x02    /* System reset (from RESET pin)       */

/* --- SYPCR: System Protection Control Register (0x0FFA21, 8-bit) --- */
#define SYPCR_SWE            0x80    /* Software watchdog enable            */
#define SYPCR_SWP            0x40    /* Software watchdog prescale          */
#define SYPCR_SWT_MASK       0x30    /* Software watchdog timing            */
#define SYPCR_SWT_SHIFT      4
#define SYPCR_HME            0x08    /* Halt monitor enable                 */
#define SYPCR_BME            0x04    /* Bus monitor external enable         */
#define SYPCR_BMT_MASK       0x03    /* Bus monitor timing                  */
/* Typical JTEC+ init: SYPCR = 0xB4
 *   SWE=1, SWP=0, SWT=3 (longest), HME=0, BME=1, BMT=0 */

/* --- PICR: Periodic Interrupt Control Register (0x0FFA22, 16-bit) --- */
#define PICR_PIRQL_MASK      0x0700  /* Periodic interrupt request level    */
#define PICR_PIRQL_SHIFT     8
#define PICR_PIV_MASK        0x00FF  /* Periodic interrupt vector number    */
/* Typical JTEC+ init: PICR = 0x0338
 *   PIRQL=3, PIV=0x38 -> vector addr = 0x38*2 = 0x0070 */

/* --- PITR: Periodic Interrupt Timer Register (0x0FFA24, 16-bit) --- */
#define PITR_PTP             0x0100  /* Periodic timer prescaler            */
#define PITR_PITM_MASK       0x00FF  /* PIT modulus (count value)           */
/* Typical JTEC+ init: PITR = 0x0002 */

/* --- SWSR: Software Watchdog Service Register (0x0FFA27, 8-bit) ---
 * Write 0x55 then 0xAA to service the watchdog */

/* --- CSPAR0: Chip-Select Pin Assignment Register 0 (0x0FFA44, 16-bit) --- */
/* Bits [15:12] = CS5, [11:8] = CS4, [7:4] = CS3, [3:0] = CS2, etc.
 * 2 bits per chip-select: 00=discrete, 01=alt, 10=CS 8-bit, 11=CS 16-bit */
#define CSPAR_DISCRETE       0x0     /* Pin is discrete output              */
#define CSPAR_ALT            0x1     /* Pin is alternate function           */
#define CSPAR_CS8            0x2     /* Pin is chip-select, 8-bit port      */
#define CSPAR_CS16           0x3     /* Pin is chip-select, 16-bit port     */

/* --- CSBAR: Chip-Select Base Address Registers ---
 * Upper 11 bits = base address bits [19:9], lower 5 bits = block size
 * Address = CSBAR[15:5] << 9 */
#define CSBAR_ADDR_MASK      0xFFE0  /* Base address [19:9]                 */
#define CSBAR_BLKSZ_MASK     0x001F  /* Block size encoding                 */
#define CSBAR_2K             0x0000  /* 2KB block size                      */
#define CSBAR_8K             0x0002  /* 8KB block size                      */
#define CSBAR_16K            0x0003  /* 16KB block size                     */
#define CSBAR_64K            0x0006  /* 64KB block size                     */
#define CSBAR_128K           0x000A  /* 128KB block size                    */
#define CSBAR_256K           0x000E  /* 256KB block size                    */
#define CSBAR_512K           0x0012  /* 512KB block size                    */
#define CSBAR_1M             0x001E  /* 1MB block size                      */

/* --- CSOR: Chip-Select Option Registers ---
 * Controls wait states, port size, access type */
#define CSOR_MODE_MASK       0x8000  /* Async/Sync mode                     */
#define CSOR_BYTE_MASK       0x6000  /* Upper/Lower byte select             */
#define CSOR_RW_MASK         0x1800  /* Read/Write: 00=rsrvd, 01=R, 10=W, 11=RW */
#define CSOR_STRB            0x0400  /* Address/Data strobe select          */
#define CSOR_DSACK_MASK      0x03C0  /* DSACK (wait state) generation       */
#define CSOR_DSACK_SHIFT     6
#define CSOR_SPACE_MASK      0x0030  /* Address space: 00=CPU, 01=user, 10=supv, 11=S/U */
#define CSOR_IPL_MASK        0x0008  /* Interrupt priority level match      */
#define CSOR_AVEC            0x0004  /* Autovector enable                   */


/* ======================================================================
 * GPT - General-Purpose Timer  (0x0FF900 - 0x0FF93F)
 * Source: MC68HC16ZUM Table D-42
 * ====================================================================== */

/* --- GPTMCR: GPT Module Configuration Register (0x0FF900, 16-bit) --- */
#define GPTMCR_STOP_MASK     0xC000  /* Stop mode behavior                  */
#define GPTMCR_FRZ_MASK      0x3000  /* Freeze mode behavior                */
#define GPTMCR_SUPV          0x0080  /* Supervisor/unrestricted             */
#define GPTMCR_IARB_MASK     0x000F  /* Interrupt arbitration ID            */

/* --- ICR: Interrupt Configuration Register (0x0FF904, 16-bit) --- */
#define ICR_ICF_MASK         0x0700  /* IC interrupt level                  */
#define ICR_ICF_SHIFT        8
#define ICR_OCF_MASK         0x0070  /* OC interrupt level                  */
#define ICR_OCF_SHIFT        4
#define ICR_TOF_MASK         0x0007  /* Timer overflow interrupt level      */
/* Typical JTEC+ init: ICR = 0x0440 */

/* --- PACTL: Pulse Accumulator Control Register (0x0FF90C, 8-bit) ---
 * In the Z3 variant this is 16-bit at 0x0FF90C */
#define PACTL_PAIS           0x40    /* Pulse acc input source (0=IC3, 1=PAI) */
#define PACTL_PAMOD          0x20    /* Pulse acc mode (0=event, 1=gated)   */
#define PACTL_PEDGE          0x10    /* Pulse acc edge (0=falling, 1=rising)*/
#define PACTL_I4O5           0x04    /* IC4/OC5 select (0=OC5, 1=IC4)      */
#define PACTL_CLK_MASK       0x03    /* Clock select (prescaler)            */

/* --- TCTL1: Timer Control Register 1 (0x0FF91E, 8-bit) --- */
/* 2 bits per OC channel: OMn, OLn
 * 00=disconnected, 01=toggle, 10=clear, 11=set */
#define TCTL1_OM2_OL2_MASK   0xC0   /* OC2 output mode                    */
#define TCTL1_OM3_OL3_MASK   0x30   /* OC3 output mode                    */
#define TCTL1_OM4_OL4_MASK   0x0C   /* OC4 output mode                    */
#define TCTL1_OM5_OL5_MASK   0x03   /* OC5 output mode                    */

/* --- TCTL2: Timer Control Register 2 (0x0FF91F, 8-bit) --- */
/* 2 bits per IC channel: EDGnB, EDGnA
 * 00=disabled, 01=rising, 10=falling, 11=any edge */
#define TCTL2_EDG1_MASK      0xC0   /* IC1 edge config                    */
#define TCTL2_EDG2_MASK      0x30   /* IC2 edge config                    */
#define TCTL2_EDG3_MASK      0x0C   /* IC3 edge config                    */

/* --- TMSK1: Timer Interrupt Mask Register 1 (0x0FF920, 8-bit) --- */
#define TMSK1_OC1I           0x80   /* OC1 interrupt enable                */
#define TMSK1_OC2I           0x40   /* OC2 interrupt enable                */
#define TMSK1_OC3I           0x20   /* OC3 interrupt enable                */
#define TMSK1_OC4I           0x10   /* OC4 interrupt enable                */
#define TMSK1_I4O5I          0x08   /* IC4/OC5 interrupt enable            */
#define TMSK1_IC1I           0x04   /* IC1 interrupt enable                */
#define TMSK1_IC2I           0x02   /* IC2 interrupt enable                */
#define TMSK1_IC3I           0x01   /* IC3 interrupt enable                */

/* --- TMSK2: Timer Interrupt Mask Register 2 (0x0FF921, 8-bit) --- */
#define TMSK2_TOI            0x80   /* Timer overflow interrupt enable     */
#define TMSK2_PAOVI          0x20   /* PA overflow interrupt enable        */
#define TMSK2_PAII           0x10   /* PA input interrupt enable           */
#define TMSK2_PR_MASK        0x03   /* Timer prescaler rate                */

/* --- TFLG1: Timer Flag Register 1 (0x0FF922, 8-bit) --- */
#define TFLG1_OC1F           0x80   /* OC1 flag                            */
#define TFLG1_OC2F           0x40   /* OC2 flag                            */
#define TFLG1_OC3F           0x20   /* OC3 flag                            */
#define TFLG1_OC4F           0x10   /* OC4 flag                            */
#define TFLG1_I4O5F          0x08   /* IC4/OC5 flag                        */
#define TFLG1_IC1F           0x04   /* IC1 flag                            */
#define TFLG1_IC2F           0x02   /* IC2 flag                            */
#define TFLG1_IC3F           0x01   /* IC3 flag                            */

/* --- TFLG2: Timer Flag Register 2 (0x0FF923, 8-bit) --- */
#define TFLG2_TOF            0x80   /* Timer overflow flag                 */
#define TFLG2_PAOVF          0x20   /* PA overflow flag                    */
#define TFLG2_PAIF           0x10   /* PA input flag                       */

/* --- PWMC: PWM Control Register C (0x0FF925, 8-bit) --- */
#define PWMC_PCLK_MASK       0xC0   /* PWM clock select                    */
#define PWMC_PPOL_MASK       0x30   /* PWM polarity                        */
#define PWMC_PSWAI           0x08   /* PWM stops in wait mode              */
#define PWMC_PCKB_MASK       0x07   /* PWM clock B prescaler               */


/* ======================================================================
 * QSM - Queued Serial Module  (0x0FFC00 - 0x0FFDFF)
 * Source: MC68HC16ZUM Table D-31
 * ====================================================================== */

/* --- QSMCR: QSM Configuration Register (0x0FFC00, 16-bit) --- */
#define QSMCR_STOP_MASK      0xC000  /* Stop mode behavior                 */
#define QSMCR_FRZ_MASK       0x3000  /* Freeze mode behavior               */
#define QSMCR_SUPV           0x0080  /* Supervisor/unrestricted            */
#define QSMCR_IARB_MASK      0x000F  /* Interrupt arbitration ID           */

/* --- QILR: QSM Interrupt Level Register (0x0FFC04, 8-bit) --- */
#define QILR_ILSPI_MASK      0x70   /* SPI interrupt level                 */
#define QILR_ILSPI_SHIFT     4
#define QILR_ILSCI_MASK      0x07   /* SCI interrupt level                 */

/* --- QIVR: QSM Interrupt Vector Register (0x0FFC05, 8-bit) --- */
/* Base vector number. SCI uses QIVR, SPI uses QIVR+1.
 * Vector address = vector_number * 2 */

/* --- SCCR0: SCI Control Register 0 (0x0FFC08, 16-bit) --- */
#define SCCR0_SCBR_MASK      0x1FFF  /* SCI baud rate divisor              */
/* Baud = System_Clock / (32 * SCBR) */

/* --- SCCR1: SCI Control Register 1 (0x0FFC0A, 16-bit) --- */
#define SCCR1_LOOPS          0x4000  /* Loop mode                           */
#define SCCR1_WOMS           0x2000  /* Wired-OR mode for SCI pins          */
#define SCCR1_ILT            0x1000  /* Idle line type                      */
#define SCCR1_PT             0x0800  /* Parity type (0=even, 1=odd)         */
#define SCCR1_PE             0x0400  /* Parity enable                       */
#define SCCR1_M              0x0200  /* Mode (0=8-bit, 1=9-bit)            */
#define SCCR1_WAKE           0x0100  /* Wakeup method                       */
#define SCCR1_TIE            0x0080  /* Transmit interrupt enable           */
#define SCCR1_TCIE           0x0040  /* Transmit complete interrupt enable  */
#define SCCR1_RIE            0x0020  /* Receive interrupt enable            */
#define SCCR1_ILIE           0x0010  /* Idle line interrupt enable           */
#define SCCR1_TE             0x0008  /* Transmitter enable                  */
#define SCCR1_RE             0x0004  /* Receiver enable                     */
#define SCCR1_RWU            0x0002  /* Receiver wakeup                     */
#define SCCR1_SBK            0x0001  /* Send break                          */
/* Typical JTEC+ init: SCCR1 = 0x000C (TE=1, RE=1) */

/* --- SCSR: SCI Status Register (0x0FFC0C, 16-bit) --- */
#define SCSR_TDRE            0x0100  /* Transmit data register empty        */
#define SCSR_TC              0x0080  /* Transmit complete                   */
#define SCSR_RDRF            0x0040  /* Receive data register full          */
#define SCSR_RAF             0x0020  /* Receiver active flag                */
#define SCSR_IDLE            0x0010  /* Idle line detected                  */
#define SCSR_OR              0x0008  /* Overrun error                       */
#define SCSR_NF              0x0004  /* Noise error flag                    */
#define SCSR_FE              0x0002  /* Framing error                       */
#define SCSR_PF              0x0001  /* Parity error flag                   */

/* --- SPCR0: SPI Control Register 0 (0x0FFC18, 16-bit) --- */
#define SPCR0_MSTR           0x8000  /* Master mode                         */
#define SPCR0_WOMQ           0x4000  /* Wired-OR mode for QSPI pins        */
#define SPCR0_BITS_MASK      0x3C00  /* Bits per transfer (0=16, else n)    */
#define SPCR0_BITS_SHIFT     10
#define SPCR0_CPOL           0x0200  /* Clock polarity                      */
#define SPCR0_CPHA           0x0100  /* Clock phase                         */
#define SPCR0_SPBR_MASK      0x00FF  /* SPI baud rate divisor               */
/* SPI baud = System_Clock / (2 * SPBR)
 * Typical JTEC+ init: SPCR0 = 0x810B
 *   MSTR=1, BITS=0 (16-bit), CPOL=0, CPHA=0, SPBR=0x0B */

/* --- SPCR1: SPI Control Register 1 (0x0FFC1A, 16-bit) --- */
#define SPCR1_SPE            0x8000  /* SPI enable                          */
#define SPCR1_DSCKL_MASK     0x7F00  /* PCS to SCK delay                    */
#define SPCR1_DTL_MASK       0x00FF  /* Delay after transfer                */

/* --- SPCR2: SPI Control Register 2 (0x0FFC1C, 16-bit) --- */
#define SPCR2_SPIFIE         0x8000  /* SPI finished interrupt enable       */
#define SPCR2_WREN           0x4000  /* Wrap enable                         */
#define SPCR2_WRTO           0x2000  /* Wrap to pointer                     */
#define SPCR2_ENDQP_MASK     0x0F00  /* End queue pointer                   */
#define SPCR2_ENDQP_SHIFT    8
#define SPCR2_NEWQP_MASK     0x000F  /* New queue start pointer             */

/* --- SPCR3: SPI Control Register 3 (0x0FFC1E, 8-bit) --- */
#define SPCR3_LOOPQ          0x04   /* Loop mode for QSPI                  */
#define SPCR3_HMIE           0x02   /* HALTA and MODF interrupt enable     */
#define SPCR3_HALT           0x01   /* Halt                                */

/* --- SPSR: SPI Status Register (0x0FFC1F, 8-bit) --- */
#define SPSR_SPIF            0x80   /* QSPI finished                       */
#define SPSR_MODF            0x40   /* Mode fault                          */
#define SPSR_HALTA           0x20   /* Halt acknowledge                    */
#define SPSR_CPTQP_MASK      0x0F   /* Completed queue pointer             */

/* --- QSPI Command RAM entries (0x0FFD40-0x0FFD5F) --- */
#define QSPI_CMD_CONT        0x80   /* Continue: don't toggle PCS          */
#define QSPI_CMD_BITSE       0x40   /* Bits per transfer override enable   */
#define QSPI_CMD_DT          0x20   /* Delay after transfer enable         */
#define QSPI_CMD_DSCK        0x10   /* PCS to SCK delay enable             */
#define QSPI_CMD_PCS_MASK    0x0F   /* Peripheral chip select (active low) */


/* ======================================================================
 * ADC - Analog-to-Digital Converter  (0x0FF700 - 0x0FF73F)
 * Source: MC68HC16ZUM Table D-24
 * ====================================================================== */

/* --- ADCMCR: ADC Module Configuration Register (0x0FF700, 16-bit) --- */
#define ADCMCR_STOP_MASK     0xC000  /* Stop mode behavior                 */
#define ADCMCR_FRZ_MASK      0x3000  /* Freeze mode behavior               */
#define ADCMCR_SUPV          0x0080  /* Supervisor/unrestricted            */
#define ADCMCR_IARB_MASK     0x000F  /* Interrupt arbitration ID           */

/* --- ADCTL0: ADC Control Register 0 (0x0FF70A, 16-bit) --- */
#define ADCTL0_PRS_MASK      0x1F00  /* ADC clock prescaler                */
#define ADCTL0_PRS_SHIFT     8
#define ADCTL0_STS_MASK      0x00E0  /* Sample time select                 */
#define ADCTL0_STS_SHIFT     5
#define ADCTL0_RES10         0x0010  /* Resolution (0=8-bit, 1=10-bit)     */
/* Typical JTEC+ init: ADCTL0 = 0x00EA */

/* --- ADCTL1: ADC Control Register 1 (0x0FF70C, 16-bit) --- */
#define ADCTL1_SCAN          0x0080  /* Continuous scan mode                */
#define ADCTL1_MULT          0x0040  /* Multi-channel mode                  */
#define ADCTL1_S8CM          0x0020  /* 8-channel mode (vs 4-channel)       */
#define ADCTL1_CD_CA_MASK    0x001F  /* Channel select (CD-CA bits)         */
/* Typical JTEC+ init: ADCTL1 = 0x0030 (scan all 8 channels) */

/* --- ADCSTAT: ADC Status Register (0x0FF70E, 16-bit) --- */
#define ADCSTAT_CCF          0x8000  /* Conversion complete flag            */
#define ADCSTAT_SCF_MASK     0x00FF  /* Per-channel conversion flags        */


/* ======================================================================
 * SRAM - Standby RAM Module  (0x0FFB00 - 0x0FFB07)
 * Source: MC68HC16ZUM Table D-19
 * ====================================================================== */

/* --- RAMMCR: RAM Module Configuration Register (0x0FFB00, 16-bit) --- */
#define RAMMCR_STOP_MASK     0xC000  /* Stop mode behavior                 */
#define RAMMCR_RASP_MASK     0x0300  /* RAM array space (access control)   */
#define RAMMCR_IARB_MASK     0x000F  /* Interrupt arbitration ID           */

/* --- RAMBAH/RAMBAL: RAM Base Address (0x0FFB04/06) ---
 * RAMBAH[7:0] = address bits [19:12]
 * RAMBAL[15:0] = address bits [15:0] (low 12 bits forced to 0)
 * Typical JTEC+ init: RAMBAH=0xFF, RAMBAL=0x8000 -> SRAM at 0x0F8000 */


/* ======================================================================
 * MRM - Masked ROM Module  (0x0FF820 - 0x0FF83F)
 * Source: MC68HC16ZUM Table D-21 (Z2/Z3 only)
 * ====================================================================== */

/* --- MRMCR: MRM Configuration Register (0x0FF820, 16-bit) --- */
#define MRMCR_STOP_MASK      0xC000  /* Stop mode behavior                 */
#define MRMCR_IARB_MASK      0x000F  /* Interrupt arbitration ID           */


/* ======================================================================
 * CCR - Condition Code Register (CPU16 internal, 16-bit)
 * Source: CPU16RM Section 3.4
 *
 * Not an MMIO register, but included for firmware analysis reference.
 * ANDP/ORP instructions modify CCR bits. PK field preserved in bits [3:0].
 * ====================================================================== */

#define CCR_S                0x8000  /* Stop disable                        */
#define CCR_MV               0x4000  /* MAC overflow                        */
#define CCR_H                0x2000  /* Half carry                          */
#define CCR_EV               0x1000  /* Extension overflow (MAC)            */
#define CCR_N                0x0800  /* Negative                            */
#define CCR_Z                0x0400  /* Zero                                */
#define CCR_V                0x0200  /* Overflow                            */
#define CCR_C                0x0100  /* Carry / Borrow                      */
#define CCR_IP_MASK          0x00E0  /* Interrupt priority level [2:0]      */
#define CCR_IP_SHIFT         5
#define CCR_SM               0x0010  /* Stack mode (0=system, 1=user)       */
#define CCR_PK_MASK          0x000F  /* Program bank extension [3:0]        */


/* ======================================================================
 * JTEC+ STARTUP REGISTER INITIALIZATION QUICK REFERENCE
 *
 * Decoded from STARTUP function at 0x020000:
 *
 * SYPCR  = 0xB4  -> SWE=1, SWP=0, SWT=3, HME=0, BME=1, BMT=0
 * SYNCR  = 0x95  -> W=0, X=0, Y=0x25, SLOCK wait loop, then set SLOCK
 * SIMCR  = 0x81CF -> EXOFF=1, SHEN=3, SUPV=1, MM=1, IARB=0xF
 * RAMBAH = 0xFF, RAMBAL=0x8000 -> SRAM at 0x0F8000
 * CSBAR0 = 0x0400, CSOR0=0x7C70 -> CS0: bank 4, 2KB, 8-bit, R/W
 * ADCMCR = 0x0000
 * ADCTL0 = 0x00EA
 * SPCR0  = 0x810B -> MSTR=1, 16-bit, SPBR=0x0B
 * SCCR0  = 0x0058 -> baud divisor = 0x58 = 88
 * SCCR1  = 0x000C -> TE=1, RE=1
 * QIVR   = 0x4E  -> SCI vector 0x4E (addr 0x009C), SPI vector 0x4F
 * PICR   = 0x0338 -> PIRQL=3, PIV=0x38 (addr 0x0070)
 * GPTMCR = 0x008C -> SUPV=1, IARB=0xC
 * ICR    = 0x0440
 * PITR   = 0x0002
 * ====================================================================== */

#endif /* MC68HC16Z3_REGS_H */
