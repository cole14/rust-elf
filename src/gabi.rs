/// This file contains constants defined in the ELF GABI
///     See http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid
/// Note: At least in 2022, it seems like the above site is not being updated. Official communication
/// occurs on the Generic System V Application Binary Interface mailing list:
///     https://groups.google.com/g/generic-abi

/// EI_* define indexes into the ELF File Header's e_ident[] byte array.
/// We define them as usize in order to use them to easily index into [u8].

/// Location of first ELF magic number byte
pub const EI_MAG0: usize = 0;
/// Location of second ELF magic number byte
pub const EI_MAG1: usize = 1;
/// Location of third ELF magic number byte
pub const EI_MAG2: usize = 2;
/// Location of fourth ELF magic number byte
pub const EI_MAG3: usize = 3;
/// Location of ELF class field in ELF file header ident array
pub const EI_CLASS: usize = 4;
/// Location of data format field in ELF file header ident array
pub const EI_DATA: usize = 5;
/// Location of ELF version field in ELF file header ident array
pub const EI_VERSION: usize = 6;
/// Location of OS ABI field in ELF file header ident array
pub const EI_OSABI: usize = 7;
/// Location of ABI version field in ELF file header ident array
pub const EI_ABIVERSION: usize = 8;
/// Start of padding bytes
pub const EI_PAD: usize = 9;
/// Length of ELF file header platform-independent identification fields (e_ident[])
pub const EI_NIDENT: usize = 16;

/// ELF magic number byte 1
pub const ELFMAG0: u8 = 0x7f;
/// ELF magic number byte 2
pub const ELFMAG1: u8 = 0x45;
/// ELF magic number byte 3
pub const ELFMAG2: u8 = 0x4c;
/// ELF magic number byte 4
pub const ELFMAG3: u8 = 0x46;
pub const ELFMAGIC: [u8; 4] = [ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3];

/// ELFCLASS* define constants for e_ident[EI_CLASS]

/// Invalid ELF file class
pub const ELFCLASSNONE: u8 = 0;
/// 32-bit ELF file
pub const ELFCLASS32: u8 = 1;
/// 64-bit ELF file
pub const ELFCLASS64: u8 = 2;

/// ELFDATA* define constants for e_ident[EI_DATA]

/// Invalid ELF data format
pub const ELFDATANONE: u8 = 0;
/// 2's complement values, with the least significant byte occupying the lowest address.
pub const ELFDATA2LSB: u8 = 1;
/// 2's complement values, with the most significant byte occupying the lowest address.
pub const ELFDATA2MSB: u8 = 2;

/// ELFOSABI* define constants for e_ident[EI_OSABI]

/// No extensions or unspecified
pub const ELFOSABI_NONE: u8 = 0;
/// Alias of unspecified for UNIX System V ABI
pub const ELFOSABI_SYSV: u8 = 0;
/// Hewlett-Packard HP-UX
pub const ELFOSABI_HPUX: u8 = 1;
/// NetBSD
pub const ELFOSABI_NETBSD: u8 = 2;
/// GNU
pub const ELFOSABI_GNU: u8 = 3;
/// Linux historical - alias for ELFOSABI_GNU
pub const ELFOSABI_LINUX: u8 = 3;
/// Sun Solaris
pub const ELFOSABI_SOLARIS: u8 = 6;
/// AIX
pub const ELFOSABI_AIX: u8 = 7;
/// IRIX
pub const ELFOSABI_IRIX: u8 = 8;
/// FreeBSD
pub const ELFOSABI_FREEBSD: u8 = 9;
/// Compaq TRU64 UNIX
pub const ELFOSABI_TRU64: u8 = 10;
/// Novell Modesto
pub const ELFOSABI_MODESTO: u8 = 11;
/// Open BSD
pub const ELFOSABI_OPENBSD: u8 = 12;
/// Open VMS
pub const ELFOSABI_OPENVMS: u8 = 13;
/// Hewlett-Packard Non-Stop Kernel
pub const ELFOSABI_NSK: u8 = 14;
/// Amiga Research OS
pub const ELFOSABI_AROS: u8 = 15;
/// The FenixOS highly scalable multi-core OS
pub const ELFOSABI_FENIXOS: u8 = 16;
/// Nuxi CloudABI
pub const ELFOSABI_CLOUDABI: u8 = 17;
/// Stratus Technologies OpenVOS
pub const ELFOSABI_OPENVOS: u8 = 18;
/// 64-255 Architecture-specific value range

/// ET_* define constants for the ELF File Header's e_type field.
/// Represented as Elf32_Half in Elf32_Ehdr and Elf64_Half in Elf64_Ehdr which
/// are both are 2-byte unsigned integers with 2-byte alignment

/// No file type
pub const ET_NONE: u16 = 0;
/// Relocatable file
pub const ET_REL: u16 = 1;
/// Executable file
pub const ET_EXEC: u16 = 2;
/// Shared object file
pub const ET_DYN: u16 = 3;
/// Core file
pub const ET_CORE: u16 = 4;
/// Operating system-specific
pub const ET_LOOS: u16 = 0xfe00;
/// Operating system-specific
pub const ET_HIOS: u16 = 0xfeff;
/// Processor-specific
pub const ET_LOPROC: u16 = 0xff00;
/// Processor-specific
pub const ET_HIPROC: u16 = 0xffff;

/// EM_* define constants for the ELF File Header's e_machine field.
/// Represented as Elf32_Half in Elf32_Ehdr and Elf64_Half in Elf64_Ehdr which
/// are both 2-byte unsigned integers with 2-byte alignment

pub const EM_NONE: u16 = 0; // No machine
pub const EM_M32: u16 = 1; // AT&T WE 32100
pub const EM_SPARC: u16 = 2; // SPARC
pub const EM_386: u16 = 3; // Intel 80386
pub const EM_68K: u16 = 4; // Motorola 68000
pub const EM_88K: u16 = 5; // Motorola 88000
pub const EM_IAMCU: u16 = 6; // Intel MCU
pub const EM_860: u16 = 7; // Intel 80860
pub const EM_MIPS: u16 = 8; // MIPS I Architecture
pub const EM_S370: u16 = 9; // IBM System/370 Processor
pub const EM_MIPS_RS3_LE: u16 = 10; // MIPS RS3000 Little-endian
                                    // 11-14 Reserved for future use
pub const EM_PARISC: u16 = 15; // Hewlett-Packard PA-RISC
                               // 16 Reserved for future use
pub const EM_VPP500: u16 = 17; // Fujitsu VPP500
pub const EM_SPARC32PLUS: u16 = 18; // Enhanced instruction set SPARC
pub const EM_960: u16 = 19; // Intel 80960
pub const EM_PPC: u16 = 20; // PowerPC
pub const EM_PPC64: u16 = 21; // 64-bit PowerPC
pub const EM_S390: u16 = 22; // IBM System/390 Processor
pub const EM_SPU: u16 = 23; // IBM SPU/SPC
                            // 24-35 Reserved for future use
pub const EM_V800: u16 = 36; // NEC V800
pub const EM_FR20: u16 = 37; // Fujitsu FR20
pub const EM_RH32: u16 = 38; // TRW RH-32
pub const EM_RCE: u16 = 39; // Motorola RCE
pub const EM_ARM: u16 = 40; // ARM 32-bit architecture (AARCH32)
pub const EM_ALPHA: u16 = 41; // Digital Alpha
pub const EM_SH: u16 = 42; // Hitachi SH
pub const EM_SPARCV9: u16 = 43; // SPARC Version 9
pub const EM_TRICORE: u16 = 44; // Siemens TriCore embedded processor
pub const EM_ARC: u16 = 45; // Argonaut RISC Core, Argonaut Technologies Inc.
pub const EM_H8_300: u16 = 46; // Hitachi H8/300
pub const EM_H8_300H: u16 = 47; // Hitachi H8/300H
pub const EM_H8S: u16 = 48; // Hitachi H8S
pub const EM_H8_500: u16 = 49; // Hitachi H8/500
pub const EM_IA_64: u16 = 50; // Intel IA-64 processor architecture
pub const EM_MIPS_X: u16 = 51; // Stanford MIPS-X
pub const EM_COLDFIRE: u16 = 52; // Motorola ColdFire
pub const EM_68HC12: u16 = 53; // Motorola M68HC12
pub const EM_MMA: u16 = 54; // Fujitsu MMA Multimedia Accelerator
pub const EM_PCP: u16 = 55; // Siemens PCP
pub const EM_NCPU: u16 = 56; // Sony nCPU embedded RISC processor
pub const EM_NDR1: u16 = 57; // Denso NDR1 microprocessor
pub const EM_STARCORE: u16 = 58; // Motorola Star*Core processor
pub const EM_ME16: u16 = 59; // Toyota ME16 processor
pub const EM_ST100: u16 = 60; // STMicroelectronics ST100 processor
pub const EM_TINYJ: u16 = 61; // Advanced Logic Corp. TinyJ embedded processor family
pub const EM_X86_64: u16 = 62; // AMD x86-64 architecture
pub const EM_PDSP: u16 = 63; // Sony DSP Processor
pub const EM_PDP10: u16 = 64; // Digital Equipment Corp. PDP-10
pub const EM_PDP11: u16 = 65; // Digital Equipment Corp. PDP-11
pub const EM_FX66: u16 = 66; // Siemens FX66 microcontroller
pub const EM_ST9PLUS: u16 = 67; // STMicroelectronics ST9+ 8/16 bit microcontroller
pub const EM_ST7: u16 = 68; // STMicroelectronics ST7 8-bit microcontroller
pub const EM_68HC16: u16 = 69; // Motorola MC68HC16 Microcontroller
pub const EM_68HC11: u16 = 70; // Motorola MC68HC11 Microcontroller
pub const EM_68HC08: u16 = 71; // Motorola MC68HC08 Microcontroller
pub const EM_68HC05: u16 = 72; // Motorola MC68HC05 Microcontroller
pub const EM_SVX: u16 = 73; // Silicon Graphics SVx
pub const EM_ST19: u16 = 74; // STMicroelectronics ST19 8-bit microcontroller
pub const EM_VAX: u16 = 75; // Digital VAX
pub const EM_CRIS: u16 = 76; // Axis Communications 32-bit embedded processor
pub const EM_JAVELIN: u16 = 77; // Infineon Technologies 32-bit embedded processor
pub const EM_FIREPATH: u16 = 78; // Element 14 64-bit DSP Processor
pub const EM_ZSP: u16 = 79; // LSI Logic 16-bit DSP Processor
pub const EM_MMIX: u16 = 80; // Donald Knuth's educational 64-bit processor
pub const EM_HUANY: u16 = 81; // Harvard University machine-independent object files
pub const EM_PRISM: u16 = 82; // SiTera Prism
pub const EM_AVR: u16 = 83; // Atmel AVR 8-bit microcontroller
pub const EM_FR30: u16 = 84; // Fujitsu FR30
pub const EM_D10V: u16 = 85; // Mitsubishi D10V
pub const EM_D30V: u16 = 86; // Mitsubishi D30V
pub const EM_V850: u16 = 87; // NEC v850
pub const EM_M32R: u16 = 88; // Mitsubishi M32R
pub const EM_MN10300: u16 = 89; // Matsushita MN10300
pub const EM_MN10200: u16 = 90; // Matsushita MN10200
pub const EM_PJ: u16 = 91; // picoJava
pub const EM_OPENRISC: u16 = 92; // OpenRISC 32-bit embedded processor
pub const EM_ARC_COMPACT: u16 = 93; // ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
pub const EM_XTENSA: u16 = 94; // Tensilica Xtensa Architecture
pub const EM_VIDEOCORE: u16 = 95; // Alphamosaic VideoCore processor
pub const EM_TMM_GPP: u16 = 96; // Thompson Multimedia General Purpose Processor
pub const EM_NS32K: u16 = 97; // National Semiconductor 32000 series
pub const EM_TPC: u16 = 98; // Tenor Network TPC processor
pub const EM_SNP1K: u16 = 99; // Trebia SNP 1000 processor
pub const EM_ST200: u16 = 100; // STMicroelectronics (www.st.com) ST200 microcontroller
pub const EM_IP2K: u16 = 101; // Ubicom IP2xxx microcontroller family
pub const EM_MAX: u16 = 102; // MAX Processor
pub const EM_CR: u16 = 103; // National Semiconductor CompactRISC microprocessor
pub const EM_F2MC16: u16 = 104; // Fujitsu F2MC16
pub const EM_MSP430: u16 = 105; // Texas Instruments embedded microcontroller msp430
pub const EM_BLACKFIN: u16 = 106; // Analog Devices Blackfin (DSP) processor
pub const EM_SE_C33: u16 = 107; // S1C33 Family of Seiko Epson processors
pub const EM_SEP: u16 = 108; // Sharp embedded microprocessor
pub const EM_ARCA: u16 = 109; // Arca RISC Microprocessor
pub const EM_UNICORE: u16 = 110; // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
pub const EM_EXCESS: u16 = 111; // eXcess: 16/32/64-bit configurable embedded CPU
pub const EM_DXP: u16 = 112; // Icera Semiconductor Inc. Deep Execution Processor
pub const EM_ALTERA_NIOS2: u16 = 113; // Altera Nios II soft-core processor
pub const EM_CRX: u16 = 114; // National Semiconductor CompactRISC CRX microprocessor
pub const EM_XGATE: u16 = 115; // Motorola XGATE embedded processor
pub const EM_C166: u16 = 116; // Infineon C16x/XC16x processor
pub const EM_M16C: u16 = 117; // Renesas M16C series microprocessors
pub const EM_DSPIC30F: u16 = 118; // Microchip Technology dsPIC30F Digital Signal Controller
pub const EM_CE: u16 = 119; // Freescale Communication Engine RISC core
pub const EM_M32C: u16 = 120; // Renesas M32C series microprocessors
                              // 121-130 Reserved for future use
pub const EM_TSK3000: u16 = 131; // Altium TSK3000 core
pub const EM_RS08: u16 = 132; // Freescale RS08 embedded processor
pub const EM_SHARC: u16 = 133; // Analog Devices SHARC family of 32-bit DSP processors
pub const EM_ECOG2: u16 = 134; // Cyan Technology eCOG2 microprocessor
pub const EM_SCORE7: u16 = 135; // Sunplus S+core7 RISC processor
pub const EM_DSP24: u16 = 136; // New Japan Radio (NJR) 24-bit DSP Processor
pub const EM_VIDEOCORE3: u16 = 137; // Broadcom VideoCore III processor
pub const EM_LATTICEMICO32: u16 = 138; // RISC processor for Lattice FPGA architecture
pub const EM_SE_C17: u16 = 139; // Seiko Epson C17 family
pub const EM_TI_C6000: u16 = 140; // The Texas Instruments TMS320C6000 DSP family
pub const EM_TI_C2000: u16 = 141; // The Texas Instruments TMS320C2000 DSP family
pub const EM_TI_C5500: u16 = 142; // The Texas Instruments TMS320C55x DSP family
pub const EM_TI_ARP32: u16 = 143; // Texas Instruments Application Specific RISC Processor, 32bit fetch
pub const EM_TI_PRU: u16 = 144; // Texas Instruments Programmable Realtime Unit
                                // 145-159 Reserved for future use
pub const EM_MMDSP_PLUS: u16 = 160; // STMicroelectronics 64bit VLIW Data Signal Processor
pub const EM_CYPRESS_M8C: u16 = 161; // Cypress M8C microprocessor
pub const EM_R32C: u16 = 162; // Renesas R32C series microprocessors
pub const EM_TRIMEDIA: u16 = 163; // NXP Semiconductors TriMedia architecture family
pub const EM_QDSP6: u16 = 164; // QUALCOMM DSP6 Processor
pub const EM_8051: u16 = 165; // Intel 8051 and variants
pub const EM_STXP7X: u16 = 166; // STMicroelectronics STxP7x family of configurable and extensible RISC processors
pub const EM_NDS32: u16 = 167; // Andes Technology compact code size embedded RISC processor family
pub const EM_ECOG1: u16 = 168; // Cyan Technology eCOG1X family
pub const EM_ECOG1X: u16 = 168; // Cyan Technology eCOG1X family
pub const EM_MAXQ30: u16 = 169; // Dallas Semiconductor MAXQ30 Core Micro-controllers
pub const EM_XIMO16: u16 = 170; // New Japan Radio (NJR) 16-bit DSP Processor
pub const EM_MANIK: u16 = 171; // M2000 Reconfigurable RISC Microprocessor
pub const EM_CRAYNV2: u16 = 172; // Cray Inc. NV2 vector architecture
pub const EM_RX: u16 = 173; // Renesas RX family
pub const EM_METAG: u16 = 174; // Imagination Technologies META processor architecture
pub const EM_MCST_ELBRUS: u16 = 175; // MCST Elbrus general purpose hardware architecture
pub const EM_ECOG16: u16 = 176; // Cyan Technology eCOG16 family
pub const EM_CR16: u16 = 177; // National Semiconductor CompactRISC CR16 16-bit microprocessor
pub const EM_ETPU: u16 = 178; // Freescale Extended Time Processing Unit
pub const EM_SLE9X: u16 = 179; // Infineon Technologies SLE9X core
pub const EM_L10M: u16 = 180; // Intel L10M
pub const EM_K10M: u16 = 181; // Intel K10M
                              // 182 Reserved for future Intel use
pub const EM_AARCH64: u16 = 183; // ARM 64-bit architecture (AARCH64)
                                 // 184 Reserved for future ARM use
pub const EM_AVR32: u16 = 185; // Atmel Corporation 32-bit microprocessor family
pub const EM_STM8: u16 = 186; // STMicroeletronics STM8 8-bit microcontroller
pub const EM_TILE64: u16 = 187; // Tilera TILE64 multicore architecture family
pub const EM_TILEPRO: u16 = 188; // Tilera TILEPro multicore architecture family
pub const EM_MICROBLAZE: u16 = 189; // Xilinx MicroBlaze 32-bit RISC soft processor core
pub const EM_CUDA: u16 = 190; // NVIDIA CUDA architecture
pub const EM_TILEGX: u16 = 191; // Tilera TILE-Gx multicore architecture family
pub const EM_CLOUDSHIELD: u16 = 192; // CloudShield architecture family
pub const EM_COREA_1ST: u16 = 193; // KIPO-KAIST Core-A 1st generation processor family
pub const EM_COREA_2ND: u16 = 194; // KIPO-KAIST Core-A 2nd generation processor family
pub const EM_ARC_COMPACT2: u16 = 195; // Synopsys ARCompact V2
pub const EM_OPEN8: u16 = 196; // Open8 8-bit RISC soft processor core
pub const EM_RL78: u16 = 197; // Renesas RL78 family
pub const EM_VIDEOCORE5: u16 = 198; // Broadcom VideoCore V processor
pub const EM_78KOR: u16 = 199; // Renesas 78KOR family
pub const EM_56800EX: u16 = 200; // Freescale 56800EX Digital Signal Controller (DSC)
pub const EM_BA1: u16 = 201; // Beyond BA1 CPU architecture
pub const EM_BA2: u16 = 202; // Beyond BA2 CPU architecture
pub const EM_XCORE: u16 = 203; // XMOS xCORE processor family
pub const EM_MCHP_PIC: u16 = 204; // Microchip 8-bit PIC(r) family
pub const EM_INTEL205: u16 = 205; // Reserved by Intel
pub const EM_INTEL206: u16 = 206; // Reserved by Intel
pub const EM_INTEL207: u16 = 207; // Reserved by Intel
pub const EM_INTEL208: u16 = 208; // Reserved by Intel
pub const EM_INTEL209: u16 = 209; // Reserved by Intel
pub const EM_KM32: u16 = 210; // KM211 KM32 32-bit processor
pub const EM_KMX32: u16 = 211; // KM211 KMX32 32-bit processor
pub const EM_KMX16: u16 = 212; // KM211 KMX16 16-bit processor
pub const EM_KMX8: u16 = 213; // KM211 KMX8 8-bit processor
pub const EM_KVARC: u16 = 214; // KM211 KVARC processor
pub const EM_CDP: u16 = 215; // Paneve CDP architecture family
pub const EM_COGE: u16 = 216; // Cognitive Smart Memory Processor
pub const EM_COOL: u16 = 217; // Bluechip Systems CoolEngine
pub const EM_NORC: u16 = 218; // Nanoradio Optimized RISC
pub const EM_CSR_KALIMBA: u16 = 219; // CSR Kalimba architecture family
pub const EM_Z80: u16 = 220; // Zilog Z80
pub const EM_VISIUM: u16 = 221; // Controls and Data Services VISIUMcore processor
pub const EM_FT32: u16 = 222; // FTDI Chip FT32 high performance 32-bit RISC architecture
pub const EM_MOXIE: u16 = 223; // Moxie processor family
pub const EM_AMDGPU: u16 = 224; // AMD GPU architecture
pub const EM_RISCV: u16 = 243; // RISC-V
pub const EM_BPF: u16 = 247; // Linux BPF

/// EV_* define constants for the ELF File Header's e_version field.
/// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
/// are both 4-byte unsigned integers with 4-byte alignment

/// Invalid version
pub const EV_NONE: u8 = 0;
/// Current version
pub const EV_CURRENT: u8 = 1;

/// PF_* define constants for the ELF Program Header's p_flags field.
/// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
/// are both 4-byte unsigned integers with 4-byte alignment

pub const PF_NONE: u32 = 0;
/// Executable program segment
pub const PF_X: u32 = 1;
/// Writable program segment
pub const PF_W: u32 = 2;
/// Readable program segment
pub const PF_R: u32 = 4;
// All bits included in the PF_MASKOS mask are reserved for operating system-specific semantics.
pub const PF_MASKOS: u32 = 0x0ff00000;
//  All bits included in the PF_MASKPROC mask are reserved for processor-specific semantics.
pub const PF_MASKPROC: u32 = 0xf0000000;

/// PT_* define constants for the ELF Program Header's p_type field.
/// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
/// are both 4-byte unsigned integers with 4-byte alignment

/// Program header table entry unused
pub const PT_NULL: u32 = 0;
/// Loadable program segment
pub const PT_LOAD: u32 = 1;
/// Dynamic linking information
pub const PT_DYNAMIC: u32 = 2;
/// Program interpreter
pub const PT_INTERP: u32 = 3;
/// Auxiliary information
pub const PT_NOTE: u32 = 4;
/// Unused
pub const PT_SHLIB: u32 = 5;
/// The program header table
pub const PT_PHDR: u32 = 6;
/// Thread-local storage segment
pub const PT_TLS: u32 = 7;
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
/// Indicates stack executability
pub const PT_GNU_STACK: u32 = 0x6474e551;
/// Read-only after relocation
pub const PT_GNU_RELRO: u32 = 0x6474e552;
/// Values between [PT_LOOS, PT_HIOS] in this inclusive range are reserved for operating system-specific semantics.
pub const PT_LOOS: u32 = 0x60000000;
/// Values between [PT_LOOS, PT_HIOS] in this inclusive range are reserved for operating system-specific semantics.
pub const PT_HIOS: u32 = 0x6fffffff;
/// Values between [PT_LOPROC, PT_HIPROC] in this inclusive range are reserved for processor-specific semantics.
pub const PT_LOPROC: u32 = 0x70000000;
/// Values between [PT_LOPROC, PT_HIPROC] in this inclusive range are reserved for processor-specific semantics.
pub const PT_HIPROC: u32 = 0x7fffffff;