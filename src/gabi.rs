/// This file contains constants defined in the ELF GABI
///     See <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>
/// Note: At least in 2022, it seems like the above site is not being updated. Official communication
/// occurs on the Generic System V Application Binary Interface mailing list:
///     <https://groups.google.com/g/generic-abi>

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
/// Values between [PT_LOOS, PT_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const PT_LOOS: u32 = 0x60000000;
/// Values between [PT_LOOS, PT_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const PT_HIOS: u32 = 0x6fffffff;
/// Values between [PT_LOPROC, PT_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const PT_LOPROC: u32 = 0x70000000;
/// Values between [PT_LOPROC, PT_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const PT_HIPROC: u32 = 0x7fffffff;

/// SHT_* define constants for the ELF Section Header's p_type field.
/// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
/// are both 4-byte unsigned integers with 4-byte alignment

/// Inactive section with undefined values
pub const SHT_NULL: u32 = 0;
/// Information defined by the program, includes executable code and data
pub const SHT_PROGBITS: u32 = 1;
/// Section data contains a symbol table
pub const SHT_SYMTAB: u32 = 2;
/// Section data contains a string table
pub const SHT_STRTAB: u32 = 3;
/// Section data contains relocation entries with explicit addends
pub const SHT_RELA: u32 = 4;
/// Section data contains a symbol hash table. Must be present for dynamic linking
pub const SHT_HASH: u32 = 5;
/// Section data contains information for dynamic linking
pub const SHT_DYNAMIC: u32 = 6;
/// Section data contains information that marks the file in some way
pub const SHT_NOTE: u32 = 7;
/// Section data occupies no space in the file but otherwise resembles SHT_PROGBITS
pub const SHT_NOBITS: u32 = 8;
/// Section data contains relocation entries without explicit addends
pub const SHT_REL: u32 = 9;
/// Section is reserved but has unspecified semantics
pub const SHT_SHLIB: u32 = 10;
/// Section data contains a minimal set of dynamic linking symbols
pub const SHT_DYNSYM: u32 = 11;
/// Section data contains an array of constructors
pub const SHT_INIT_ARRAY: u32 = 14;
/// Section data contains an array of destructors
pub const SHT_FINI_ARRAY: u32 = 15;
/// Section data contains an array of pre-constructors
pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Section group
pub const SHT_GROUP: u32 = 17;
/// Extended symbol table section index
pub const SHT_SYMTAB_SHNDX: u32 = 18;
/// Number of reserved SHT_* values
pub const SHT_NUM: u32 = 19;
/// Object attributes
pub const SHT_GNU_ATTRIBUTES: u32 = 0x6ffffff5;
/// GNU-style hash section
pub const SHT_GNU_HASH: u32 = 0x6ffffff6;
/// Pre-link library list
pub const SHT_GNU_LIBLIST: u32 = 0x6ffffff7;
/// Version definition section
pub const SHT_GNU_VERDEF: u32 = 0x6ffffffd;
/// Version needs section
pub const SHT_GNU_VERNEED: u32 = 0x6ffffffe;
/// Version symbol table
pub const SHT_GNU_VERSYM: u32 = 0x6fffffff;

/// This value marks an undefined, missing, irrelevant, or otherwise meaningless
/// section reference.
pub const SHN_UNDEF: u16 = 0;
pub const SHN_XINDEX: u16 = 0xffff;

/// SHF_* define constants for the ELF Section Header's sh_flags field.
/// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Xword in Elf64_Ehdr which
/// are both 4-byte and 8-byte unsigned integers, respectively.
/// All of the constants are < 32-bits, so we use a u32 to represent these in order
/// to make working with them easier.

/// Empty flags
pub const SHF_NONE: u32 = 0;
/// The section contains data that should be writable during process execution.
pub const SHF_WRITE: u32 = 1;
/// The section occupies memory during process execution. Some control sections
/// do not reside in the memory image of an object file; this attribute is off for
/// those sections.
pub const SHF_ALLOC: u32 = 1 << 1;
/// The section contains executable machine instructions.
pub const SHF_EXECINSTR: u32 = 1 << 2;
/// The data in the section may be merged to eliminate duplication. Unless the
/// SHF_STRINGS flag is also set, the data elements in the section are of a uniform size.
/// The size of each element is specified in the section header's sh_entsize field. If
/// the SHF_STRINGS flag is also set, the data elements consist of null-terminated
/// character strings. The size of each character is specified in the section header's
/// sh_entsize field.
///
/// Each element in the section is compared against other elements in sections with the
/// same name, type and flags. Elements that would have identical values at program
/// run-time may be merged. Relocations referencing elements of such sections must be
/// resolved to the merged locations of the referenced values. Note that any relocatable
/// values, including values that would result in run-time relocations, must be analyzed
/// to determine whether the run-time values would actually be identical. An
/// ABI-conforming object file may not depend on specific elements being merged, and an
/// ABI-conforming link editor may choose not to merge specific elements.
pub const SHF_MERGE: u32 = 1 << 4;
/// The data elements in the section consist of null-terminated character strings.
/// The size of each character is specified in the section header's sh_entsize field.
pub const SHF_STRINGS: u32 = 1 << 5;
/// The sh_info field of this section header holds a section header table index.
pub const SHF_INFO_LINK: u32 = 1 << 6;
/// This flag adds special ordering requirements for link editors. The requirements
/// apply if the sh_link field of this section's header references another section (the
/// linked-to section). If this section is combined with other sections in the output
/// file, it must appear in the same relative order with respect to those sections,
/// as the linked-to section appears with respect to sections the linked-to section is
/// combined with.
pub const SHF_LINK_ORDER: u32 = 1 << 7;
/// This section requires special OS-specific processing (beyond the standard linking
/// rules) to avoid incorrect behavior. If this section has either an sh_type value or
/// contains sh_flags bits in the OS-specific ranges for those fields, and a link
/// editor processing this section does not recognize those values, then the link editor
/// should reject the object file containing this section with an error.
pub const SHF_OS_NONCONFORMING: u32 = 1 << 8;
/// This section is a member (perhaps the only one) of a section group. The section must
/// be referenced by a section of type SHT_GROUP. The SHF_GROUP flag may be set only for
/// sections contained in relocatable objects (objects with the ELF header e_type member
/// set to ET_REL).
pub const SHF_GROUP: u32 = 1 << 9;
/// This section holds Thread-Local Storage, meaning that each separate execution flow
/// has its own distinct instance of this data. Implementations need not support this flag.
pub const SHF_TLS: u32 = 1 << 10;
/// This flag identifies a section containing compressed data. SHF_COMPRESSED applies only
/// to non-allocable sections, and cannot be used in conjunction with SHF_ALLOC. In
/// addition, SHF_COMPRESSED cannot be applied to sections of type SHT_NOBITS.
///
/// All relocations to a compressed section specifiy offsets to the uncompressed section
/// data. It is therefore necessary to decompress the section data before relocations can
/// be applied. Each compressed section specifies the algorithm independently. It is
/// permissible for different sections in a given ELF object to employ different
/// compression algorithms.
///
/// Compressed sections begin with a compression header structure that identifies the
/// compression algorithm.
pub const SHF_COMPRESSED: u32 = 1 << 11;
/// Masked bits are reserved for operating system-specific semantics.
pub const SHF_MASKOS: u32 = 0x0ff00000;
/// Masked bits are reserved for processor-specific semantics.
pub const SHF_MASKPROC: u32 = 0xf0000000;

/// STT_* define constants for the ELF Symbol's st_type (encoded in the st_info field).

/// Unspecified symbol type
pub const STT_NOTYPE: u8 = 0;
/// Data object symbol
pub const STT_OBJECT: u8 = 1;
/// Code object symbol
pub const STT_FUNC: u8 = 2;
/// Section symbol
pub const STT_SECTION: u8 = 3;
/// File name symbol
pub const STT_FILE: u8 = 4;
/// Common data object symbol
pub const STT_COMMON: u8 = 5;
/// Thread-local data object symbol
pub const STT_TLS: u8 = 6;
/// Indirect code object symbol
pub const STT_GNU_IFUNC: u8 = 10;
/// Values between [STT_LOOS, STT_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const STT_LOOS: u8 = 10;
/// Values between [STT_LOOS, STT_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const STT_HIOS: u8 = 12;
/// Values between [STT_LOPROC, STT_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const STT_LOPROC: u8 = 13;
/// Values between [STT_LOPROC, STT_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const STT_HIPROC: u8 = 15;

/// STB_* define constants for the ELF Symbol's st_bind (encoded in the st_info field).

/// Local symbols are not visible outside the object file containing their
/// definition.  Local symbols of the same name may exist in multiple files
/// without interfering with each other.
pub const STB_LOCAL: u8 = 0;
/// Global symbols are visible to all object files being combined. One file's
/// definition of a global symbol will satisfy another file's undefined
/// reference to the same global symbol.
pub const STB_GLOBAL: u8 = 1;
/// Weak symbols resemble global symbols, but their definitions have lower
/// precedence.
pub const STB_WEAK: u8 = 2;
/// Unique symbol
pub const STB_GNU_UNIQUE: u8 = 10;
/// Values between [STB_LOOS, STB_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const STB_LOOS: u8 = 10;
/// Values between [STB_LOOS, STB_HIOS] in this inclusive range are reserved for
/// operating system-specific semantics.
pub const STB_HIOS: u8 = 12;
/// Values between [STB_LOPROC, STB_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const STB_LOPROC: u8 = 13;
/// Values between [STB_LOPROC, STB_HIPROC] in this inclusive range are reserved
/// for processor-specific semantics.
pub const STB_HIPROC: u8 = 15;

/// STV_* define constants for the ELF Symbol's st_visibility (encoded in the st_other field).

/// The visibility of symbols with the STV_DEFAULT attribute is as specified by
/// the symbol's binding type.  That is, global and weak symbols are visible
/// outside of their defining component (executable file or shared object).
/// Local symbols are hidden, as described below. Global and weak symbols are
/// also preemptable, that is, they may by preempted by definitions of the same
/// name in another component.
pub const STV_DEFAULT: u8 = 0;
/// The meaning of this visibility attribute may be defined by processor
/// supplements to further constrain hidden symbols. A processor supplement's
/// definition should be such that generic tools can safely treat internal
/// symbols as hidden.
pub const STV_INTERNAL: u8 = 1;
/// A symbol defined in the current component is hidden if its name is not
/// visible to other components. Such a symbol is necessarily protected. This
/// attribute may be used to control the external interface of a component. Note
/// that an object named by such a symbol may still be referenced from another
/// component if its address is passed outside.
pub const STV_HIDDEN: u8 = 2;
/// A symbol defined in the current component is protected if it is visible in
/// other components but not preemptable, meaning that any reference to such a
/// symbol from within the defining component must be resolved to the definition
/// in that component, even if there is a definition in another component that
/// would preempt by the default rules.
pub const STV_PROTECTED: u8 = 3;

/// An entry with a DT_NULL tag marks the end of the _DYNAMIC array.
pub const DT_NULL: i64 = 0;
/// This element holds the string table offset of a null-terminated string,
/// giving the name of a needed library. The offset is an index into the table
/// recorded in the DT_STRTAB code. The dynamic array may contain multiple
/// entries with this type. These entries' relative order is significant, though
/// their relation to entries of other types is not.
pub const DT_NEEDED: i64 = 1;
/// This element holds the total size, in bytes, of the relocation entries
/// associated with the procedure linkage table. If an entry of type DT_JMPREL
/// is present, a DT_PLTRELSZ must accompany it.
pub const DT_PLTRELSZ: i64 = 2;
/// This element holds an address associated with the procedure linkage table
/// and/or the global offset table.
pub const DT_PLTGOT: i64 = 3;
/// This element holds the address of the symbol hash table. This hash table
/// refers to the symbol table referenced by the DT_SYMTAB element.
pub const DT_HASH: i64 = 4;
/// This element holds the address of the string table. Symbol names, library
/// names, and other strings reside in this table.
pub const DT_STRTAB: i64 = 5;
/// This element holds the address of the symbol table.
pub const DT_SYMTAB: i64 = 6;
/// This element holds the address of a relocation table. Entries in the table
/// have explicit addends, (Rela). An object file may have multiple relocation
/// sections. When building the relocation table for an executable or shared
/// object file, the link editor catenates those sections to form a single
/// table. Although the sections remain independent in the object file, the
/// dynamic linker sees a single table. When the dynamic linker creates the
/// process image for an executable file or adds a shared object to the process
/// image, it reads the relocation table and performs the associated actions.
/// If this element is present, the dynamic structure must also have DT_RELASZ
/// and DT_RELAENT elements. When relocation is mandatory for a file, either
/// DT_RELA or DT_REL may occur (both are permitted but not required).
pub const DT_RELA: i64 = 7;
/// This element holds the total size, in bytes, of the DT_RELA relocation table.
pub const DT_RELASZ: i64 = 8;
/// This element holds the size, in bytes, of the DT_RELA relocation entry.
pub const DT_RELAENT: i64 = 9;
/// This element holds the size, in bytes, of the string table.
pub const DT_STRSZ: i64 = 10;
/// This element holds the size, in bytes, of a symbol table entry.
pub const DT_SYMENT: i64 = 11;
/// This element holds the address of the initialization function.
pub const DT_INIT: i64 = 12;
/// This element holds the address of the termination function.
pub const DT_FINI: i64 = 13;
/// This element holds the string table offset of a null-terminated string,
/// giving the name of the shared object. The offset is an index into the table
/// recorded in the DT_STRTAB entry.
pub const DT_SONAME: i64 = 14;
/// This element holds the string table offset of a null-terminated search
/// library search path string. The offset is an index into the table recorded
/// in the DT_STRTAB entry. Its use has been superseded by DT_RUNPATH.
pub const DT_RPATH: i64 = 15;
/// This element's presence in a shared object library alters the dynamic
/// linker's symbol resolution algorithm for references within the library.
/// Instead of starting a symbol search with the executable file, the dynamic
/// linker starts from the shared object itself. If the shared object fails to
/// supply the referenced symbol, the dynamic linker then searches the
/// executable file and other shared objects as usual. Its use has been
/// superseded by the DF_SYMBOLIC flag.
pub const DT_SYMBOLIC: i64 = 16;
/// This element is similar to DT_RELA, except its table has implicit addends (Rel).
/// If this element is present, the dynamic structure must also have DT_RELSZ
/// and DT_RELENT elements.
pub const DT_REL: i64 = 17;
/// This element holds the total size, in bytes, of the DT_REL relocation table.
pub const DT_RELSZ: i64 = 18;
/// This element holds the size, in bytes, of the DT_REL relocation entry.
pub const DT_RELENT: i64 = 19;
/// This member specifies the type of relocation entry to which the procedure
/// linkage table refers. The d_val member holds DT_REL or DT_RELA, as
/// appropriate. All relocations in a procedure linkage table must use the same
/// relocation.
pub const DT_PLTREL: i64 = 20;
/// This member is used for debugging. Its contents are not specified for the
/// ABI; programs that access this entry are not ABI-conforming.
pub const DT_DEBUG: i64 = 21;
/// This member's absence signifies that no relocation entry should cause a
/// modification to a non-writable segment, as specified by the segment
/// permissions in the program header table. If this member is present, one or
/// more relocation entries might request modifications to a non-writable
/// segment, and the dynamic linker can prepare accordingly. Its use has been
/// superseded by the DF_TEXTREL flag.
pub const DT_TEXTREL: i64 = 22;
/// If present, this entry's d_ptr member holds the address of relocation
/// entries associated solely with the procedure linkage table. Separating these
/// relocation entries lets the dynamic linker ignore them during process
/// initialization, if lazy binding is enabled. If this entry is present, the
/// related entries of types DT_PLTRELSZ and DT_PLTREL must also be present.
pub const DT_JMPREL: i64 = 23;
/// If present in a shared object or executable, this entry instructs the
/// dynamic linker to process all relocations for the object containing this
/// entry before transferring control to the program. The presence of this entry
/// takes precedence over a directive to use lazy binding for this object when
/// specified through the environment or via dlopen(BA_LIB). Its use has been
/// superseded by the DF_BIND_NOW flag.
pub const DT_BIND_NOW: i64 = 24;
/// This element holds the address of the array of pointers to initialization functions.
pub const DT_INIT_ARRAY: i64 = 25;
/// This element holds the address of the array of pointers to termination functions.
pub const DT_FINI_ARRAY: i64 = 26;
/// This element holds the size in bytes of the array of initialization
/// functions pointed to by the DT_INIT_ARRAY entry. If an object has a
/// DT_INIT_ARRAY entry, it must also have a DT_INIT_ARRAYSZ entry.
pub const DT_INIT_ARRAYSZ: i64 = 27;
/// This element holds the size in bytes of the array of termination functions
/// pointed to by the DT_FINI_ARRAY entry. If an object has a DT_FINI_ARRAY
/// entry, it must also have a DT_FINI_ARRAYSZ entry.
pub const DT_FINI_ARRAYSZ: i64 = 28;
/// This element holds the string table offset of a null-terminated library
/// search path string. The offset is an index into the table recorded in the
/// DT_STRTAB entry.
pub const DT_RUNPATH: i64 = 29;
/// This element holds flag values specific to the object being loaded. Each
/// flag value will have the name DF_flag_name. Defined values and their
/// meanings are described below. All other values are reserved.
pub const DT_FLAGS: i64 = 30;
/// This element holds the address of the array of pointers to
/// pre-initialization functions. The DT_PREINIT_ARRAY table is processed only
/// in an executable file; it is ignored if contained in a shared object.
pub const DT_PREINIT_ARRAY: i64 = 32;
/// This element holds the size in bytes of the array of pre-initialization
/// functions pointed to by the DT_PREINIT_ARRAY entry. If an object has a
/// DT_PREINIT_ARRAY entry, it must also have a DT_PREINIT_ARRAYSZ entry. As
/// with DT_PREINIT_ARRAY, this entry is ignored if it appears in a shared
/// object.
pub const DT_PREINIT_ARRAYSZ: i64 = 33;
/// This element holds the address of the SHT_SYMTAB_SHNDX section associated
/// with the dynamic symbol table referenced by the DT_SYMTAB element.
pub const DT_SYMTAB_SHNDX: i64 = 34;
/// Values in [DT_LOOS, DT_HIOS] are reserved for operating system-specific semantics.
pub const DT_LOOS: i64 = 0x6000000D;
/// Values in [DT_LOOS, DT_HIOS] are reserved for operating system-specific semantics.
pub const DT_HIOS: i64 = 0x6ffff000;
/// Values in [DT_LOPROC, DT_HIPROC] are reserved for processor-specific semantics.
pub const DT_LOPROC: i64 = 0x70000000;
/// Values in [DT_LOPROC, DT_HIPROC] are reserved for processor-specific semantics.
pub const DT_HIPROC: i64 = 0x7fffffff;

/// This flag signifies that the object being loaded may make reference to the
/// $ORIGIN substitution string. The dynamic linker must determine the pathname
/// of the object containing this entry when the object is loaded.
pub const DF_ORIGIN: i64 = 0x1;
/// If this flag is set in a shared object library, the dynamic linker's symbol
/// resolution algorithm for references within the library is changed. Instead
/// of starting a symbol search with the executable file, the dynamic linker
/// starts from the shared object itself. If the shared object fails to supply
/// the referenced symbol, the dynamic linker then searches the executable file
/// and other shared objects as usual.
pub const DF_SYMBOLIC: i64 = 0x2;
/// If this flag is not set, no relocation entry should cause a modification to
/// a non-writable segment, as specified by the segment permissions in the
/// program header table. If this flag is set, one or more relocation entries
/// might request modifications to a non-writable segment, and the dynamic
/// linker can prepare accordingly.
pub const DF_TEXTREL: i64 = 0x4;
/// If set in a shared object or executable, this flag instructs the dynamic
/// linker to process all relocations for the object containing this entry
/// before transferring control to the program. The presence of this entry takes
/// precedence over a directive to use lazy binding for this object when
/// specified through the environment or via dlopen(BA_LIB).
pub const DF_BIND_NOW: i64 = 0x8;
/// If set in a shared object or executable, this flag instructs the dynamic
/// linker to reject attempts to load this file dynamically. It indicates that
/// the shared object or executable contains code using a static thread-local
/// storage scheme. Implementations need not support any form of thread-local
/// storage.
pub const DF_STATIC_TLS: i64 = 0x10;

/// ZLIB/DEFLATE
pub const ELFCOMPRESS_ZLIB: u32 = 1;
/// zstd algorithm
pub const ELFCOMPRESS_ZSTD: u32 = 2;
/// Values in [ELFCOMPRESS_LOOS, ELFCOMPRESS_HIOS] are reserved for operating system-specific semantics.
pub const ELFCOMPRESS_LOOS: u32 = 0x60000000;
/// Values in [ELFCOMPRESS_LOOS, ELFCOMPRESS_HIOS] are reserved for operating system-specific semantics.
pub const ELFCOMPRESS_HIOS: u32 = 0x6fffffff;
/// Values in [ELFCOMPRESS_LOPROC, ELFCOMPRESS_HIPROC] are reserved for processor-specific semantics.
pub const ELFCOMPRESS_LOPROC: u32 = 0x70000000;
/// Values in [ELFCOMPRESS_LOPROC, ELFCOMPRESS_HIPROC] are reserved for processor-specific semantics.
pub const ELFCOMPRESS_HIPROC: u32 = 0x7fffffff;
