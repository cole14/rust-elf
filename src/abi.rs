//! Contains ELF constants defined in the ELF gABI and various extensions
//     See <http://www.sco.com/developers/gabi/latest/ch4.eheader.html#elfid>
// Note: At least in 2022, it seems like the above site is not being updated. Official communication
// occurs on the Generic System V Application Binary Interface mailing list:
//     <https://groups.google.com/g/generic-abi>

// EI_* define indexes into the ELF File Header's e_ident[] byte array.
// We define them as usize in order to use them to easily index into [u8].

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

// ELFCLASS* define constants for e_ident[EI_CLASS]

/// Invalid ELF file class
pub const ELFCLASSNONE: u8 = 0;
/// 32-bit ELF file
pub const ELFCLASS32: u8 = 1;
/// 64-bit ELF file
pub const ELFCLASS64: u8 = 2;

// ELFDATA* define constants for e_ident[EI_DATA]

/// Invalid ELF data format
pub const ELFDATANONE: u8 = 0;
/// 2's complement values, with the least significant byte occupying the lowest address.
pub const ELFDATA2LSB: u8 = 1;
/// 2's complement values, with the most significant byte occupying the lowest address.
pub const ELFDATA2MSB: u8 = 2;

// ELFOSABI* define constants for e_ident[EI_OSABI]

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

// ET_* define constants for the ELF File Header's e_type field.
// Represented as Elf32_Half in Elf32_Ehdr and Elf64_Half in Elf64_Ehdr which
// are both are 2-byte unsigned integers with 2-byte alignment

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

// EM_* define constants for the ELF File Header's e_machine field.
// Represented as Elf32_Half in Elf32_Ehdr and Elf64_Half in Elf64_Ehdr which
// are both 2-byte unsigned integers with 2-byte alignment

/// No machine
pub const EM_NONE: u16 = 0;
/// AT&T WE 32100
pub const EM_M32: u16 = 1;
/// SPARC
pub const EM_SPARC: u16 = 2;
/// Intel 80386
pub const EM_386: u16 = 3;
/// Motorola 68000
pub const EM_68K: u16 = 4;
/// Motorola 88000
pub const EM_88K: u16 = 5;
/// Intel MCU
pub const EM_IAMCU: u16 = 6;
/// Intel 80860
pub const EM_860: u16 = 7;
/// MIPS I Architecture
pub const EM_MIPS: u16 = 8;
/// IBM System/370 Processor
pub const EM_S370: u16 = 9;
/// MIPS RS3000 Little-endian
pub const EM_MIPS_RS3_LE: u16 = 10;
// 11-14 Reserved for future use
/// Hewlett-Packard PA-RISC
pub const EM_PARISC: u16 = 15;
// 16 Reserved for future use
/// Fujitsu VPP500
pub const EM_VPP500: u16 = 17;
/// Enhanced instruction set SPARC
pub const EM_SPARC32PLUS: u16 = 18;
/// Intel 80960
pub const EM_960: u16 = 19;
/// PowerPC
pub const EM_PPC: u16 = 20;
/// 64-bit PowerPC
pub const EM_PPC64: u16 = 21;
/// IBM System/390 Processor
pub const EM_S390: u16 = 22;
/// IBM SPU/SPC
pub const EM_SPU: u16 = 23;
// 24-35 Reserved for future use
/// NEC V800
pub const EM_V800: u16 = 36;
/// Fujitsu FR20
pub const EM_FR20: u16 = 37;
/// TRW RH-32
pub const EM_RH32: u16 = 38;
/// Motorola RCE
pub const EM_RCE: u16 = 39;
/// ARM 32-bit architecture (AARCH32)
pub const EM_ARM: u16 = 40;
/// Digital Alpha
pub const EM_ALPHA: u16 = 41;
/// Hitachi SH
pub const EM_SH: u16 = 42;
/// SPARC Version 9
pub const EM_SPARCV9: u16 = 43;
/// Siemens TriCore embedded processor
pub const EM_TRICORE: u16 = 44;
/// Argonaut RISC Core, Argonaut Technologies Inc.
pub const EM_ARC: u16 = 45;
/// Hitachi H8/300
pub const EM_H8_300: u16 = 46;
/// Hitachi H8/300H
pub const EM_H8_300H: u16 = 47;
/// Hitachi H8S
pub const EM_H8S: u16 = 48;
/// Hitachi H8/500
pub const EM_H8_500: u16 = 49;
/// Intel IA-64 processor architecture
pub const EM_IA_64: u16 = 50;
/// Stanford MIPS-X
pub const EM_MIPS_X: u16 = 51;
/// Motorola ColdFire
pub const EM_COLDFIRE: u16 = 52;
/// Motorola M68HC12
pub const EM_68HC12: u16 = 53;
/// Fujitsu MMA Multimedia Accelerator
pub const EM_MMA: u16 = 54;
/// Siemens PCP
pub const EM_PCP: u16 = 55;
/// Sony nCPU embedded RISC processor
pub const EM_NCPU: u16 = 56;
/// Denso NDR1 microprocessor
pub const EM_NDR1: u16 = 57;
/// Motorola Star*Core processor
pub const EM_STARCORE: u16 = 58;
/// Toyota ME16 processor
pub const EM_ME16: u16 = 59;
/// STMicroelectronics ST100 processor
pub const EM_ST100: u16 = 60;
/// Advanced Logic Corp. TinyJ embedded processor family
pub const EM_TINYJ: u16 = 61;
/// AMD x86-64 architecture
pub const EM_X86_64: u16 = 62;
/// Sony DSP Processor
pub const EM_PDSP: u16 = 63;
/// Digital Equipment Corp. PDP-10
pub const EM_PDP10: u16 = 64;
/// Digital Equipment Corp. PDP-11
pub const EM_PDP11: u16 = 65;
/// Siemens FX66 microcontroller
pub const EM_FX66: u16 = 66;
/// STMicroelectronics ST9+ 8/16 bit microcontroller
pub const EM_ST9PLUS: u16 = 67;
/// STMicroelectronics ST7 8-bit microcontroller
pub const EM_ST7: u16 = 68;
/// Motorola MC68HC16 Microcontroller
pub const EM_68HC16: u16 = 69;
/// Motorola MC68HC11 Microcontroller
pub const EM_68HC11: u16 = 70;
/// Motorola MC68HC08 Microcontroller
pub const EM_68HC08: u16 = 71;
/// Motorola MC68HC05 Microcontroller
pub const EM_68HC05: u16 = 72;
/// Silicon Graphics SVx
pub const EM_SVX: u16 = 73;
/// STMicroelectronics ST19 8-bit microcontroller
pub const EM_ST19: u16 = 74;
/// Digital VAX
pub const EM_VAX: u16 = 75;
/// Axis Communications 32-bit embedded processor
pub const EM_CRIS: u16 = 76;
/// Infineon Technologies 32-bit embedded processor
pub const EM_JAVELIN: u16 = 77;
/// Element 14 64-bit DSP Processor
pub const EM_FIREPATH: u16 = 78;
/// LSI Logic 16-bit DSP Processor
pub const EM_ZSP: u16 = 79;
/// Donald Knuth's educational 64-bit processor
pub const EM_MMIX: u16 = 80;
/// Harvard University machine-independent object files
pub const EM_HUANY: u16 = 81;
/// SiTera Prism
pub const EM_PRISM: u16 = 82;
/// Atmel AVR 8-bit microcontroller
pub const EM_AVR: u16 = 83;
/// Fujitsu FR30
pub const EM_FR30: u16 = 84;
/// Mitsubishi D10V
pub const EM_D10V: u16 = 85;
/// Mitsubishi D30V
pub const EM_D30V: u16 = 86;
/// NEC v850
pub const EM_V850: u16 = 87;
/// Mitsubishi M32R
pub const EM_M32R: u16 = 88;
/// Matsushita MN10300
pub const EM_MN10300: u16 = 89;
/// Matsushita MN10200
pub const EM_MN10200: u16 = 90;
/// picoJava
pub const EM_PJ: u16 = 91;
/// OpenRISC 32-bit embedded processor
pub const EM_OPENRISC: u16 = 92;
/// ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
pub const EM_ARC_COMPACT: u16 = 93;
/// Tensilica Xtensa Architecture
pub const EM_XTENSA: u16 = 94;
/// Alphamosaic VideoCore processor
pub const EM_VIDEOCORE: u16 = 95;
/// Thompson Multimedia General Purpose Processor
pub const EM_TMM_GPP: u16 = 96;
/// National Semiconductor 32000 series
pub const EM_NS32K: u16 = 97;
/// Tenor Network TPC processor
pub const EM_TPC: u16 = 98;
/// Trebia SNP 1000 processor
pub const EM_SNP1K: u16 = 99;
/// STMicroelectronics (www.st.com) ST200 microcontroller
pub const EM_ST200: u16 = 100;
/// Ubicom IP2xxx microcontroller family
pub const EM_IP2K: u16 = 101;
/// MAX Processor
pub const EM_MAX: u16 = 102;
/// National Semiconductor CompactRISC microprocessor
pub const EM_CR: u16 = 103;
/// Fujitsu F2MC16
pub const EM_F2MC16: u16 = 104;
/// Texas Instruments embedded microcontroller msp430
pub const EM_MSP430: u16 = 105;
/// Analog Devices Blackfin (DSP) processor
pub const EM_BLACKFIN: u16 = 106;
/// S1C33 Family of Seiko Epson processors
pub const EM_SE_C33: u16 = 107;
/// Sharp embedded microprocessor
pub const EM_SEP: u16 = 108;
/// Arca RISC Microprocessor
pub const EM_ARCA: u16 = 109;
/// Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
pub const EM_UNICORE: u16 = 110;
/// eXcess: 16/32/64-bit configurable embedded CPU
pub const EM_EXCESS: u16 = 111;
/// Icera Semiconductor Inc. Deep Execution Processor
pub const EM_DXP: u16 = 112;
/// Altera Nios II soft-core processor
pub const EM_ALTERA_NIOS2: u16 = 113;
/// National Semiconductor CompactRISC CRX microprocessor
pub const EM_CRX: u16 = 114;
/// Motorola XGATE embedded processor
pub const EM_XGATE: u16 = 115;
/// Infineon C16x/XC16x processor
pub const EM_C166: u16 = 116;
/// Renesas M16C series microprocessors
pub const EM_M16C: u16 = 117;
/// Microchip Technology dsPIC30F Digital Signal Controller
pub const EM_DSPIC30F: u16 = 118;
/// Freescale Communication Engine RISC core
pub const EM_CE: u16 = 119;
/// Renesas M32C series microprocessors
pub const EM_M32C: u16 = 120;
// 121-130 Reserved for future use
/// Altium TSK3000 core
pub const EM_TSK3000: u16 = 131;
/// Freescale RS08 embedded processor
pub const EM_RS08: u16 = 132;
/// Analog Devices SHARC family of 32-bit DSP processors
pub const EM_SHARC: u16 = 133;
/// Cyan Technology eCOG2 microprocessor
pub const EM_ECOG2: u16 = 134;
/// Sunplus S+core7 RISC processor
pub const EM_SCORE7: u16 = 135;
/// New Japan Radio (NJR) 24-bit DSP Processor
pub const EM_DSP24: u16 = 136;
/// Broadcom VideoCore III processor
pub const EM_VIDEOCORE3: u16 = 137;
/// RISC processor for Lattice FPGA architecture
pub const EM_LATTICEMICO32: u16 = 138;
/// Seiko Epson C17 family
pub const EM_SE_C17: u16 = 139;
/// The Texas Instruments TMS320C6000 DSP family
pub const EM_TI_C6000: u16 = 140;
/// The Texas Instruments TMS320C2000 DSP family
pub const EM_TI_C2000: u16 = 141;
/// The Texas Instruments TMS320C55x DSP family
pub const EM_TI_C5500: u16 = 142;
/// Texas Instruments Application Specific RISC Processor, 32bit fetch
pub const EM_TI_ARP32: u16 = 143;
/// Texas Instruments Programmable Realtime Unit
pub const EM_TI_PRU: u16 = 144;
// 145-159 Reserved for future use
/// STMicroelectronics 64bit VLIW Data Signal Processor
pub const EM_MMDSP_PLUS: u16 = 160;
/// Cypress M8C microprocessor
pub const EM_CYPRESS_M8C: u16 = 161;
/// Renesas R32C series microprocessors
pub const EM_R32C: u16 = 162;
/// NXP Semiconductors TriMedia architecture family
pub const EM_TRIMEDIA: u16 = 163;
/// QUALCOMM DSP6 Processor
pub const EM_QDSP6: u16 = 164;
/// Intel 8051 and variants
pub const EM_8051: u16 = 165;
/// STMicroelectronics STxP7x family of configurable and extensible RISC processors
pub const EM_STXP7X: u16 = 166;
/// Andes Technology compact code size embedded RISC processor family
pub const EM_NDS32: u16 = 167;
/// Cyan Technology eCOG1X family
pub const EM_ECOG1: u16 = 168;
/// Cyan Technology eCOG1X family
pub const EM_ECOG1X: u16 = 168;
/// Dallas Semiconductor MAXQ30 Core Micro-controllers
pub const EM_MAXQ30: u16 = 169;
/// New Japan Radio (NJR) 16-bit DSP Processor
pub const EM_XIMO16: u16 = 170;
/// M2000 Reconfigurable RISC Microprocessor
pub const EM_MANIK: u16 = 171;
/// Cray Inc. NV2 vector architecture
pub const EM_CRAYNV2: u16 = 172;
/// Renesas RX family
pub const EM_RX: u16 = 173;
/// Imagination Technologies META processor architecture
pub const EM_METAG: u16 = 174;
/// MCST Elbrus general purpose hardware architecture
pub const EM_MCST_ELBRUS: u16 = 175;
/// Cyan Technology eCOG16 family
pub const EM_ECOG16: u16 = 176;
/// National Semiconductor CompactRISC CR16 16-bit microprocessor
pub const EM_CR16: u16 = 177;
/// Freescale Extended Time Processing Unit
pub const EM_ETPU: u16 = 178;
/// Infineon Technologies SLE9X core
pub const EM_SLE9X: u16 = 179;
/// Intel L10M
pub const EM_L10M: u16 = 180;
/// Intel K10M
pub const EM_K10M: u16 = 181;
// 182 Reserved for future Intel use
/// ARM 64-bit architecture (AARCH64)
pub const EM_AARCH64: u16 = 183;
// 184 Reserved for future ARM use
/// Atmel Corporation 32-bit microprocessor family
pub const EM_AVR32: u16 = 185;
/// STMicroeletronics STM8 8-bit microcontroller
pub const EM_STM8: u16 = 186;
/// Tilera TILE64 multicore architecture family
pub const EM_TILE64: u16 = 187;
/// Tilera TILEPro multicore architecture family
pub const EM_TILEPRO: u16 = 188;
/// Xilinx MicroBlaze 32-bit RISC soft processor core
pub const EM_MICROBLAZE: u16 = 189;
/// NVIDIA CUDA architecture
pub const EM_CUDA: u16 = 190;
/// Tilera TILE-Gx multicore architecture family
pub const EM_TILEGX: u16 = 191;
/// CloudShield architecture family
pub const EM_CLOUDSHIELD: u16 = 192;
/// KIPO-KAIST Core-A 1st generation processor family
pub const EM_COREA_1ST: u16 = 193;
/// KIPO-KAIST Core-A 2nd generation processor family
pub const EM_COREA_2ND: u16 = 194;
/// Synopsys ARCompact V2
pub const EM_ARC_COMPACT2: u16 = 195;
/// Open8 8-bit RISC soft processor core
pub const EM_OPEN8: u16 = 196;
/// Renesas RL78 family
pub const EM_RL78: u16 = 197;
/// Broadcom VideoCore V processor
pub const EM_VIDEOCORE5: u16 = 198;
/// Renesas 78KOR family
pub const EM_78KOR: u16 = 199;
/// Freescale 56800EX Digital Signal Controller (DSC)
pub const EM_56800EX: u16 = 200;
/// Beyond BA1 CPU architecture
pub const EM_BA1: u16 = 201;
/// Beyond BA2 CPU architecture
pub const EM_BA2: u16 = 202;
/// XMOS xCORE processor family
pub const EM_XCORE: u16 = 203;
/// Microchip 8-bit PIC(r) family
pub const EM_MCHP_PIC: u16 = 204;
/// Reserved by Intel
pub const EM_INTEL205: u16 = 205;
/// Reserved by Intel
pub const EM_INTEL206: u16 = 206;
/// Reserved by Intel
pub const EM_INTEL207: u16 = 207;
/// Reserved by Intel
pub const EM_INTEL208: u16 = 208;
/// Reserved by Intel
pub const EM_INTEL209: u16 = 209;
/// KM211 KM32 32-bit processor
pub const EM_KM32: u16 = 210;
/// KM211 KMX32 32-bit processor
pub const EM_KMX32: u16 = 211;
/// KM211 KMX16 16-bit processor
pub const EM_KMX16: u16 = 212;
/// KM211 KMX8 8-bit processor
pub const EM_KMX8: u16 = 213;
/// KM211 KVARC processor
pub const EM_KVARC: u16 = 214;
/// Paneve CDP architecture family
pub const EM_CDP: u16 = 215;
/// Cognitive Smart Memory Processor
pub const EM_COGE: u16 = 216;
/// Bluechip Systems CoolEngine
pub const EM_COOL: u16 = 217;
/// Nanoradio Optimized RISC
pub const EM_NORC: u16 = 218;
/// CSR Kalimba architecture family
pub const EM_CSR_KALIMBA: u16 = 219;
/// Zilog Z80
pub const EM_Z80: u16 = 220;
/// Controls and Data Services VISIUMcore processor
pub const EM_VISIUM: u16 = 221;
/// FTDI Chip FT32 high performance 32-bit RISC architecture
pub const EM_FT32: u16 = 222;
/// Moxie processor family
pub const EM_MOXIE: u16 = 223;
/// AMD GPU architecture
pub const EM_AMDGPU: u16 = 224;
/// RISC-V
pub const EM_RISCV: u16 = 243;
/// Linux BPF
pub const EM_BPF: u16 = 247;

// EV_* define constants for the ELF File Header's e_version field.
// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
// are both 4-byte unsigned integers with 4-byte alignment

/// Invalid version
pub const EV_NONE: u8 = 0;
/// Current version
pub const EV_CURRENT: u8 = 1;

/// If the number of program headers is greater than or equal to PN_XNUM (0xffff),
/// this member has the value PN_XNUM (0xffff). The actual number of
/// program header table entries is contained in the sh_info field of the
/// section header at index 0. Otherwise, the sh_info member of the initial
/// section header entry contains the value zero.
pub const PN_XNUM: u16 = 0xffff;

// PF_* define constants for the ELF Program Header's p_flags field.
// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
// are both 4-byte unsigned integers with 4-byte alignment

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

// PT_* define constants for the ELF Program Header's p_type field.
// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
// are both 4-byte unsigned integers with 4-byte alignment

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
/// The segment contains .note.gnu.property section
pub const PT_GNU_PROPERTY: u32 = 0x6474e553;
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

// SHT_* define constants for the ELF Section Header's p_type field.
// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Word in Elf64_Ehdr which
// are both 4-byte unsigned integers with 4-byte alignment

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
/// Values in [SHT_LOOS, SHT_HIOS] are reserved for operating system-specific semantics.
pub const SHT_LOOS: u32 = 0x60000000;
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
/// Values in [SHT_LOOS, SHT_HIOS] are reserved for operating system-specific semantics.
pub const SHT_HIOS: u32 = 0x6fffffff;
/// Values in [SHT_LOPROC, SHT_HIPROC] are reserved for processor-specific semantics.
pub const SHT_LOPROC: u32 = 0x70000000;
/// IA_64 extension bits
pub const SHT_IA_64_EXT: u32 = 0x70000000; // SHT_LOPROC + 0;
/// IA_64 unwind section
pub const SHT_IA_64_UNWIND: u32 = 0x70000001; // SHT_LOPROC + 1;
/// Values in [SHT_LOPROC, SHT_HIPROC] are reserved for processor-specific semantics.
pub const SHT_HIPROC: u32 = 0x7fffffff;
/// Values in [SHT_LOUSER, SHT_HIUSER] are reserved for application-specific semantics.
pub const SHT_LOUSER: u32 = 0x80000000;
/// Values in [SHT_LOUSER, SHT_HIUSER] are reserved for application-specific semantics.
pub const SHT_HIUSER: u32 = 0x8fffffff;

/// This value marks an undefined, missing, irrelevant, or otherwise meaningless
/// section reference.
pub const SHN_UNDEF: u16 = 0;
/// Symbols with st_shndx=SHN_ABS are absolute and are not affected by relocation.
pub const SHN_ABS: u16 = 0xfff1;
/// Symbols with st_shndx=SHN_COMMON are sometimes used for unallocated C external variables.
pub const SHN_COMMON: u16 = 0xfff2;
pub const SHN_XINDEX: u16 = 0xffff;

// SHF_* define constants for the ELF Section Header's sh_flags field.
// Represented as Elf32_Word in Elf32_Ehdr and Elf64_Xword in Elf64_Ehdr which
// are both 4-byte and 8-byte unsigned integers, respectively.
// All of the constants are < 32-bits, so we use a u32 to represent these in order
// to make working with them easier.

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

// STT_* define constants for the ELF Symbol's st_type (encoded in the st_info field).

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

// STB_* define constants for the ELF Symbol's st_bind (encoded in the st_info field).

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
/// Guile offset of GC roots
pub const DT_GUILE_GC_ROOT: i64 = 0x37146000;
/// Guile size in machine words of GC roots
pub const DT_GUILE_GC_ROOT_SZ: i64 = 0x37146001;
/// Guile address of entry thunk
pub const DT_GUILE_ENTRY: i64 = 0x37146002;
/// Guile bytecode version
pub const DT_GUILE_VM_VERSION: i64 = 0x37146003;
/// Guile frame maps
pub const DT_GUILE_FRAME_MAPS: i64 = 0x37146004;
/// Values in [DT_LOOS, DT_HIOS] are reserved for operating system-specific semantics.
pub const DT_LOOS: i64 = 0x6000000D;
/// Prelinking timestamp
pub const DT_GNU_PRELINKED: i64 = 0x6ffffdf5;
/// Size of conflict section
pub const DT_GNU_CONFLICTSZ: i64 = 0x6ffffdf6;
/// Size of library list
pub const DT_GNU_LIBLISTSZ: i64 = 0x6ffffdf7;
pub const DT_CHECKSUM: i64 = 0x6ffffdf8;
pub const DT_PLTPADSZ: i64 = 0x6ffffdf9;
pub const DT_MOVEENT: i64 = 0x6ffffdfa;
pub const DT_MOVESZ: i64 = 0x6ffffdfb;
/// Feature selection (DTF_*)
pub const DT_FEATURE_1: i64 = 0x6ffffdfc;
/// Flags for DT_* entries, effecting the following DT_* entry
pub const DT_POSFLAG_1: i64 = 0x6ffffdfd;
/// Size of syminfo table (in bytes)
pub const DT_SYMINSZ: i64 = 0x6ffffdfe;
/// Entry size of syminfo table
pub const DT_SYMINENT: i64 = 0x6ffffdff;
/// GNU-style hash table
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_TLSDESC_PLT: i64 = 0x6ffffef6;
pub const DT_TLSDESC_GOT: i64 = 0x6ffffef7;
/// Start of conflict section
pub const DT_GNU_CONFLICT: i64 = 0x6ffffef8;
/// Library list
pub const DT_GNU_LIBLIST: i64 = 0x6ffffef9;
/// Configuration information
pub const DT_CONFIG: i64 = 0x6ffffefa;
/// Dependency auditing
pub const DT_DEPAUDIT: i64 = 0x6ffffefb;
/// Object auditing
pub const DT_AUDIT: i64 = 0x6ffffefc;
/// PLT padding
pub const DT_PLTPAD: i64 = 0x6ffffefd;
/// Move table
pub const DT_MOVETAB: i64 = 0x6ffffefe;
/// Syminfo table
pub const DT_SYMINFO: i64 = 0x6ffffeff;
pub const DT_VERSYM: i64 = 0x6ffffff0;
pub const DT_RELACOUNT: i64 = 0x6ffffff9;
pub const DT_RELCOUNT: i64 = 0x6ffffffa;
/// State flags, see DF_1_* below.
pub const DT_FLAGS_1: i64 = 0x6ffffffb;
/// Address of version definition table
pub const DT_VERDEF: i64 = 0x6ffffffc;
/// Number of version definitions
pub const DT_VERDEFNUM: i64 = 0x6ffffffd;
/// Address of table with needed versions
pub const DT_VERNEED: i64 = 0x6ffffffe;
/// Number of needed versions
pub const DT_VERNEEDNUM: i64 = 0x6fffffff;
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

// State flags selectable in Dyn.d_val() of the DT_FLAGS_1 entries in the dynamic section

/// Set RTLD_NOW for this object
pub const DF_1_NOW: i64 = 0x00000001;
/// Set RTLD_GLOBAL for this object
pub const DF_1_GLOBAL: i64 = 0x00000002;
/// Set RTLD_GROUP for this object
pub const DF_1_GROUP: i64 = 0x00000004;
/// Set RTLD_NODELETE for this object
pub const DF_1_NODELETE: i64 = 0x00000008;
/// Trigger filtee loading at runtime
pub const DF_1_LOADFLTR: i64 = 0x00000010;
/// Set RTLD_INITFIRST for this object
pub const DF_1_INITFIRST: i64 = 0x00000020;
/// Set RTLD_NOOPEN for this object
pub const DF_1_NOOPEN: i64 = 0x00000040;
/// $ORIGIN must be handled
pub const DF_1_ORIGIN: i64 = 0x00000080;
/// Direct binding enabled
pub const DF_1_DIRECT: i64 = 0x00000100;
pub const DF_1_TRANS: i64 = 0x00000200;
/// Object is used to interpose
pub const DF_1_INTERPOSE: i64 = 0x00000400;
/// Ignore default lib search path
pub const DF_1_NODEFLIB: i64 = 0x00000800;
/// Object can't be dldump'ed
pub const DF_1_NODUMP: i64 = 0x00001000;
/// Configuration alternative created
pub const DF_1_CONFALT: i64 = 0x00002000;
/// Filtee terminates filters search
pub const DF_1_ENDFILTEE: i64 = 0x00004000;
/// Disp reloc applied at build time
pub const DF_1_DISPRELDNE: i64 = 0x00008000;
/// Disp reloc applied at run-time
pub const DF_1_DISPRELPND: i64 = 0x00010000;
/// Object has no-direct binding
pub const DF_1_NODIRECT: i64 = 0x00020000;
pub const DF_1_IGNMULDEF: i64 = 0x00040000;
pub const DF_1_NOKSYMS: i64 = 0x00080000;
pub const DF_1_NOHDR: i64 = 0x00100000;
/// Object is modified after built
pub const DF_1_EDITED: i64 = 0x00200000;
pub const DF_1_NORELOC: i64 = 0x00400000;
/// Object has individual interposers
pub const DF_1_SYMINTPOSE: i64 = 0x00800000;
/// Global auditing required
pub const DF_1_GLOBAUDIT: i64 = 0x01000000;
/// Singleton symbols are used
pub const DF_1_SINGLETON: i64 = 0x02000000;
pub const DF_1_STUB: i64 = 0x04000000;
pub const DF_1_PIE: i64 = 0x08000000;
pub const DF_1_KMOD: i64 = 0x10000000;
pub const DF_1_WEAKFILTER: i64 = 0x20000000;
pub const DF_1_NOCOMMON: i64 = 0x40000000;

// Flags for the feature selection in DT_FEATURE_1
pub const DTF_1_PARINIT: i64 = 0x00000001;
pub const DTF_1_CONFEXP: i64 = 0x00000002;

// Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry
/// Lazyload following object
pub const DF_P1_LAZYLOAD: i64 = 0x00000001;
/// Symbols from next object are not generally available
pub const DF_P1_GROUPPERM: i64 = 0x00000002;

// .gnu.version index reserved values
/// Symbol is local
pub const VER_NDX_LOCAL: u16 = 0;
/// Symbol is global
pub const VER_NDX_GLOBAL: u16 = 1;
/// .gnu.version index mask
pub const VER_NDX_VERSION: u16 = 0x7fff;
/// Symbol is hidden
pub const VER_NDX_HIDDEN: u16 = 0x8000;

// .gnu.version_d VerDef.vd_version reserved values
/// Only defined valid vd_version value
pub const VER_DEF_CURRENT: u16 = 1;

// .gnu.version_r VerNeed.vn_version reserved values
/// Only defined valid vn_version value
pub const VER_NEED_CURRENT: u16 = 1;

// Bit flags which appear in vd_flags of VerDef and vna_flags of VerNeedAux.
pub const VER_FLG_BASE: u16 = 0x1;
pub const VER_FLG_WEAK: u16 = 0x2;
pub const VER_FLG_INFO: u16 = 0x4;

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

/// GNU-extension notes have this name
pub const ELF_NOTE_GNU: &str = "GNU";

// Note header descriptor types constants (n_type)

/// Contains copy of prstatus struct
pub const NT_PRSTATUS: u64 = 1;
/// Contains copy of fpregset struct
pub const NT_PRFPREG: u64 = 2;
/// Contains copy of fpregset struct
pub const NT_FPREGSET: u64 = 2;
/// Contains copy of prpsinfo struct
pub const NT_PRPSINFO: u64 = 3;
/// Contains copy of prxregset struct
pub const NT_PRXREG: u64 = 4;
/// Contains copy of task structure
pub const NT_TASKSTRUCT: u64 = 4;
/// String from sysinfo(SI_PLATFORM)
pub const NT_PLATFORM: u64 = 5;
/// Contains copy of auxv array
pub const NT_AUXV: u64 = 6;
/// Contains copy of gwindows struct
pub const NT_GWINDOWS: u64 = 7;
/// Contains copy of asrset struct
pub const NT_ASRS: u64 = 8;
/// Contains copy of pstatus struct
pub const NT_PSTATUS: u64 = 10;
/// Contains copy of psinfo struct
pub const NT_PSINFO: u64 = 13;
/// Contains copy of prcred struct
pub const NT_PRCRED: u64 = 14;
/// Contains copy of utsname struct
pub const NT_UTSNAME: u64 = 15;
/// Contains copy of lwpstatus struct
pub const NT_LWPSTATUS: u64 = 16;
/// Contains copy of lwpinfo struct
pub const NT_LWPSINFO: u64 = 17;
/// Contains copy of fprxregset struct
pub const NT_PRFPXREG: u64 = 20;
/// Contains copy of siginfo_t, size might increase
pub const NT_SIGINFO: u64 = 0x53494749;
/// Contains information about mapped files
pub const NT_FILE: u64 = 0x46494c45;
/// Contains copy of user_fxsr_struct
pub const NT_PRXFPREG: u64 = 0x46e62b7f;
/// /// PowerPC Altivec/VMX registers
pub const NT_PPC_VMX: u64 = 0x100;
/// PowerPC SPE/EVR registers
pub const NT_PPC_SPE: u64 = 0x101;
/// PowerPC VSX registers
pub const NT_PPC_VSX: u64 = 0x102;
/// Target Address Register
pub const NT_PPC_TAR: u64 = 0x103;
/// Program Priority Register
pub const NT_PPC_PPR: u64 = 0x104;
/// Data Stream Control Register
pub const NT_PPC_DSCR: u64 = 0x105;
/// Event Based Branch Registers
pub const NT_PPC_EBB: u64 = 0x106;
/// Performance Monitor Registers
pub const NT_PPC_PMU: u64 = 0x107;
/// TM checkpointed GPR Registers
pub const NT_PPC_TM_CGPR: u64 = 0x108;
/// TM checkpointed FPR Registers
pub const NT_PPC_TM_CFPR: u64 = 0x109;
/// TM checkpointed VMX Registers
pub const NT_PPC_TM_CVMX: u64 = 0x10a;
/// TM checkpointed VSX Registers
pub const NT_PPC_TM_CVSX: u64 = 0x10b;
/// TM Special Purpose Registers
pub const NT_PPC_TM_SPR: u64 = 0x10c;
/// TM checkpointed Target Address Register
pub const NT_PPC_TM_CTAR: u64 = 0x10d;
/// TM checkpointed Program Priority Register
pub const NT_PPC_TM_CPPR: u64 = 0x10e;
/// TM checkpointed Data Stream Control Register
pub const NT_PPC_TM_CDSCR: u64 = 0x10f;
/// Memory Protection Keys registers
pub const NT_PPC_PKEY: u64 = 0x110;
/// i386 TLS slots (struct user_desc)
pub const NT_386_TLS: u64 = 0x200;
/// x86 io permission bitmap (1=deny)
pub const NT_386_IOPERM: u64 = 0x201;
/// x86 extended state using xsave
pub const NT_X86_XSTATE: u64 = 0x202;
/// ARM VFP/NEON registers
pub const NT_ARM_VFP: u64 = 0x400;
/// ARM TLS register
pub const NT_ARM_TLS: u64 = 0x401;
/// ARM hardware breakpoint registers
pub const NT_ARM_HW_BREAK: u64 = 0x402;
/// ARM hardware watchpoint registers
pub const NT_ARM_HW_WATCH: u64 = 0x403;
/// ARM system call number
pub const NT_ARM_SYSTEM_CALL: u64 = 0x404;
/// ARM Scalable Vector Extension registers
pub const NT_ARM_SVE: u64 = 0x405;
/// ARM pointer authentication code masks
pub const NT_ARM_PAC_MASK: u64 = 0x406;
/// ARM pointer authentication address keys
pub const NT_ARM_PACA_KEYS: u64 = 0x407;
/// ARM pointer authentication generic key
pub const NT_ARM_PACG_KEYS: u64 = 0x408;
/// AArch64 tagged address control.
pub const NT_ARM_TAGGED_ADDR_CTRL: u64 = 0x409;
/// AArch64 pointer authentication enabled keys
pub const NT_ARM_PAC_ENABLED_KEYS: u64 = 0x40a;
/// Vmcore Device Dump Note
pub const NT_VMCOREDD: u64 = 0x700;

/// ABI information
/// The descriptor consists of words:
///     word 0: OS descriptor
///     word 1: major version of the ABI
///     word 2: minor version of the ABI
///     word 3: subminor version of the ABI
pub const NT_GNU_ABI_TAG: u64 = 1;
/// Synthetic hwcap information
pub const NT_GNU_HWCAP: u64 = 2;
/// Build ID bits as generated by ld --build-id.
pub const NT_GNU_BUILD_ID: u64 = 3;
/// Version note generated by GNU gold containing a version string
pub const NT_GNU_GOLD_VERSION: u64 = 4;
/// Program property note which describes special handling requirements for linker and run-time loader.
pub const NT_GNU_PROPERTY_TYPE_0: u64 = 5;

// These values can appear in word 0 of an NT_GNU_ABI_TAG note section entry.
pub const ELF_NOTE_GNU_ABI_TAG_OS_LINUX: u32 = 0;
pub const ELF_NOTE_GNU_ABI_TAG_OS_GNU: u32 = 1;
pub const ELF_NOTE_GNU_ABI_TAG_OS_SOLARIS2: u32 = 2;
pub const ELF_NOTE_GNU_ABI_TAG_OS_FREEBSD: u32 = 3;

//     _    ____  __  __
//    / \  |  _ \|  \/  |
//   / _ \ | |_) | |\/| |
//  / ___ \|  _ <| |  | |
// /_/   \_\_| \_\_|  |_|
//
// ARM-specific declarations (ABI v5)
// See: https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst
// See: https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst

/// Set in executable file headers (e_type = ET_EXEC or ET_DYN) to note explicitly that the
/// executable file was built to conform to the software floating-point procedure-call standard
/// (the base standard). If both EF_ARM_ABI_FLOAT_XXXX bits are clear, conformance to the base
/// procedure-call standard is implied.
pub const EF_ARM_ABI_FLOAT_SOFT: u32 = 0x200;
/// Compatible with legacy (pre version 5) gcc use as EF_ARM_SOFT_FLOAT
pub const EF_ARM_SOFT_FLOAT: u32 = EF_ARM_ABI_FLOAT_SOFT;
/// Set in executable file headers (e_type = ET_EXEC or ET_DYN) to note that the executable file
/// was built to conform to the hardware floating-point procedure-call standard.
pub const EF_ARM_ABI_FLOAT_HARD: u32 = 0x400;
/// Compatible with legacy (pre version 5) gcc use as EF_ARM_VFP_FLOAT.
pub const EF_ARM_VFP_FLOAT: u32 = EF_ARM_ABI_FLOAT_HARD;

/// The ELF file contains BE-8 code, suitable for execution on an Arm Architecture v6 processor.
/// This flag must only be set on an executable file.
pub const EF_ARM_BE8: u32 = 0x00800000;

/// Legacy code (ABI version 4 and earlier) generated by gcc-arm-xxx might use these bits.
pub const EF_ARM_GCCMASK: u32 = 0x00400FFF;

/// This masks an 8-bit version number, the version of the ABI to which this ELF
/// file conforms. This ABI is version 5. A value of 0 denotes unknown conformance.
pub const EF_ARM_EABIMASK: u32 = 0xFF000000;
pub const EF_ARM_EABI_UNKNOWN: u32 = 0x00000000;
pub const EF_ARM_EABI_VER1: u32 = 0x01000000;
pub const EF_ARM_EABI_VER2: u32 = 0x02000000;
pub const EF_ARM_EABI_VER3: u32 = 0x03000000;
pub const EF_ARM_EABI_VER4: u32 = 0x04000000;
pub const EF_ARM_EABI_VER5: u32 = 0x05000000;

/// Section contains index information for exception unwinding
pub const SHT_ARM_EXIDX: u32 = 0x70000001;
/// BPABI DLL dynamic linking pre-emption map
pub const SHT_ARM_PREEMPTMAP: u32 = 0x70000002;
/// Object file compatibility attributes
pub const SHT_ARM_ATTRIBUTES: u32 = 0x70000003;
/// See <https://github.com/ARM-software/abi-aa/blob/main/dbgovl32/dbgovl32.rst>
pub const SHT_ARM_DEBUGOVERLAY: u32 = 0x70000004;
/// See <https://github.com/ARM-software/abi-aa/blob/main/dbgovl32/dbgovl32.rst>
pub const SHT_ARM_OVERLAYSECTION: u32 = 0x70000005;

/// The contents of this section contains only program instructions and no program data.
///
/// If any section contained by a segment does not have the SHF_ARM_PURECODE
/// section flag set, the PF_R segment flag must be set in the program header
/// for the segment. If all sections contained by a segment have the
/// SHF_ARM_PURECODE section flag, a linker may optionally clear the PF_R
/// segment flag in the program header of the segment, to signal to the runtime
/// that the program does not rely on being able to read that segment.
pub const SHF_ARM_PURECODE: u64 = 0x20000000;

/// Architecture compatibility information.
///
/// A segment of type PT_ARM_ARCHEXT contains information describing the
/// platform capabilities required by the executable file. The segment is
/// optional, but if present it must appear before segment of type PT_LOAD.
pub const PT_ARM_ARCHEXT: u32 = 0x70000000;
/// alias for unwind
pub const PT_ARM_EXIDX: u32 = 0x70000001;
/// Exception unwind tables
pub const PT_ARM_UNWIND: u32 = 0x70000001;

// Contents of a PT_ARM_ARCHEXT segment shall contain at least one 32-bit word with meanings:
/// Masks bits describing the format of data in subsequent words.
pub const PT_ARM_ARCHEXT_FMTMSK: u32 = 0xff000000;
/// There are no additional words of data. However, if EF_OSABI is non-zero, the
/// relevant platform ABI may define additional data that follows the initial word.
pub const PT_ARM_ARCHEXT_FMT_OS: u32 = 0x00000000;
/// See <https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#platform-architecture-compatibility-data>
/// and <https://github.com/ARM-software/abi-aa/blob/main/addenda32/addenda32.rst>
pub const PT_ARM_ARCHEXT_FMT_ABI: u32 = 0x01000000;

/// Masks bits describing the architecture profile required by the executable.
pub const PT_ARM_ARCHEXT_PROFMSK: u32 = 0x00ff0000;
/// The architecture has no profile variants, or the image has no profile-specific constraints
pub const PT_ARM_ARCHEXT_PROF_NONE: u32 = 0x00000000;
/// (‘A’<<16) The executable file requires the Application profile
pub const PT_ARM_ARCHEXT_PROF_ARM: u32 = 0x00410000;
/// (‘R’<<16) The executable file requires the Real-Time profile
pub const PT_ARM_ARCHEXT_PROF_RT: u32 = 0x00520000;
/// (‘M’<<16) The executable file requires the Microcontroller profile
pub const PT_ARM_ARCHEXT_PROF_MC: u32 = 0x004D0000;
/// (‘S’<<16) The executable file requires the ‘classic’ (‘A’ or ‘R’ profile) exception model.
pub const PT_ARM_ARCHEXT_PROF_CLASSIC: u32 = 0x00530000;

/// Masks bits describing the base architecture required by the executable.
pub const PT_ARM_ARCHEXT_ARCHMSK: u32 = 0x000000ff;
/// The needed architecture is unknown or specified in some other way
pub const PT_ARM_ARCHEXT_ARCH_UNKN: u32 = 0x00;
/// Architecture v4
pub const PT_ARM_ARCHEXT_ARCHV4: u32 = 0x01;
/// Architecture v4T
pub const PT_ARM_ARCHEXT_ARCHV4T: u32 = 0x02;
/// Architecture v5T
pub const PT_ARM_ARCHEXT_ARCHV5T: u32 = 0x03;
/// Architecture v5TE
pub const PT_ARM_ARCHEXT_ARCHV5TE: u32 = 0x04;
/// Architecture v5TEJ
pub const PT_ARM_ARCHEXT_ARCHV5TEJ: u32 = 0x05;
/// Architecture v6
pub const PT_ARM_ARCHEXT_ARCHV6: u32 = 0x06;
/// Architecture v6KZ
pub const PT_ARM_ARCHEXT_ARCHV6KZ: u32 = 0x07;
/// Architecture v6T2
pub const PT_ARM_ARCHEXT_ARCHV6T2: u32 = 0x08;
/// Architecture v6K
pub const PT_ARM_ARCHEXT_ARCHV6K: u32 = 0x09;
/// Architecture v7 (in this case the architecture profile may also be
/// required to fully specify the needed execution environment).
pub const PT_ARM_ARCHEXT_ARCHV7: u32 = 0x0A;
/// Architecture v6M (e.g. Cortex-M0)
pub const PT_ARM_ARCHEXT_ARCHV6M: u32 = 0x0B;
/// Architecture v6S-M (e.g. Cortex-M0)
pub const PT_ARM_ARCHEXT_ARCHV6SM: u32 = 0x0C;
/// Architecture v7E-M
pub const PT_ARM_ARCHEXT_ARCHV7EM: u32 = 0x0D;

/// gives the number of entries in the dynamic symbol table, including the initial dummy symbol
pub const DT_ARM_SYMTABSZ: i64 = 0x70000001;
/// holds the address of the pre-emption map for platforms that use the DLL static binding mode
pub const DT_ARM_PREEMPTMAP: i64 = 0x70000002;

// ARM relocs
//
// * S (when used on its own) is the address of the symbol.
// * A is the addend for the relocation.
// * P is the address of the place being relocated (derived from r_offset).
// * Pa is the adjusted address of the place being relocated, defined as (P & 0xFFFFFFFC).
// * T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; 0 otherwise.
// * B(S) is the addressing origin of the output segment defining the symbol S.
//     The origin is not required to be the base address of the segment. This value must always be word-aligned.
// * GOT_ORG is the addressing origin of the Global Offset Table (the indirection table for imported data addresses).
//     This value must always be word-aligned.
// * GOT(S) is the address of the GOT entry for the symbol S

/// no reloc
pub const R_ARM_NONE: u32 = 0;
/// Deprecated PC relative 26 bit branch. `((S + A) | T) – P`
pub const R_ARM_PC24: u32 = 1;
/// Direct 32 bit. `(S + A) | T`
pub const R_ARM_ABS32: u32 = 2;
/// PC relative 32 bit. `((S + A) | T) | – P`
pub const R_ARM_REL32: u32 = 3;
/// `S + A – P`
pub const R_ARM_LDR_PC_G0: u32 = 4;
/// Direct 16 bit. `S + A`
pub const R_ARM_ABS16: u32 = 5;
/// Direct 12 bit. `S + A`
pub const R_ARM_ABS12: u32 = 6;
/// Direct & 0x7C `(LDR, STR). S + A`
pub const R_ARM_THM_ABS5: u32 = 7;
/// Direct 8 bit. `S + A`
pub const R_ARM_ABS8: u32 = 8;
/// `((S + A) | T) – B(S)`
pub const R_ARM_SBREL32: u32 = 9;
/// PC relative 24 bit (Thumb32 BL). `((S + A) | T) – P`
pub const R_ARM_THM_CALL: u32 = 10;
/// PC relative & 0x3FC (Thumb16 LDR, ADD, ADR). `S + A – Pa`
pub const R_ARM_THM_PC8: u32 = 11;
pub const R_ARM_BREL_ADJ: u32 = 12;
/// dynamic reloc
pub const R_ARM_TLS_DESC: u32 = 13;
/// obsolete/reserved
pub const R_ARM_THM_SWI8: u32 = 14;
/// obsolete/reserved
pub const R_ARM_XPC25: u32 = 15;
/// obsolete/reserved
pub const R_ARM_THM_XPC22: u32 = 16;
/// ID of module containing symbol.
pub const R_ARM_TLS_DTPMOD32: u32 = 17;
/// Offset in TLS block. `S + A – TLS`
pub const R_ARM_TLS_DTPOFF32: u32 = 18;
/// Offset in static TLS block. `S + A – Tp`
pub const R_ARM_TLS_TPOFF32: u32 = 19;
/// dynamic reloc Copy symbol at runtime.
pub const R_ARM_COPY: u32 = 20;
/// Create GOT entry. `(S + A) | T`
pub const R_ARM_GLOB_DAT: u32 = 21;
/// Create PLT entry. `(S + A) | T`
pub const R_ARM_JUMP_SLOT: u32 = 22;
/// Adjust by program base. `B(S) + A`
pub const R_ARM_RELATIVE: u32 = 23;
/// 32 bit offset to GOT. `((S + A) | T) – GOT_ORG`
pub const R_ARM_GOTOFF32: u32 = 24;
/// 32 bit PC relative offset to GOT. `B(S) + A – P`
pub const R_ARM_BASE_PREL: u32 = 25;
/// 32 bit GOT entry. `GOT(S) + A – GOT_ORG`
pub const R_ARM_BASE_BREL: u32 = 26;
/// Deprecated, 32 bit PLT address.
pub const R_ARM_PLT32: u32 = 27;
/// PC relative 24 bit (BL, BLX). `((S + A) | T) – P`
pub const R_ARM_CALL: u32 = 28;
/// PC relative 24 bit (B, BL{cond}). `((S + A) | T) – P`
pub const R_ARM_JUMP24: u32 = 29;
/// PC relative 24 bit (Thumb32 B.W). `((S + A) | T) – P`
pub const R_ARM_THM_JUMP24: u32 = 30;
/// Adjust by program base. `B(S) + A`
pub const R_ARM_BASE_ABS: u32 = 31;
/// Obsolete.
pub const R_ARM_ALU_PCREL_7_0: u32 = 32;
/// Obsolete.
pub const R_ARM_ALU_PCREL_15_8: u32 = 33;
/// Obsolete.
pub const R_ARM_ALU_PCREL_23_15: u32 = 34;
/// Deprecated, prog. base relative.
pub const R_ARM_LDR_SBREL_11_0: u32 = 35;
/// Deprecated, prog. base relative.
pub const R_ARM_ALU_SBREL_19_12: u32 = 36;
/// Deprecated, prog. base relative.
pub const R_ARM_ALU_SBREL_27_20: u32 = 37;
pub const R_ARM_TARGET1: u32 = 38;
/// Program base relative. `((S + A) | T) – B(S)`
pub const R_ARM_SBREL31: u32 = 39;
pub const R_ARM_V4BX: u32 = 40;
pub const R_ARM_TARGET2: u32 = 41;
/// 32 bit PC relative. `((S + A) | T) – P`
pub const R_ARM_PREL31: u32 = 42;
/// Direct 16-bit (MOVW). `(S + A) | T`
pub const R_ARM_MOVW_ABS_NC: u32 = 43;
/// Direct high 16-bit (MOVT). `S + A`
pub const R_ARM_MOVT_ABS: u32 = 44;
/// PC relative 16-bit (MOVW). `((S + A) | T) – P`
pub const R_ARM_MOVW_PREL_NC: u32 = 45;
/// PC relative (MOVT). `S + A - P`
pub const R_ARM_MOVT_PREL: u32 = 46;
/// Direct 16 bit (Thumb32 MOVW). `(S + A) | T`
pub const R_ARM_THM_MOVW_ABS_NC: u32 = 47;
/// Direct high 16 bit (Thumb32 MOVT). `S + A`
pub const R_ARM_THM_MOVT_ABS: u32 = 48;
/// PC relative 16 bit (Thumb32 MOVW). `((S + A) | T) – P`
pub const R_ARM_THM_MOVW_PREL_NC: u32 = 49;
/// PC relative high 16 bit (Thumb32 MOVT). `S + A – P`
pub const R_ARM_THM_MOVT_PREL: u32 = 50;
/// PC relative 20 bit (Thumb32 B{cond}.W). `((S + A) | T) – P`
pub const R_ARM_THM_JUMP19: u32 = 51;
/// PC relative X & 0x7E (Thumb16 CBZ, CBNZ). `S + A – P`
pub const R_ARM_THM_JUMP6: u32 = 52;
/// PC relative 12 bit (Thumb32 ADR.W). `((S + A) | T) – Pa`
pub const R_ARM_THM_ALU_PREL_11_0: u32 = 53;
/// PC relative 12 bit (Thumb32 LDR{D,SB,H,SH}). `S + A – Pa`
pub const R_ARM_THM_PC12: u32 = 54;
/// Direct 32-bit. `S + A`
pub const R_ARM_ABS32_NOI: u32 = 55;
/// PC relative 32-bit. `S + A - P`
pub const R_ARM_REL32_NOI: u32 = 56;
/// PC relative (ADD, SUB). `((S + A) | T) – P`
pub const R_ARM_ALU_PC_G0_NC: u32 = 57;
/// PC relative (ADD, SUB). `((S + A) | T) – P`
pub const R_ARM_ALU_PC_G0: u32 = 58;
/// PC relative (ADD, SUB). `((S + A) | T) – P`
pub const R_ARM_ALU_PC_G1_NC: u32 = 59;
/// PC relative (ADD, SUB). `((S + A) | T) – P`
pub const R_ARM_ALU_PC_G1: u32 = 60;
/// PC relative (ADD, SUB). `((S + A) | T) – P`
pub const R_ARM_ALU_PC_G2: u32 = 61;
/// PC relative (LDR,STR,LDRB,STRB). `S + A – P`
pub const R_ARM_LDR_PC_G1: u32 = 62;
/// PC relative (LDR,STR,LDRB,STRB). `S + A – P`
pub const R_ARM_LDR_PC_G2: u32 = 63;
/// PC relative (STR{D,H}, LDR{D,SB,H,SH}). `S + A – P`
pub const R_ARM_LDRS_PC_G0: u32 = 64;
/// PC relative (STR{D,H}, LDR{D,SB,H,SH}). `S + A – P`
pub const R_ARM_LDRS_PC_G1: u32 = 65;
/// PC relative (STR{D,H}, LDR{D,SB,H,SH}). `S + A – P`
pub const R_ARM_LDRS_PC_G2: u32 = 66;
/// PC relative (LDC, STC). `S + A – P`
pub const R_ARM_LDC_PC_G0: u32 = 67;
/// PC relative (LDC, STC). `S + A – P`
pub const R_ARM_LDC_PC_G1: u32 = 68;
/// PC relative (LDC, STC). `S + A – P`
pub const R_ARM_LDC_PC_G2: u32 = 69;
/// Program base relative (ADD,SUB). `((S + A) | T) – B(S)`
pub const R_ARM_ALU_SB_G0_NC: u32 = 70;
/// Program base relative (ADD,SUB). `((S + A) | T) – B(S)`
pub const R_ARM_ALU_SB_G0: u32 = 71;
/// Program base relative (ADD,SUB). `((S + A) | T) – B(S)`
pub const R_ARM_ALU_SB_G1_NC: u32 = 72;
/// Program base relative (ADD,SUB). `((S + A) | T) – B(S)`
pub const R_ARM_ALU_SB_G1: u32 = 73;
/// Program base relative (ADD,SUB). `((S + A) | T) – B(S)`
pub const R_ARM_ALU_SB_G2: u32 = 74;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDR_SB_G0: u32 = 75;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDR_SB_G1: u32 = 76;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDR_SB_G2: u32 = 77;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDRS_SB_G0: u32 = 78;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDRS_SB_G1: u32 = 79;
/// Program base relative (LDR, STR, LDRB, STRB). `S + A – B(S)`
pub const R_ARM_LDRS_SB_G2: u32 = 80;
/// Program base relative (LDC,STC). `S + A – B(S)`
pub const R_ARM_LDC_SB_G0: u32 = 81;
/// Program base relative (LDC,STC). `S + A – B(S)`
pub const R_ARM_LDC_SB_G1: u32 = 82;
/// Program base relative (LDC,STC). `S + A – B(S)`
pub const R_ARM_LDC_SB_G2: u32 = 83;
/// Program base relative 16 bit (MOVW). `((S + A) | T) – B(S)`
pub const R_ARM_MOVW_BREL_NC: u32 = 84;
/// Program base relative high 16 bit (MOVT). `S + A – B(S)`
pub const R_ARM_MOVT_BREL: u32 = 85;
/// Program base relative 16 bit (MOVW). `((S + A) | T) – B(S)`
pub const R_ARM_MOVW_BREL: u32 = 86;
/// Program base relative 16 bit (Thumb32 MOVW). `((S + A) | T) – B(S)`
pub const R_ARM_THM_MOVW_BREL_NC: u32 = 87;
/// Program base relative high 16 bit (Thumb32 MOVT). `S + A – B(S)`
pub const R_ARM_THM_MOVT_BREL: u32 = 88;
/// Program base relative 16 bit (Thumb32 MOVW). `((S + A) | T) – B(S)`
pub const R_ARM_THM_MOVW_BREL: u32 = 89;
pub const R_ARM_TLS_GOTDESC: u32 = 90;
pub const R_ARM_TLS_CALL: u32 = 91;
/// TLS relaxation.
pub const R_ARM_TLS_DESCSEQ: u32 = 92;
pub const R_ARM_THM_TLS_CALL: u32 = 93;
/// `PLT(S) + A`
pub const R_ARM_PLT32_ABS: u32 = 94;
/// GOT entry. `GOT(S) + A`
pub const R_ARM_GOT_ABS: u32 = 95;
/// PC relative GOT entry. `GOT(S) + A – P`
pub const R_ARM_GOT_PREL: u32 = 96;
/// GOT entry relative to GOT origin (LDR). `GOT(S) + A – GOT_ORG`
pub const R_ARM_GOT_BREL12: u32 = 97;
/// 12 bit, GOT entry relative to GOT origin (LDR, STR). `S + A – GOT_ORG`
pub const R_ARM_GOTOFF12: u32 = 98;
pub const R_ARM_GOTRELAX: u32 = 99;
pub const R_ARM_GNU_VTENTRY: u32 = 100;
pub const R_ARM_GNU_VTINHERIT: u32 = 101;
/// PC relative & 0xFFE (Thumb16 B). `S + A – P`
pub const R_ARM_THM_JUMP11: u32 = 102;
/// PC relative & 0x1FE (Thumb16 B/B{cond}). `S + A – P`
pub const R_ARM_THM_JUMP8: u32 = 103;
/// PC-rel 32 bit for global dynamic thread local data. `GOT(S) + A – P`
pub const R_ARM_TLS_GD32: u32 = 104;
/// PC-rel 32 bit for local dynamic thread local data. `GOT(S) + A – P`
pub const R_ARM_TLS_LDM32: u32 = 105;
/// 32 bit offset relative to TLS block. `S + A – TLS`
pub const R_ARM_TLS_LDO32: u32 = 106;
/// PC-rel 32 bit for GOT entry of static TLS block offset. `GOT(S) + A – P`
pub const R_ARM_TLS_IE32: u32 = 107;
/// 32 bit offset relative to static TLS block. `S + A – tp`
pub const R_ARM_TLS_LE32: u32 = 108;
/// 12 bit relative to TLS block (LDR, STR). `S + A – TLS`
pub const R_ARM_TLS_LDO12: u32 = 109;
/// 12 bit relative to static TLS block (LDR, STR). `S + A – tp`
pub const R_ARM_TLS_LE12: u32 = 110;
/// 12 bit GOT entry relative to GOT origin (LDR). `GOT(S) + A – GOT_ORG`
pub const R_ARM_TLS_IE12GP: u32 = 111;
/// Obsolete.
pub const R_ARM_ME_TOO: u32 = 128;
pub const R_ARM_THM_TLS_DESCSEQ16: u32 = 129;
pub const R_ARM_THM_TLS_DESCSEQ32: u32 = 130;
/// GOT entry relative to GOT origin, 12 bit (Thumb32 LDR). `GOT(S) + A – GOT_ORG`
pub const R_ARM_THM_GOT_BREL12: u32 = 131;
/// Static Thumb16 `(S + A) | T`
pub const R_ARM_THM_ALU_ABS_G0_NC: u32 = 132;
/// Static Thumb16 `S + A`
pub const R_ARM_THM_ALU_ABS_G1_NC: u32 = 133;
/// Static Thumb16 `S + A`
pub const R_ARM_THM_ALU_ABS_G2_NC: u32 = 134;
/// Static Thumb16 `S + A`
pub const R_ARM_THM_ALU_ABS_G3: u32 = 135;
/// Static Arm `((S + A) | T) – P`
pub const R_ARM_THM_BF16: u32 = 136;
/// Static Arm `((S + A) | T) – P`
pub const R_ARM_THM_BF12: u32 = 137;
/// Static Arm `((S + A) | T) – P`
pub const R_ARM_THM_BF18: u32 = 138;
pub const R_ARM_IRELATIVE: u32 = 160;

/// Object file compatibility attributes
pub const SHT_AARCH64_ATTRIBUTES: u32 = 0x70000003;
pub const SHT_AARCH64_ATTRIBUTES_SECTION_NAME: &str = ".ARM.attributes";

/// Architecture compatibility information.
///
/// A segment of type PT_AARCH64_ARCHEXT (if present) contains information
/// describing the architecture capabilities required by the executable file.
/// Not all platform ABIs require this segment; the Linux ABI does not. If the
/// segment is present it must appear before segment of type PT_LOAD.
pub const PT_AARCH64_ARCHEXT: u32 = 0x70000000;
/// (if present) describes the location of a program’s exception unwind tables.
pub const PT_AARCH64_UNWIND: u32 = 0x70000001;
/// Reserved for MTE memory tag data dumps in core files
/// (if present) hold MTE memory tags for a particular memory range.
/// At present they are defined for core dump files of type ET_CORE
/// See <https://www.kernel.org/doc/html/latest/arm64/memory-tagging-extension.html#core-dump-support>
pub const PT_AARCH64_MEMTAG_MTE: u32 = 0x70000002;

/// The function associated with the symbol may follow a variant procedure call
/// standard with different register usage convention.
/// Found in Symbol's st_other field
pub const STO_AARCH64_VARIANT_PCS: u8 = 0x80;

pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc0000000;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 0x1;
pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 0x2;

// AArch64 specific values for the Dyn d_tag field.
/// indicates PLTs enabled with Branch Target Identification mechanism
pub const DT_AARCH64_BTI_PLT: i64 = 0x70000001;
/// indicates PLTs enabled with Pointer Authentication.
pub const DT_AARCH64_PAC_PLT: i64 = 0x70000003;
/// must be present if there are R_{CLS}_JUMP_SLOT relocations that reference
/// symbols marked with the STO_AARCH64_VARIANT_PCS flag set in their st_other field
pub const DT_AARCH64_VARIANT_PCS: i64 = 0x70000005;

/// No relocation.
pub const R_AARCH64_NONE: u32 = 0;
/// Direct 32 bit.
pub const R_AARCH64_P32_ABS32: u32 = 1;
/// Copy symbol at runtime.
pub const R_AARCH64_P32_COPY: u32 = 180;
/// Create GOT entry.
pub const R_AARCH64_P32_GLOB_DAT: u32 = 181;
/// Create PLT entry.
pub const R_AARCH64_P32_JUMP_SLOT: u32 = 182;
/// Adjust by program base.
pub const R_AARCH64_P32_RELATIVE: u32 = 183;
/// Module number, 32 bit.
pub const R_AARCH64_P32_TLS_DTPMOD: u32 = 184;
/// Module-relative offset, 32 bit.
pub const R_AARCH64_P32_TLS_DTPREL: u32 = 185;
/// TP-relative offset, 32 bit.
pub const R_AARCH64_P32_TLS_TPREL: u32 = 186;
/// TLS Descriptor.
pub const R_AARCH64_P32_TLSDESC: u32 = 187;
/// STT_GNU_IFUNC relocation
pub const R_AARCH64_P32_IRELATIVE: u32 = 188;
/// Direct 64 bit.
pub const R_AARCH64_ABS64: u32 = 257;
/// Direct 32 bit.
pub const R_AARCH64_ABS32: u32 = 258;
/// Direct 16-bit.
pub const R_AARCH64_ABS16: u32 = 259;
/// PC-relative 64-bit.
pub const R_AARCH64_PREL64: u32 = 260;
/// PC-relative 32-bit.
pub const R_AARCH64_PREL32: u32 = 261;
/// PC-relative 16-bit.
pub const R_AARCH64_PREL16: u32 = 262;
/// Dir. MOVZ imm. from bits 15:0.
pub const R_AARCH64_MOVW_UABS_G0: u32 = 263;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
/// Dir. MOVZ imm. from bits 31:16.
pub const R_AARCH64_MOVW_UABS_G1: u32 = 265;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
/// Dir. MOVZ imm. from bits 47:32.
pub const R_AARCH64_MOVW_UABS_G2: u32 = 267;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
/// Dir. MOV{K,Z} imm. from 63:48.
pub const R_AARCH64_MOVW_UABS_G3: u32 = 269;
/// Dir. MOV{N,Z} imm. from 15:0.
pub const R_AARCH64_MOVW_SABS_G0: u32 = 270;
/// Dir. MOV{N,Z} imm. from 31:16.
pub const R_AARCH64_MOVW_SABS_G1: u32 = 271;
/// Dir. MOV{N,Z} imm. from 47:32.
pub const R_AARCH64_MOVW_SABS_G2: u32 = 272;
/// PC-rel. LD imm. from bits 20:2.
pub const R_AARCH64_LD_PREL_LO19: u32 = 273;
/// PC-rel. ADR imm. from bits 20:0.
pub const R_AARCH64_ADR_PREL_LO21: u32 = 274;
/// Page-rel. ADRP imm. from 32:12.
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
/// Likewise; no overflow check.
pub const R_AARCH64_ADR_PREL_PG_HI21_NC: u32 = 276;
/// Dir. ADD imm. from bits 11:0.
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
/// Likewise for LD/ST; no check.
pub const R_AARCH64_LDST8_ABS_LO12_NC: u32 = 278;
/// PC-rel. TBZ/TBNZ imm. from 15:2.
pub const R_AARCH64_TSTBR14: u32 = 279;
/// PC-rel. cond. br. imm. from 20:2.
pub const R_AARCH64_CONDBR19: u32 = 280;
/// PC-rel. B imm. from bits 27:2.
pub const R_AARCH64_JUMP26: u32 = 282;
/// Likewise for CALL.
pub const R_AARCH64_CALL26: u32 = 283;
/// Dir. ADD imm. from bits 11:1.
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
/// Likewise for bits 11:2.
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
/// Likewise for bits 11:3.
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
/// PC-rel. MOV{N,Z} imm. from 15:0.
pub const R_AARCH64_MOVW_PREL_G0: u32 = 287;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_PREL_G0_NC: u32 = 288;
/// PC-rel. MOV{N,Z} imm. from 31:16.
pub const R_AARCH64_MOVW_PREL_G1: u32 = 289;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_PREL_G1_NC: u32 = 290;
/// PC-rel. MOV{N,Z} imm. from 47:32.
pub const R_AARCH64_MOVW_PREL_G2: u32 = 291;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_PREL_G2_NC: u32 = 292;
/// PC-rel. MOV{N,Z} imm. from 63:48.
pub const R_AARCH64_MOVW_PREL_G3: u32 = 293;
/// Dir. ADD imm. from bits 11:4.
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
/// GOT-rel. off. MOV{N,Z} imm. 15:0.
pub const R_AARCH64_MOVW_GOTOFF_G0: u32 = 300;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_GOTOFF_G0_NC: u32 = 301;
/// GOT-rel. o. MOV{N,Z} imm. 31:16.
pub const R_AARCH64_MOVW_GOTOFF_G1: u32 = 302;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_GOTOFF_G1_NC: u32 = 303;
/// GOT-rel. o. MOV{N,Z} imm. 47:32.
pub const R_AARCH64_MOVW_GOTOFF_G2: u32 = 304;
/// Likewise for MOVK; no check.
pub const R_AARCH64_MOVW_GOTOFF_G2_NC: u32 = 305;
/// GOT-rel. o. MOV{N,Z} imm. 63:48.
pub const R_AARCH64_MOVW_GOTOFF_G3: u32 = 306;
/// GOT-relative 64-bit.
pub const R_AARCH64_GOTREL64: u32 = 307;
/// GOT-relative 32-bit.
pub const R_AARCH64_GOTREL32: u32 = 308;
/// PC-rel. GOT off. load imm. 20:2.
pub const R_AARCH64_GOT_LD_PREL19: u32 = 309;
/// GOT-rel. off. LD/ST imm. 14:3.
pub const R_AARCH64_LD64_GOTOFF_LO15: u32 = 310;
/// P-page-rel. GOT off. ADRP: u32 = 32:12.
pub const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
/// Dir. GOT off. LD/ST imm. 11:3.
pub const R_AARCH64_LD64_GOT_LO12_NC: u32 = 312;
/// GOT-page-rel. GOT off. LD/ST: u32 = 14:3
pub const R_AARCH64_LD64_GOTPAGE_LO15: u32 = 313;
/// PC-relative ADR imm. 20:0.
pub const R_AARCH64_TLSGD_ADR_PREL21: u32 = 512;
/// page-rel. ADRP imm. 32:12.
pub const R_AARCH64_TLSGD_ADR_PAGE21: u32 = 513;
/// direct ADD imm. from 11:0.
pub const R_AARCH64_TLSGD_ADD_LO12_NC: u32 = 514;
/// GOT-rel. MOV{N,Z} 31:16.
pub const R_AARCH64_TLSGD_MOVW_G1: u32 = 515;
/// GOT-rel. MOVK imm. 15:0.
pub const R_AARCH64_TLSGD_MOVW_G0_NC: u32 = 516;
/// Like 512; local dynamic model.
pub const R_AARCH64_TLSLD_ADR_PREL21: u32 = 517;
/// Like 513; local dynamic model.
pub const R_AARCH64_TLSLD_ADR_PAGE21: u32 = 518;
/// Like 514; local dynamic model.
pub const R_AARCH64_TLSLD_ADD_LO12_NC: u32 = 519;
/// Like 515; local dynamic model.
pub const R_AARCH64_TLSLD_MOVW_G1: u32 = 520;
/// Like 516; local dynamic model.
pub const R_AARCH64_TLSLD_MOVW_G0_NC: u32 = 521;
/// TLS PC-rel. load imm. 20:2.
pub const R_AARCH64_TLSLD_LD_PREL19: u32 = 522;
/// TLS DTP-rel. MOV{N,Z} 47:32.
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G2: u32 = 523;
/// TLS DTP-rel. MOV{N,Z} 31:16.
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1: u32 = 524;
/// Likewise; MOVK; no check.
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC: u32 = 525;
/// TLS DTP-rel. MOV{N,Z} 15:0.
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0: u32 = 526;
/// Likewise; MOVK; no check.
pub const R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC: u32 = 527;
/// DTP-rel. ADD imm. from 23:12.
pub const R_AARCH64_TLSLD_ADD_DTPREL_HI12: u32 = 528;
/// DTP-rel. ADD imm. from 11:0.
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12: u32 = 529;
/// Likewise; no ovfl. check.
pub const R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC: u32 = 530;
/// DTP-rel. LD/ST imm. 11:0.
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12: u32 = 531;
/// Likewise; no check.
pub const R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC: u32 = 532;
/// DTP-rel. LD/ST imm. 11:1.
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12: u32 = 533;
/// Likewise; no check.
pub const R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC: u32 = 534;
/// DTP-rel. LD/ST imm. 11:2.
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12: u32 = 535;
/// Likewise; no check.
pub const R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC: u32 = 536;
/// DTP-rel. LD/ST imm. 11:3.
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12: u32 = 537;
/// Likewise; no check.
pub const R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC: u32 = 538;
/// GOT-rel. MOV{N,Z} 31:16.
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G1: u32 = 539;
/// GOT-rel. MOVK: u32 = 15:0.
pub const R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC: u32 = 540;
/// Page-rel. ADRP: u32 = 32:12.
pub const R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21: u32 = 541;
/// Direct LD off. 11:3.
pub const R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC: u32 = 542;
/// PC-rel. load imm. 20:2.
pub const R_AARCH64_TLSIE_LD_GOTTPREL_PREL19: u32 = 543;
/// TLS TP-rel. MOV{N,Z} 47:32.
pub const R_AARCH64_TLSLE_MOVW_TPREL_G2: u32 = 544;
/// TLS TP-rel. MOV{N,Z} 31:16.
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1: u32 = 545;
/// Likewise; MOVK; no check.
pub const R_AARCH64_TLSLE_MOVW_TPREL_G1_NC: u32 = 546;
/// TLS TP-rel. MOV{N,Z} 15:0.
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0: u32 = 547;
/// Likewise; MOVK; no check.
pub const R_AARCH64_TLSLE_MOVW_TPREL_G0_NC: u32 = 548;
/// TP-rel. ADD imm. 23:12.
pub const R_AARCH64_TLSLE_ADD_TPREL_HI12: u32 = 549;
/// TP-rel. ADD imm. 11:0.
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12: u32 = 550;
/// Likewise; no ovfl. check.
pub const R_AARCH64_TLSLE_ADD_TPREL_LO12_NC: u32 = 551;
/// TP-rel. LD/ST off. 11:0.
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12: u32 = 552;
/// Likewise; no ovfl. check.
pub const R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC: u32 = 553;
/// TP-rel. LD/ST off. 11:1.
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12: u32 = 554;
/// Likewise; no check.
pub const R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC: u32 = 555;
/// TP-rel. LD/ST off. 11:2.
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12: u32 = 556;
/// Likewise; no check.
pub const R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC: u32 = 557;
/// TP-rel. LD/ST off. 11:3.
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12: u32 = 558;
/// Likewise; no check.
pub const R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC: u32 = 559;
/// PC-rel. load immediate 20:2.
pub const R_AARCH64_TLSDESC_LD_PREL19: u32 = 560;
/// PC-rel. ADR immediate 20:0.
pub const R_AARCH64_TLSDESC_ADR_PREL21: u32 = 561;
/// Page-rel. ADRP imm. 32:12.
pub const R_AARCH64_TLSDESC_ADR_PAGE21: u32 = 562;
/// Direct LD off. from 11:3.
pub const R_AARCH64_TLSDESC_LD64_LO12: u32 = 563;
/// Direct ADD imm. from 11:0.
pub const R_AARCH64_TLSDESC_ADD_LO12: u32 = 564;
/// GOT-rel. MOV{N,Z} imm. 31:16.
pub const R_AARCH64_TLSDESC_OFF_G1: u32 = 565;
/// GOT-rel. MOVK imm. 15:0; no ck.
pub const R_AARCH64_TLSDESC_OFF_G0_NC: u32 = 566;
/// Relax LDR.
pub const R_AARCH64_TLSDESC_LDR: u32 = 567;
/// Relax ADD.
pub const R_AARCH64_TLSDESC_ADD: u32 = 568;
/// Relax BLR.
pub const R_AARCH64_TLSDESC_CALL: u32 = 569;
/// TP-rel. LD/ST off. 11:4.
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12: u32 = 570;
/// Likewise; no check.
pub const R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC: u32 = 571;
/// DTP-rel. LD/ST imm. 11:4.
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12: u32 = 572;
/// Likewise; no check.
pub const R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC: u32 = 573;
/// Copy symbol at runtime.
pub const R_AARCH64_COPY: u32 = 1024;
/// Create GOT entry.
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
/// Create PLT entry.
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
/// Adjust by program base.
pub const R_AARCH64_RELATIVE: u32 = 1027;
/// Module number, 64 bit.
pub const R_AARCH64_TLS_DTPMOD: u32 = 1028;
/// Module-relative offset, 64 bit.
pub const R_AARCH64_TLS_DTPREL: u32 = 1029;
/// TP-relative offset, 64 bit.
pub const R_AARCH64_TLS_TPREL: u32 = 1030;
/// TLS Descriptor.
pub const R_AARCH64_TLSDESC: u32 = 1031;
/// STT_GNU_IFUNC relocation.
pub const R_AARCH64_IRELATIVE: u32 = 1032;

//  ____                        ____   ____
// |  _ \ _____      _____ _ __|  _ \ / ___|
// | |_) / _ \ \ /\ / / _ \ '__| |_) | |
// |  __/ (_) \ V  V /  __/ |  |  __/| |___
// |_|   \___/ \_/\_/ \___|_|  |_|    \____|
//
// See: https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi.html#ELF-HEAD

/// PowerPC embedded flag
pub const EF_PPC_EMB: u32 = 0x80000000;
/// PowerPC -mrelocatable flag
pub const EF_PPC_RELOCATABLE: u32 = 0x00010000;
/// PowerPC -mrelocatable-lib flag
pub const EF_PPC_RELOCATABLE_LIB: u32 = 0x00008000;

// PowerPC relocations types
pub const R_PPC_NONE: u32 = 0;
/// 32bit absolute address
pub const R_PPC_ADDR32: u32 = 1;
/// 26bit address, 2 bits ignored.
pub const R_PPC_ADDR24: u32 = 2;
/// 16bit absolute address
pub const R_PPC_ADDR16: u32 = 3;
/// lower 16bit of absolute address
pub const R_PPC_ADDR16_LO: u32 = 4;
/// high 16bit of absolute address
pub const R_PPC_ADDR16_HI: u32 = 5;
/// adjusted high 16bit
pub const R_PPC_ADDR16_HA: u32 = 6;
/// 16bit address, 2 bits ignored
pub const R_PPC_ADDR14: u32 = 7;
pub const R_PPC_ADDR14_BRTAKEN: u32 = 8;
pub const R_PPC_ADDR14_BRNTAKEN: u32 = 9;
/// PC relative 26 bit
pub const R_PPC_REL24: u32 = 10;
/// PC relative 16 bit
pub const R_PPC_REL14: u32 = 11;
pub const R_PPC_REL14_BRTAKEN: u32 = 12;
pub const R_PPC_REL14_BRNTAKEN: u32 = 13;
pub const R_PPC_GOT16: u32 = 14;
pub const R_PPC_GOT16_LO: u32 = 15;
pub const R_PPC_GOT16_HI: u32 = 16;
pub const R_PPC_GOT16_HA: u32 = 17;
pub const R_PPC_PLTREL24: u32 = 18;
pub const R_PPC_COPY: u32 = 19;
pub const R_PPC_GLOB_DAT: u32 = 20;
pub const R_PPC_JMP_SLOT: u32 = 21;
pub const R_PPC_RELATIVE: u32 = 22;
pub const R_PPC_LOCAL24PC: u32 = 23;
pub const R_PPC_UADDR32: u32 = 24;
pub const R_PPC_UADDR16: u32 = 25;
pub const R_PPC_REL32: u32 = 26;
pub const R_PPC_PLT32: u32 = 27;
pub const R_PPC_PLTREL32: u32 = 28;
pub const R_PPC_PLT16_LO: u32 = 29;
pub const R_PPC_PLT16_HI: u32 = 30;
pub const R_PPC_PLT16_HA: u32 = 31;
pub const R_PPC_SDAREL16: u32 = 32;
pub const R_PPC_SECTOFF: u32 = 33;
pub const R_PPC_SECTOFF_LO: u32 = 34;
pub const R_PPC_SECTOFF_HI: u32 = 35;
pub const R_PPC_SECTOFF_HA: u32 = 36;

/// (sym+add)@tls
pub const R_PPC_TLS: u32 = 67;
/// (sym+add)@dtpmod
pub const R_PPC_DTPMOD32: u32 = 68;
/// (sym+add)@tprel
pub const R_PPC_TPREL16: u32 = 69;
/// (sym+add)@tprel@l
pub const R_PPC_TPREL16_LO: u32 = 70;
/// (sym+add)@tprel@h
pub const R_PPC_TPREL16_HI: u32 = 71;
/// (sym+add)@tprel@ha
pub const R_PPC_TPREL16_HA: u32 = 72;
/// (sym+add)@tprel
pub const R_PPC_TPREL32: u32 = 73;
/// (sym+add)@dtprel
pub const R_PPC_DTPREL16: u32 = 74;
/// (sym+add)@dtprel@l
pub const R_PPC_DTPREL16_LO: u32 = 75;
/// (sym+add)@dtprel@h
pub const R_PPC_DTPREL16_HI: u32 = 76;
/// (sym+add)@dtprel@ha
pub const R_PPC_DTPREL16_HA: u32 = 77;
/// (sym+add)@dtprel
pub const R_PPC_DTPREL32: u32 = 78;
/// (sym+add)@got@tlsgd
pub const R_PPC_GOT_TLSGD16: u32 = 79;
/// (sym+add)@got@tlsgd@l
pub const R_PPC_GOT_TLSGD16_LO: u32 = 80;
/// (sym+add)@got@tlsgd@h
pub const R_PPC_GOT_TLSGD16_HI: u32 = 81;
/// (sym+add)@got@tlsgd@ha
pub const R_PPC_GOT_TLSGD16_HA: u32 = 82;
/// (sym+add)@got@tlsld
pub const R_PPC_GOT_TLSLD16: u32 = 83;
/// (sym+add)@got@tlsld@l
pub const R_PPC_GOT_TLSLD16_LO: u32 = 84;
/// (sym+add)@got@tlsld@h
pub const R_PPC_GOT_TLSLD16_HI: u32 = 85;
/// (sym+add)@got@tlsld@ha
pub const R_PPC_GOT_TLSLD16_HA: u32 = 86;
/// (sym+add)@got@tprel
pub const R_PPC_GOT_TPREL16: u32 = 87;
/// (sym+add)@got@tprel@l
pub const R_PPC_GOT_TPREL16_LO: u32 = 88;
/// (sym+add)@got@tprel@h
pub const R_PPC_GOT_TPREL16_HI: u32 = 89;
/// (sym+add)@got@tprel@ha
pub const R_PPC_GOT_TPREL16_HA: u32 = 90;
/// (sym+add)@got@dtprel
pub const R_PPC_GOT_DTPREL16: u32 = 91;
/// (sym+add)@got@dtprel@l
pub const R_PPC_GOT_DTPREL16_LO: u32 = 92;
/// (sym+add)@got@dtprel@h
pub const R_PPC_GOT_DTPREL16_HI: u32 = 93;
/// (sym+add)@got@dtprel@ha
pub const R_PPC_GOT_DTPREL16_HA: u32 = 94;
/// (sym+add)@tlsgd
pub const R_PPC_TLSGD: u32 = 95;
/// (sym+add)@tlsld
pub const R_PPC_TLSLD: u32 = 96;

// The remaining relocs are from the Embedded ELF ABI, and are not in the SVR4 ELF ABI.
pub const R_PPC_EMB_NADDR32: u32 = 101;
pub const R_PPC_EMB_NADDR16: u32 = 102;
pub const R_PPC_EMB_NADDR16_LO: u32 = 103;
pub const R_PPC_EMB_NADDR16_HI: u32 = 104;
pub const R_PPC_EMB_NADDR16_HA: u32 = 105;
pub const R_PPC_EMB_SDAI16: u32 = 106;
pub const R_PPC_EMB_SDA2I16: u32 = 107;
pub const R_PPC_EMB_SDA2REL: u32 = 108;
/// 16 bit offset in SDA
pub const R_PPC_EMB_SDA21: u32 = 109;
pub const R_PPC_EMB_MRKREF: u32 = 110;
pub const R_PPC_EMB_RELSEC16: u32 = 111;
pub const R_PPC_EMB_RELST_LO: u32 = 112;
pub const R_PPC_EMB_RELST_HI: u32 = 113;
pub const R_PPC_EMB_RELST_HA: u32 = 114;
pub const R_PPC_EMB_BIT_FLD: u32 = 115;
pub const R_PPC_EMB_RELSDA: u32 = 116;

/// like EMB_SDA21, but lower 16 bit
pub const R_PPC_DIAB_SDA21_LO: u32 = 180;
/// like EMB_SDA21, but high 16 bit
pub const R_PPC_DIAB_SDA21_HI: u32 = 181;
/// like EMB_SDA21, adjusted high 16
pub const R_PPC_DIAB_SDA21_HA: u32 = 182;
/// like EMB_RELSDA, but lower 16 bit
pub const R_PPC_DIAB_RELSDA_LO: u32 = 183;
/// like EMB_RELSDA, but high 16 bit
pub const R_PPC_DIAB_RELSDA_HI: u32 = 184;
/// like EMB_RELSDA, adjusted high 16
pub const R_PPC_DIAB_RELSDA_HA: u32 = 185;

// GNU extension to support local ifunc.
pub const R_PPC_IRELATIVE: u32 = 248;

// GNU relocs used in PIC code sequences.
/// (sym+add-.)
pub const R_PPC_REL16: u32 = 249;
/// (sym+add-.)@l
pub const R_PPC_REL16_LO: u32 = 250;
/// (sym+add-.)@h
pub const R_PPC_REL16_HI: u32 = 251;
/// (sym+add-.)@ha
pub const R_PPC_REL16_HA: u32 = 252;

/// This is a phony reloc to handle any old fashioned TOC16 references that may still be in object files.
pub const R_PPC_TOC16: u32 = 255;

// PowerPC specific values for the Dyn d_tag field.
pub const DT_PPC_GOT: i64 = 0x70000000;
pub const DT_PPC_OPT: i64 = 0x70000001;

/// PowerPC specific values for the DT_PPC_OPT Dyn entry.
pub const PPC_OPT_TLS: u64 = 1;

// e_flags bits specifying ABI.
//   1 for original function descriptor using ABI,
//   2 for revised ABI without function descriptors,
//   0 for unspecified or not using any features affected by the differences.
pub const EF_PPC64_ABI: u32 = 3;

// PowerPC64 specific values for the Dyn d_tag field.
pub const DT_PPC64_GLINK: i64 = 0x70000000;
pub const DT_PPC64_OPD: i64 = 0x70000001;
pub const DT_PPC64_OPDSZ: i64 = 0x70000002;
pub const DT_PPC64_OPT: i64 = 0x70000003;

// PowerPC64 specific bits in the DT_PPC64_OPT Dyn entry.
pub const PPC64_OPT_TLS: u64 = 1;
pub const PPC64_OPT_MULTI_TOC: u64 = 2;
pub const PPC64_OPT_LOCALENTRY: u64 = 4;

// PowerPC64 specific values for the Elf64_Sym st_other field.
pub const STO_PPC64_LOCAL_BIT: u8 = 5;
pub const STO_PPC64_LOCAL_MASK: u8 = 7 << STO_PPC64_LOCAL_BIT;

// Relocation types
//
// A Represents the addend used to compute the value of the relocatable field.
// B Represents the base address at which a shared object has been loaded into memory during execution.
// G Represents the offset into the global offset table, relative to
//     the TOC base, at which the address of the relocation entry's symbol
//     plus addend will reside during execution.
// L Represents the section offset or address of the procedure linkage
//     table entry for the symbol plus addend.
// M Similar to G, except that the address which is stored may be the
//     address of the procedure linkage table entry for the symbol.
// P Represents the place (section offset or address) of the storage
//     unit being relocated (computed using r_offset).
// R Represents the offset of the symbol within the section in which
//     the symbol is defined (its section-relative address).
// S Represents the value of the symbol whose index resides in the relocation entry.

/// none
pub const R_PPC64_NONE: u32 = 0;
/// `S + A`
pub const R_PPC64_ADDR32: u32 = 1;
/// `(S + A) >> 2`
pub const R_PPC64_ADDR24: u32 = 2;
/// `S + A`
pub const R_PPC64_ADDR16: u32 = 3;
/// `#lo(S + A)`
pub const R_PPC64_ADDR16_LO: u32 = 4;
/// `#hi(S + A)`
pub const R_PPC64_ADDR16_HI: u32 = 5;
/// `#ha(S + A)`
pub const R_PPC64_ADDR16_HA: u32 = 6;
/// `(S + A) >> 2`
pub const R_PPC64_ADDR14: u32 = 7;
/// `(S + A) >> 2`
pub const R_PPC64_ADDR14_BRTAKEN: u32 = 8;
/// `(S + A) >> 2`
pub const R_PPC64_ADDR14_BRNTAKEN: u32 = 9;
/// `(S + A - P) >> 2`
pub const R_PPC64_REL24: u32 = 10;
/// `(S + A - P) >> 2`
pub const R_PPC64_REL14: u32 = 11;
/// `(S + A - P) >> 2`
pub const R_PPC64_REL14_BRTAKEN: u32 = 12;
/// `(S + A - P) >> 2`
pub const R_PPC64_REL14_BRNTAKEN: u32 = 13;
/// `G`
pub const R_PPC64_GOT16: u32 = 14;
/// `#lo(G)`
pub const R_PPC64_GOT16_LO: u32 = 15;
/// `#hi(G)`
pub const R_PPC64_GOT16_HI: u32 = 16;
/// `#ha(G)`
pub const R_PPC64_GOT16_HA: u32 = 17;
/// none
pub const R_PPC64_COPY: u32 = 19;
/// `S + A`
pub const R_PPC64_GLOB_DAT: u32 = 20;
/// see below
pub const R_PPC64_JMP_SLOT: u32 = 21;
/// `B + A`
pub const R_PPC64_RELATIVE: u32 = 22;
/// `S + A`
pub const R_PPC64_UADDR32: u32 = 24;
/// `S + A`
pub const R_PPC64_UADDR16: u32 = 25;
/// `S + A - P`
pub const R_PPC64_REL32: u32 = 26;
/// `L`
pub const R_PPC64_PLT32: u32 = 27;
/// `L - P`
pub const R_PPC64_PLTREL32: u32 = 28;
/// `#lo(L)`
pub const R_PPC64_PLT16_LO: u32 = 29;
/// `#hi(L)`
pub const R_PPC64_PLT16_HI: u32 = 30;
/// `#ha(L)`
pub const R_PPC64_PLT16_HA: u32 = 31;
/// `R + A`
pub const R_PPC64_SECTOFF: u32 = 33;
/// `#lo(R + A)`
pub const R_PPC64_SECTOFF_LO: u32 = 34;
/// `#hi(R + A)`
pub const R_PPC64_SECTOFF_HI: u32 = 35;
/// `#ha(R + A)`
pub const R_PPC64_SECTOFF_HA: u32 = 36;
/// `(S + A - P) >> 2`
pub const R_PPC64_ADDR30: u32 = 37;
/// `S + A`
pub const R_PPC64_ADDR64: u32 = 38;
/// `#higher(S + A)`
pub const R_PPC64_ADDR16_HIGHER: u32 = 39;
/// `#highera(S + A)`
pub const R_PPC64_ADDR16_HIGHERA: u32 = 40;
/// `#highest(S + A)`
pub const R_PPC64_ADDR16_HIGHEST: u32 = 41;
/// `#highesta(S + A)`
pub const R_PPC64_ADDR16_HIGHESTA: u32 = 42;
/// `S + A`
pub const R_PPC64_UADDR64: u32 = 43;
/// `S + A - P`
pub const R_PPC64_REL64: u32 = 44;
/// `L`
pub const R_PPC64_PLT64: u32 = 45;
/// `L - P`
pub const R_PPC64_PLTREL64: u32 = 46;
/// `S + A - .TOC.`
pub const R_PPC64_TOC16: u32 = 47;
/// `#lo(S + A - .TOC.)`
pub const R_PPC64_TOC16_LO: u32 = 48;
/// `#hi(S + A - .TOC.)`
pub const R_PPC64_TOC16_HI: u32 = 49;
/// `#ha(S + A - .TOC.)`
pub const R_PPC64_TOC16_HA: u32 = 50;
/// `.TOC.`
pub const R_PPC64_TOC: u32 = 51;
/// `M`
pub const R_PPC64_PLTGOT16: u32 = 52;
/// `#lo(M)`
pub const R_PPC64_PLTGOT16_LO: u32 = 53;
/// `#hi(M)`
pub const R_PPC64_PLTGOT16_HI: u32 = 54;
/// `#ha(M)`
pub const R_PPC64_PLTGOT16_HA: u32 = 55;
/// `(S + A) >> 2`
pub const R_PPC64_ADDR16_DS: u32 = 56;
/// `#lo(S + A) >> 2`
pub const R_PPC64_ADDR16_LO_DS: u32 = 57;
/// `G >> 2`
pub const R_PPC64_GOT16_DS: u32 = 58;
/// `#lo(G) >> 2`
pub const R_PPC64_GOT16_LO_DS: u32 = 59;
/// `#lo(L) >> 2`
pub const R_PPC64_PLT16_LO_DS: u32 = 60;
/// `(R + A) >> 2`
pub const R_PPC64_SECTOFF_DS: u32 = 61;
/// `#lo(R + A) >> 2`
pub const R_PPC64_SECTOFF_LO_DS: u32 = 62;
/// `(S + A - .TOC.) >> 2`
pub const R_PPC64_TOC16_DS: u32 = 63;
/// `#lo(S + A - .TOC.) >> 2`
pub const R_PPC64_TOC16_LO_DS: u32 = 64;
/// `M >> 2`
pub const R_PPC64_PLTGOT16_DS: u32 = 65;
/// `#lo(M) >> 2`
pub const R_PPC64_PLTGOT16_LO_DS: u32 = 66;
/// none
pub const R_PPC64_TLS: u32 = 67;
/// `@dtpmod`
pub const R_PPC64_DTPMOD64: u32 = 68;
/// `@tprel`
pub const R_PPC64_TPREL16: u32 = 69;
/// `#lo(@tprel)`
pub const R_PPC64_TPREL16_LO: u32 = 60;
/// `#hi(@tprel)`
pub const R_PPC64_TPREL16_HI: u32 = 71;
/// `#ha(@tprel)`
pub const R_PPC64_TPREL16_HA: u32 = 72;
/// `@tprel`
pub const R_PPC64_TPREL64: u32 = 73;
/// `@dtprel`
pub const R_PPC64_DTPREL16: u32 = 74;
/// `#lo(@dtprel)`
pub const R_PPC64_DTPREL16_LO: u32 = 75;
/// `#hi(@dtprel)`
pub const R_PPC64_DTPREL16_HI: u32 = 76;
/// `#ha(@dtprel)`
pub const R_PPC64_DTPREL16_HA: u32 = 77;
/// `@dtprel`
pub const R_PPC64_DTPREL64: u32 = 78;
/// `@got@tlsgd`
pub const R_PPC64_GOT_TLSGD16: u32 = 79;
/// `#lo(@got@tlsgd)`
pub const R_PPC64_GOT_TLSGD16_LO: u32 = 80;
/// `#hi(@got@tlsgd)`
pub const R_PPC64_GOT_TLSGD16_HI: u32 = 81;
/// `#ha(@got@tlsgd)`
pub const R_PPC64_GOT_TLSGD16_HA: u32 = 82;
/// `@got@tlsld`
pub const R_PPC64_GOT_TLSLD16: u32 = 83;
/// `#lo(@got@tlsld)`
pub const R_PPC64_GOT_TLSLD16_LO: u32 = 84;
/// `#hi(@got@tlsld)`
pub const R_PPC64_GOT_TLSLD16_HI: u32 = 85;
/// `#ha(@got@tlsld)`
pub const R_PPC64_GOT_TLSLD16_HA: u32 = 86;
/// `@got@tprel`
pub const R_PPC64_GOT_TPREL16_DS: u32 = 87;
/// `#lo(@got@tprel)`
pub const R_PPC64_GOT_TPREL16_LO_DS: u32 = 88;
/// `#hi(@got@tprel)`
pub const R_PPC64_GOT_TPREL16_HI: u32 = 89;
/// `#ha(@got@tprel)`
pub const R_PPC64_GOT_TPREL16_HA: u32 = 90;
/// `@got@dtprel`
pub const R_PPC64_GOT_DTPREL16_DS: u32 = 91;
/// `#lo(@got@dtprel)`
pub const R_PPC64_GOT_DTPREL16_LO_DS: u32 = 92;
/// `#hi(@got@dtprel)`
pub const R_PPC64_GOT_DTPREL16_HI: u32 = 93;
/// `#ha(@got@dtprel)`
pub const R_PPC64_GOT_DTPREL16_HA: u32 = 94;
/// `@tprel`
pub const R_PPC64_TPREL16_DS: u32 = 95;
/// `#lo(@tprel)`
pub const R_PPC64_TPREL16_LO_DS: u32 = 96;
/// `#higher(@tprel)`
pub const R_PPC64_TPREL16_HIGHER: u32 = 97;
/// `#highera(@tprel)`
pub const R_PPC64_TPREL16_HIGHERA: u32 = 98;
/// `#highest(@tprel)`
pub const R_PPC64_TPREL16_HIGHEST: u32 = 99;
/// `#highesta(@tprel)`
pub const R_PPC64_TPREL16_HIGHESTA: u32 = 100;
/// `@dtprel`
pub const R_PPC64_DTPREL16_DS: u32 = 101;
/// `#lo(@dtprel)`
pub const R_PPC64_DTPREL16_LO_DS: u32 = 102;
/// `#higher(@dtprel)`
pub const R_PPC64_DTPREL16_HIGHER: u32 = 103;
/// `#highera(@dtprel)`
pub const R_PPC64_DTPREL16_HIGHERA: u32 = 104;
/// `#highest(@dtprel)`
pub const R_PPC64_DTPREL16_HIGHEST: u32 = 105;
/// `#highesta(@dtprel)`
pub const R_PPC64_DTPREL16_HIGHESTA: u32 = 106;
/// `(sym+add)@tlsgd`
pub const R_PPC64_TLSGD: u32 = 107;
/// `(sym+add)@tlsld`
pub const R_PPC64_TLSLD: u32 = 108;
pub const R_PPC64_TOCSAVE: u32 = 109;
pub const R_PPC64_ADDR16_HIGH: u32 = 110;
pub const R_PPC64_ADDR16_HIGHA: u32 = 111;
pub const R_PPC64_TPREL16_HIGH: u32 = 112;
pub const R_PPC64_TPREL16_HIGHA: u32 = 113;
pub const R_PPC64_DTPREL16_HIGH: u32 = 114;
pub const R_PPC64_DTPREL16_HIGHA: u32 = 115;

// GNU extension to support local ifunc.
pub const R_PPC64_JMP_IREL: u32 = 247;
pub const R_PPC64_IRELATIVE: u32 = 248;
/// `(sym+add-.)`
pub const R_PPC64_REL16: u32 = 249;
/// `(sym+add-.)@l`
pub const R_PPC64_REL16_LO: u32 = 250;
/// `(sym+add-.)@h`
pub const R_PPC64_REL16_HI: u32 = 251;
/// `(sym+add-.)@ha`
pub const R_PPC64_REL16_HA: u32 = 252;

//  ____  ___ ____   ____   __     __
// |  _ \|_ _/ ___| / ___|  \ \   / /
// | |_) || |\___ \| |   ____\ \ / /
// |  _ < | | ___) | |__|_____\ V /
// |_| \_\___|____/ \____|     \_/
//
// See: https://github.com/riscv-non-isa/riscv-elf-psabi-doc

/// This bit is set when the binary targets the C ABI.
pub const EF_RISCV_RVC: u32 = 0x0001;
pub const EF_RISCV_FLOAT_ABI_SOFT: u32 = 0x0000;
pub const EF_RISCV_FLOAT_ABI_SINGLE: u32 = 0x0002;
pub const EF_RISCV_FLOAT_ABI_DOUBLE: u32 = 0x0004;
pub const EF_RISCV_FLOAT_ABI_QUAD: u32 = 0x0006;
/// This is used as a mask to test for one of the above floating-point ABIs,
/// e.g., (e_flags & EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_DOUBLE.
pub const EF_RISCV_FLOAT_ABI_MASK: u32 = 0x0006;
/// This bit is set when the binary targets the E ABI.
pub const EF_RISCV_RVE: u32 = 0x0008;
/// This bit is set when the binary requires the RVTSO memory consistency model.
pub const EF_RISCV_TSO: u32 = 0x0010;

pub const SHT_RISCV_ATTRIBUTES: u32 = 0x70000003; // SHT_LOPROC + 3;
pub const SHT_RISCV_ATTRIBUTES_SECTION_NAME: &str = ".riscv.attributes";

pub const PT_RISCV_ATTRIBUTES: u32 = 0x70000003;

/// Any functions that use registers in a way that is incompatible with the
/// calling convention of the ABI in use must be annotated with STO_RISCV_VARIANT_CC
pub const STO_RISCV_VARIANT_CC: u8 = 0x80;

/// An object must have the dynamic tag DT_RISCV_VARIANT_CC if it has one or more R_RISCV_JUMP_SLOT
/// relocations against symbols with the STO_RISCV_VARIANT_CC attribute.
pub const DT_RISCV_VARIANT_CC: i64 = 0x70000001;

// RISC-V relocation types
//
// A Addend field in the relocation entry associated with the symbol
// B Base address of a shared object loaded into memory
// G Offset of the symbol into the GOT (Global Offset Table)
// GOT Address of the GOT (Global Offset Table)
// P Position of the relocation
// S Value of the symbol in the symbol table
// V Value at the position of the relocation
// GP Value of __global_pointer$ symbol
// TLSMODULE TLS module index for the object containing the symbol
// TLSOFFSET TLS static block offset (relative to tp) for the object containing the symbol

pub const R_RISCV_NONE: u32 = 0;
/// 32-bit relocation: `S + A`
pub const R_RISCV_32: u32 = 1;
/// 64-bit relocation: `S + A`
pub const R_RISCV_64: u32 = 2;
/// Adjust a link address (A) to its load address: `(B + A).`
pub const R_RISCV_RELATIVE: u32 = 3;
/// Must be in executable; not allowed in shared library
pub const R_RISCV_COPY: u32 = 4;
/// Indicates the symbol associated with a PLT entry: `S`
pub const R_RISCV_JUMP_SLOT: u32 = 5;
/// `TLSMODULE`
pub const R_RISCV_TLS_DTPMOD32: u32 = 6;
/// `TLSMODULE`
pub const R_RISCV_TLS_DTPMOD64: u32 = 7;
/// `S + A - TLS_DTV_OFFSET`
pub const R_RISCV_TLS_DTPREL32: u32 = 8;
/// `S + A - TLS_DTV_OFFSET`
pub const R_RISCV_TLS_DTPREL64: u32 = 9;
/// `S + A + TLSOFFSET`
pub const R_RISCV_TLS_TPREL32: u32 = 10;
/// `S + A + TLSOFFSET`
pub const R_RISCV_TLS_TPREL64: u32 = 11;
/// 12-bit PC-relative branch offset `S + A - P`
pub const R_RISCV_BRANCH: u32 = 16;
/// 20-bit PC-relative jump offset `S + A - P`
pub const R_RISCV_JAL: u32 = 17;
/// Deprecated, please use CALL_PLT instead 32-bit PC-relative function call, macros call, tail: `S + A - P`
pub const R_RISCV_CALL: u32 = 18;
/// 32-bit PC-relative function call, macros call, tail (PIC): `S + A - P`
pub const R_RISCV_CALL_PLT: u32 = 19;
/// High 20 bits of 32-bit PC-relative GOT access, %got_pcrel_hi(symbol): `G + GOT + A - P`
pub const R_RISCV_GOT_HI20: u32 = 20;
/// High 20 bits of 32-bit PC-relative TLS IE GOT access, macro la.tls.ie
pub const R_RISCV_TLS_GOT_HI20: u32 = 21;
/// High 20 bits of 32-bit PC-relative TLS GD GOT reference, macro la.tls.gd
pub const R_RISCV_TLS_GD_HI20: u32 = 22;
/// High 20 bits of 32-bit PC-relative reference, %pcrel_hi(symbol): `S + A - P`
pub const R_RISCV_PCREL_HI20: u32 = 23;
/// Low 12 bits of a 32-bit PC-relative, %pcrel_lo(address of %pcrel_hi), the addend must be 0: `S - P`
pub const R_RISCV_PCREL_LO12_I: u32 = 24;
/// Low 12 bits of a 32-bit PC-relative, %pcrel_lo(address of %pcrel_hi), the addend must be 0: `S - P`
pub const R_RISCV_PCREL_LO12_S: u32 = 25;
/// High 20 bits of 32-bit absolute address, %hi(symbol): `S + A`
pub const R_RISCV_HI20: u32 = 26;
/// Low 12 bits of 32-bit absolute address, %lo(symbol): `S + A`
pub const R_RISCV_LO12_I: u32 = 27;
/// Low 12 bits of 32-bit absolute address, %lo(symbol): `S + A`
pub const R_RISCV_LO12_S: u32 = 28;
/// High 20 bits of TLS LE thread pointer offset, `%tprel_hi(symbol)`
pub const R_RISCV_TPREL_HI20: u32 = 29;
/// Low 12 bits of TLS LE thread pointer offset, `%tprel_lo(symbol)`
pub const R_RISCV_TPREL_LO12_I: u32 = 30;
/// Low 12 bits of TLS LE thread pointer offset, `%tprel_lo(symbol)`
pub const R_RISCV_TPREL_LO12_S: u32 = 31;
/// TLS LE thread pointer usage, `%tprel_add(symbol)`
pub const R_RISCV_TPREL_ADD: u32 = 32;
/// 8-bit label addition: `V + S + A`
pub const R_RISCV_ADD8: u32 = 33;
/// 16-bit label addition: `V + S + A`
pub const R_RISCV_ADD16: u32 = 34;
/// 32-bit label addition: `V + S + A`
pub const R_RISCV_ADD32: u32 = 35;
/// 64-bit label addition: `V + S + A`
pub const R_RISCV_ADD64: u32 = 36;
/// 8-bit label subtraction: `V - S - A`
pub const R_RISCV_SUB8: u32 = 37;
/// 16-bit label subtraction: `V - S - A`
pub const R_RISCV_SUB16: u32 = 38;
/// 32-bit label subtraction: `V - S - A`
pub const R_RISCV_SUB32: u32 = 39;
/// 64-bit label subtraction: `V - S - A`
pub const R_RISCV_SUB64: u32 = 40;
/// Alignment statement. The addend indicates the number of bytes occupied by
/// nop instructions at the relocation offset. The alignment boundary is
/// specified by the addend rounded up to the next power of two.
pub const R_RISCV_ALIGN: u32 = 43;
/// 8-bit PC-relative branch offset: `S + A - P`
pub const R_RISCV_RVC_BRANCH: u32 = 44;
/// 11-bit PC-relative jump offset: `S + A - P`
pub const R_RISCV_RVC_JUMP: u32 = 45;
/// High 6 bits of 18-bit absolute address: `S + A`
pub const R_RISCV_RVC_LUI: u32 = 46;
/// Instruction can be relaxed, paired with a normal relocation at the same address
pub const R_RISCV_RELAX: u32 = 51;
/// Local label subtraction: `V - S - A`
pub const R_RISCV_SUB6: u32 = 52;
/// Local label assignment: `S + A`
pub const R_RISCV_SET6: u32 = 53;
/// Local label assignment: `S + A`
pub const R_RISCV_SET8: u32 = 54;
/// Local label assignment: `S + A`
pub const R_RISCV_SET16: u32 = 55;
/// Local label assignment: `S + A`
pub const R_RISCV_SET32: u32 = 56;
/// 32-bit PC relative: `S + A - P`
pub const R_RISCV_32_PCREL: u32 = 57;
/// Relocation against a non-preemptible ifunc symbolifunc_resolver: `(B + A)`
pub const R_RISCV_IRELATIVE: u32 = 58;

//       ___   __      __   _  _
// __  _( _ ) / /_    / /_ | || |
// \ \/ / _ \| '_ \  | '_ \| || |_
//  >  < (_) | (_) | | (_) |__   _|
// /_/\_\___/ \___/___\___/   |_|
//              |_____|
//
// See: https://gitlab.com/x86-psABIs/x86-64-ABI

/// If an object file section does not have this flag set, then it may not hold
/// more than 2GB and can be freely referred to in objects using smaller code models.
pub const SHF_X86_64_LARGE: u64 = 0x10000000;

/// This section contains unwind function table entries for stack unwinding.
pub const SHT_X86_64_UNWIND: u32 = 0x70000001; // SHT_LOPROC + 1;

// x86_64 reloc types
//
// A Represents the addend used to compute the value of the relocatable field.
// B Represents the base address at which a shared object has been loaded into memory
//     during execution. Generally, a shared object is built with a 0 base virtual address,
//     but the execution address will be different.
// G Represents the offset into the global offset table at which the relocation entry’s symbol
//     will reside during execution.
// GOT Represents the address of the global offset table.
// L Represents the place (section offset or address) of the Procedure Linkage Table entry for a symbol.
// P Represents the place (section offset or address) of the storage unit being relocated (computed using r_offset).
// S Represents the value of the symbol whose index resides in the relocation entry.
// Z Represents the size of the symbol whose index resides in the relocation entry.

pub const R_X86_64_NONE: u32 = 0;
/// `S + A`
pub const R_X86_64_64: u32 = 1;
/// `S + A - P`
pub const R_X86_64_PC32: u32 = 2;
/// `G + A`
pub const R_X86_64_GOT32: u32 = 3;
/// `L + A - P`
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
/// `S`
pub const R_X86_64_GLOB_DAT: u32 = 6;
/// `S`
pub const R_X86_64_JUMP_SLOT: u32 = 7;
/// `B + A`
pub const R_X86_64_RELATIVE: u32 = 8;
/// `G + GOT + A - P`
pub const R_X86_64_GOTPCREL: u32 = 9;
/// `S + A`
pub const R_X86_64_32: u32 = 10;
/// `S + A`
pub const R_X86_64_32S: u32 = 11;
/// `S + A`
pub const R_X86_64_16: u32 = 12;
/// `S + A - P`
pub const R_X86_64_PC16: u32 = 13;
/// `S + A`
pub const R_X86_64_8: u32 = 14;
/// `S + A - P`
pub const R_X86_64_PC8: u32 = 15;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_TLSGD: u32 = 19;
pub const R_X86_64_TLSLD: u32 = 20;
pub const R_X86_64_DTPOFF32: u32 = 21;
pub const R_X86_64_GOTTPOFF: u32 = 22;
pub const R_X86_64_TPOFF32: u32 = 23;
/// `S + A - P`
pub const R_X86_64_PC64: u32 = 24;
/// `S + A - GOT`
pub const R_X86_64_GOTOFF64: u32 = 25;
/// `GOT + A - P`
pub const R_X86_64_GOTPC32: u32 = 26;
/// `G + A`
pub const R_X86_64_GOT64: u32 = 27;
/// `G + GOT - P + A`
pub const R_X86_64_GOTPCREL64: u32 = 28;
/// `GOT - P + A`
pub const R_X86_64_GOTPC64: u32 = 29;
/// `L - GOT + A`
pub const R_X86_64_PLTOFF64: u32 = 31;
/// `Z + A`
pub const R_X86_64_SIZE32: u32 = 32;
/// `Z + A`
pub const R_X86_64_SIZE64: u32 = 33;
pub const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
pub const R_X86_64_TLSDESC_CALL: u32 = 35;
pub const R_X86_64_TLSDESC: u32 = 36;
/// `indirect (B + A)`
pub const R_X86_64_IRELATIVE: u32 = 37;
/// `B + A`
pub const R_X86_64_RELATIVE64: u32 = 38;
/// `G + GOT + A - P`
pub const R_X86_64_GOTPCRELX: u32 = 41;
/// `G + GOT + A - P`
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;
