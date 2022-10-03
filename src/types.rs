use std::fmt;

/// Length of ELF file header platform-independent identification fields
pub const EI_NIDENT: usize = 16;
/// ELF magic number byte 1
pub const ELFMAG0: u8 = 0x7f;
/// ELF magic number byte 2
pub const ELFMAG1: u8 = 0x45;
/// ELF magic number byte 3
pub const ELFMAG2: u8 = 0x4c;
/// ELF magic number byte 4
pub const ELFMAG3: u8 = 0x46;
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

/// Represents the ELF file class (32-bit vs 64-bit)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Class(pub u8);
/// Invalid ELF file class
pub const ELFCLASSNONE : Class = Class(0);
/// 32-bit ELF file
pub const ELFCLASS32 : Class = Class(1);
/// 64-bit ELF file
pub const ELFCLASS64 : Class = Class(2);

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFCLASSNONE => "Invalid",
            ELFCLASS32 => "32-bit",
            ELFCLASS64 => "64-bit",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Data(pub u8);
/// Invalid ELF data format
pub const ELFDATANONE : Data = Data(0);
/// little-endian ELF file
pub const ELFDATA2LSB : Data = Data(1);
/// big-endian ELF file
pub const ELFDATA2MSB : Data = Data(2);

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFDATANONE => "Invalid",
            ELFDATA2LSB => "2's complement, little endian",
            ELFDATA2MSB => "2's complement, big endian",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file version
///
/// This field represents the values both found in the e_ident byte array and the e_version field.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Version(pub u32);
/// Invalid version
pub const EV_NONE : Version = Version(0);
/// Current version
pub const EV_CURRENT : Version = Version(1);

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            EV_NONE => "Invalid",
            EV_CURRENT => "1 (Current)",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file OS ABI
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OSABI(pub u8);
/// Defaults to Unix System V
pub const ELFOSABI_NONE : OSABI = OSABI(0);
/// Unix System V
pub const ELFOSABI_SYSV : OSABI = OSABI(0);
/// HP-UX
pub const ELFOSABI_HPUX : OSABI = OSABI(1);
/// NetBSD
pub const ELFOSABI_NETBSD : OSABI = OSABI(2);
/// Linux with GNU extensions
pub const ELFOSABI_LINUX : OSABI = OSABI(3);
/// Solaris
pub const ELFOSABI_SOLARIS : OSABI = OSABI(6);
/// AIX
pub const ELFOSABI_AIX : OSABI = OSABI(7);
/// SGI Irix
pub const ELFOSABI_IRIX : OSABI = OSABI(8);
/// FreeBSD
pub const ELFOSABI_FREEBSD : OSABI = OSABI(9);
/// Compaq TRU64 UNIX
pub const ELFOSABI_TRU64 : OSABI = OSABI(10);
/// Novell Modesto
pub const ELFOSABI_MODESTO : OSABI = OSABI(11);
/// OpenBSD
pub const ELFOSABI_OPENBSD : OSABI = OSABI(12);

impl fmt::Debug for OSABI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for OSABI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ELFOSABI_SYSV => "UNIX System V",
            ELFOSABI_HPUX => "HP-UX",
            ELFOSABI_NETBSD => "NetBSD",
            ELFOSABI_LINUX => "Linux with GNU extensions",
            ELFOSABI_SOLARIS => "Solaris",
            ELFOSABI_AIX => "AIX",
            ELFOSABI_IRIX => "SGI Irix",
            ELFOSABI_FREEBSD => "FreeBSD",
            ELFOSABI_TRU64 => "Compaq TRU64 UNIX",
            ELFOSABI_MODESTO => "Novell Modesto",
            ELFOSABI_OPENBSD => "OpenBSD",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file type (object, executable, shared lib, core)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Type(pub u16);
/// No file type
pub const ET_NONE : Type = Type(0);
/// Relocatable object file
pub const ET_REL : Type = Type(1);
/// Executable file
pub const ET_EXEC : Type = Type(2);
/// Shared library
pub const ET_DYN : Type = Type(3);
/// Core file
pub const ET_CORE : Type = Type(4);

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            ET_NONE => "No file type",
            ET_REL => "Relocatable file",
            ET_EXEC => "Executable file",
            ET_DYN => "Shared object file",
            ET_CORE => "Core file",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file machine architecture
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Machine(pub u16);
pub const EM_NONE: Machine = Machine(0); // No machine
pub const EM_M32: Machine = Machine(1); // AT&T WE 32100
pub const EM_SPARC: Machine = Machine(2); // SPARC
pub const EM_386: Machine = Machine(3); // Intel 80386
pub const EM_68K: Machine = Machine(4); // Motorola 68000
pub const EM_88K: Machine = Machine(5); // Motorola 88000
pub const EM_IAMCU: Machine = Machine(6); // Intel MCU
pub const EM_860: Machine = Machine(7); // Intel 80860
pub const EM_MIPS: Machine = Machine(8); // MIPS I Architecture
pub const EM_S370: Machine = Machine(9); // IBM System/370 Processor
pub const EM_MIPS_RS3_LE: Machine = Machine(10); // MIPS RS3000 Little-endian
// 11-14 Reserved for future use
pub const EM_PARISC: Machine = Machine(15); // Hewlett-Packard PA-RISC
// 16 Reserved for future use
pub const EM_VPP500: Machine = Machine(17); // Fujitsu VPP500
pub const EM_SPARC32PLUS: Machine = Machine(18); // Enhanced instruction set SPARC
pub const EM_960: Machine = Machine(19); // Intel 80960
pub const EM_PPC: Machine = Machine(20); // PowerPC
pub const EM_PPC64: Machine = Machine(21); // 64-bit PowerPC
pub const EM_S390: Machine = Machine(22); // IBM System/390 Processor
pub const EM_SPU: Machine = Machine(23); // IBM SPU/SPC
// 24-35 Reserved for future use
pub const EM_V800: Machine = Machine(36); // NEC V800
pub const EM_FR20: Machine = Machine(37); // Fujitsu FR20
pub const EM_RH32: Machine = Machine(38); // TRW RH-32
pub const EM_RCE: Machine = Machine(39); // Motorola RCE
pub const EM_ARM: Machine = Machine(40); // ARM 32-bit architecture (AARCH32)
pub const EM_ALPHA: Machine = Machine(41); // Digital Alpha
pub const EM_SH: Machine = Machine(42); // Hitachi SH
pub const EM_SPARCV9: Machine = Machine(43); // SPARC Version 9
pub const EM_TRICORE: Machine = Machine(44); // Siemens TriCore embedded processor
pub const EM_ARC: Machine = Machine(45); // Argonaut RISC Core, Argonaut Technologies Inc.
pub const EM_H8_300: Machine = Machine(46); // Hitachi H8/300
pub const EM_H8_300H: Machine = Machine(47); // Hitachi H8/300H
pub const EM_H8S: Machine = Machine(48); // Hitachi H8S
pub const EM_H8_500: Machine = Machine(49); // Hitachi H8/500
pub const EM_IA_64: Machine = Machine(50); // Intel IA-64 processor architecture
pub const EM_MIPS_X: Machine = Machine(51); // Stanford MIPS-X
pub const EM_COLDFIRE: Machine = Machine(52); // Motorola ColdFire
pub const EM_68HC12: Machine = Machine(53); // Motorola M68HC12
pub const EM_MMA: Machine = Machine(54); // Fujitsu MMA Multimedia Accelerator
pub const EM_PCP: Machine = Machine(55); // Siemens PCP
pub const EM_NCPU: Machine = Machine(56); // Sony nCPU embedded RISC processor
pub const EM_NDR1: Machine = Machine(57); // Denso NDR1 microprocessor
pub const EM_STARCORE: Machine = Machine(58); // Motorola Star*Core processor
pub const EM_ME16: Machine = Machine(59); // Toyota ME16 processor
pub const EM_ST100: Machine = Machine(60); // STMicroelectronics ST100 processor
pub const EM_TINYJ: Machine = Machine(61); // Advanced Logic Corp. TinyJ embedded processor family
pub const EM_X86_64: Machine = Machine(62); // AMD x86-64 architecture
pub const EM_PDSP: Machine = Machine(63); // Sony DSP Processor
pub const EM_PDP10: Machine = Machine(64); // Digital Equipment Corp. PDP-10
pub const EM_PDP11: Machine = Machine(65); // Digital Equipment Corp. PDP-11
pub const EM_FX66: Machine = Machine(66); // Siemens FX66 microcontroller
pub const EM_ST9PLUS: Machine = Machine(67); // STMicroelectronics ST9+ 8/16 bit microcontroller
pub const EM_ST7: Machine = Machine(68); // STMicroelectronics ST7 8-bit microcontroller
pub const EM_68HC16: Machine = Machine(69); // Motorola MC68HC16 Microcontroller
pub const EM_68HC11: Machine = Machine(70); // Motorola MC68HC11 Microcontroller
pub const EM_68HC08: Machine = Machine(71); // Motorola MC68HC08 Microcontroller
pub const EM_68HC05: Machine = Machine(72); // Motorola MC68HC05 Microcontroller
pub const EM_SVX: Machine = Machine(73); // Silicon Graphics SVx
pub const EM_ST19: Machine = Machine(74); // STMicroelectronics ST19 8-bit microcontroller
pub const EM_VAX: Machine = Machine(75); // Digital VAX
pub const EM_CRIS: Machine = Machine(76); // Axis Communications 32-bit embedded processor
pub const EM_JAVELIN: Machine = Machine(77); // Infineon Technologies 32-bit embedded processor
pub const EM_FIREPATH: Machine = Machine(78); // Element 14 64-bit DSP Processor
pub const EM_ZSP: Machine = Machine(79); // LSI Logic 16-bit DSP Processor
pub const EM_MMIX: Machine = Machine(80); // Donald Knuth's educational 64-bit processor
pub const EM_HUANY: Machine = Machine(81); // Harvard University machine-independent object files
pub const EM_PRISM: Machine = Machine(82); // SiTera Prism
pub const EM_AVR: Machine = Machine(83); // Atmel AVR 8-bit microcontroller
pub const EM_FR30: Machine = Machine(84); // Fujitsu FR30
pub const EM_D10V: Machine = Machine(85); // Mitsubishi D10V
pub const EM_D30V: Machine = Machine(86); // Mitsubishi D30V
pub const EM_V850: Machine = Machine(87); // NEC v850
pub const EM_M32R: Machine = Machine(88); // Mitsubishi M32R
pub const EM_MN10300: Machine = Machine(89); // Matsushita MN10300
pub const EM_MN10200: Machine = Machine(90); // Matsushita MN10200
pub const EM_PJ: Machine = Machine(91); // picoJava
pub const EM_OPENRISC: Machine = Machine(92); // OpenRISC 32-bit embedded processor
pub const EM_ARC_COMPACT: Machine = Machine(93); // ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
pub const EM_XTENSA: Machine = Machine(94); // Tensilica Xtensa Architecture
pub const EM_VIDEOCORE: Machine = Machine(95); // Alphamosaic VideoCore processor
pub const EM_TMM_GPP: Machine = Machine(96); // Thompson Multimedia General Purpose Processor
pub const EM_NS32K: Machine = Machine(97); // National Semiconductor 32000 series
pub const EM_TPC: Machine = Machine(98); // Tenor Network TPC processor
pub const EM_SNP1K: Machine = Machine(99); // Trebia SNP 1000 processor
pub const EM_ST200: Machine = Machine(100); // STMicroelectronics (www.st.com) ST200 microcontroller
pub const EM_IP2K: Machine = Machine(101); // Ubicom IP2xxx microcontroller family
pub const EM_MAX: Machine = Machine(102); // MAX Processor
pub const EM_CR: Machine = Machine(103); // National Semiconductor CompactRISC microprocessor
pub const EM_F2MC16: Machine = Machine(104); // Fujitsu F2MC16
pub const EM_MSP430: Machine = Machine(105); // Texas Instruments embedded microcontroller msp430
pub const EM_BLACKFIN: Machine = Machine(106); // Analog Devices Blackfin (DSP) processor
pub const EM_SE_C33: Machine = Machine(107); // S1C33 Family of Seiko Epson processors
pub const EM_SEP: Machine = Machine(108); // Sharp embedded microprocessor
pub const EM_ARCA: Machine = Machine(109); // Arca RISC Microprocessor
pub const EM_UNICORE: Machine = Machine(110); // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
pub const EM_EXCESS: Machine = Machine(111); // eXcess: 16/32/64-bit configurable embedded CPU
pub const EM_DXP: Machine = Machine(112); // Icera Semiconductor Inc. Deep Execution Processor
pub const EM_ALTERA_NIOS2: Machine = Machine(113); // Altera Nios II soft-core processor
pub const EM_CRX: Machine = Machine(114); // National Semiconductor CompactRISC CRX microprocessor
pub const EM_XGATE: Machine = Machine(115); // Motorola XGATE embedded processor
pub const EM_C166: Machine = Machine(116); // Infineon C16x/XC16x processor
pub const EM_M16C: Machine = Machine(117); // Renesas M16C series microprocessors
pub const EM_DSPIC30F: Machine = Machine(118); // Microchip Technology dsPIC30F Digital Signal Controller
pub const EM_CE: Machine = Machine(119); // Freescale Communication Engine RISC core
pub const EM_M32C: Machine = Machine(120); // Renesas M32C series microprocessors
// 121-130 Reserved for future use
pub const EM_TSK3000: Machine = Machine(131); // Altium TSK3000 core
pub const EM_RS08: Machine = Machine(132); // Freescale RS08 embedded processor
pub const EM_SHARC: Machine = Machine(133); // Analog Devices SHARC family of 32-bit DSP processors
pub const EM_ECOG2: Machine = Machine(134); // Cyan Technology eCOG2 microprocessor
pub const EM_SCORE7: Machine = Machine(135); // Sunplus S+core7 RISC processor
pub const EM_DSP24: Machine = Machine(136); // New Japan Radio (NJR) 24-bit DSP Processor
pub const EM_VIDEOCORE3: Machine = Machine(137); // Broadcom VideoCore III processor
pub const EM_LATTICEMICO32: Machine = Machine(138); // RISC processor for Lattice FPGA architecture
pub const EM_SE_C17: Machine = Machine(139); // Seiko Epson C17 family
pub const EM_TI_C6000: Machine = Machine(140); // The Texas Instruments TMS320C6000 DSP family
pub const EM_TI_C2000: Machine = Machine(141); // The Texas Instruments TMS320C2000 DSP family
pub const EM_TI_C5500: Machine = Machine(142); // The Texas Instruments TMS320C55x DSP family
pub const EM_TI_ARP32: Machine = Machine(143); // Texas Instruments Application Specific RISC Processor, 32bit fetch
pub const EM_TI_PRU: Machine = Machine(144); // Texas Instruments Programmable Realtime Unit
// 145-159 Reserved for future use
pub const EM_MMDSP_PLUS: Machine = Machine(160); // STMicroelectronics 64bit VLIW Data Signal Processor
pub const EM_CYPRESS_M8C: Machine = Machine(161); // Cypress M8C microprocessor
pub const EM_R32C: Machine = Machine(162); // Renesas R32C series microprocessors
pub const EM_TRIMEDIA: Machine = Machine(163); // NXP Semiconductors TriMedia architecture family
pub const EM_QDSP6: Machine = Machine(164); // QUALCOMM DSP6 Processor
pub const EM_8051: Machine = Machine(165); // Intel 8051 and variants
pub const EM_STXP7X: Machine = Machine(166); // STMicroelectronics STxP7x family of configurable and extensible RISC processors
pub const EM_NDS32: Machine = Machine(167); // Andes Technology compact code size embedded RISC processor family
pub const EM_ECOG1: Machine = Machine(168); // Cyan Technology eCOG1X family
pub const EM_ECOG1X: Machine = Machine(168); // Cyan Technology eCOG1X family
pub const EM_MAXQ30: Machine = Machine(169); // Dallas Semiconductor MAXQ30 Core Micro-controllers
pub const EM_XIMO16: Machine = Machine(170); // New Japan Radio (NJR) 16-bit DSP Processor
pub const EM_MANIK: Machine = Machine(171); // M2000 Reconfigurable RISC Microprocessor
pub const EM_CRAYNV2: Machine = Machine(172); // Cray Inc. NV2 vector architecture
pub const EM_RX: Machine = Machine(173); // Renesas RX family
pub const EM_METAG: Machine = Machine(174); // Imagination Technologies META processor architecture
pub const EM_MCST_ELBRUS: Machine = Machine(175); // MCST Elbrus general purpose hardware architecture
pub const EM_ECOG16: Machine = Machine(176); // Cyan Technology eCOG16 family
pub const EM_CR16: Machine = Machine(177); // National Semiconductor CompactRISC CR16 16-bit microprocessor
pub const EM_ETPU: Machine = Machine(178); // Freescale Extended Time Processing Unit
pub const EM_SLE9X: Machine = Machine(179); // Infineon Technologies SLE9X core
pub const EM_L10M: Machine = Machine(180); // Intel L10M
pub const EM_K10M: Machine = Machine(181); // Intel K10M
// 182 Reserved for future Intel use
pub const EM_AARCH64: Machine = Machine(183); // ARM 64-bit architecture (AARCH64)
// 184 Reserved for future ARM use
pub const EM_AVR32: Machine = Machine(185); // Atmel Corporation 32-bit microprocessor family
pub const EM_STM8: Machine = Machine(186); // STMicroeletronics STM8 8-bit microcontroller
pub const EM_TILE64: Machine = Machine(187); // Tilera TILE64 multicore architecture family
pub const EM_TILEPRO: Machine = Machine(188); // Tilera TILEPro multicore architecture family
pub const EM_MICROBLAZE: Machine = Machine(189); // Xilinx MicroBlaze 32-bit RISC soft processor core
pub const EM_CUDA: Machine = Machine(190); // NVIDIA CUDA architecture
pub const EM_TILEGX: Machine = Machine(191); // Tilera TILE-Gx multicore architecture family
pub const EM_CLOUDSHIELD: Machine = Machine(192); // CloudShield architecture family
pub const EM_COREA_1ST: Machine = Machine(193); // KIPO-KAIST Core-A 1st generation processor family
pub const EM_COREA_2ND: Machine = Machine(194); // KIPO-KAIST Core-A 2nd generation processor family
pub const EM_ARC_COMPACT2: Machine = Machine(195); // Synopsys ARCompact V2
pub const EM_OPEN8: Machine = Machine(196); // Open8 8-bit RISC soft processor core
pub const EM_RL78: Machine = Machine(197); // Renesas RL78 family
pub const EM_VIDEOCORE5: Machine = Machine(198); // Broadcom VideoCore V processor
pub const EM_78KOR: Machine = Machine(199); // Renesas 78KOR family
pub const EM_56800EX: Machine = Machine(200); // Freescale 56800EX Digital Signal Controller (DSC)
pub const EM_BA1: Machine = Machine(201); // Beyond BA1 CPU architecture
pub const EM_BA2: Machine = Machine(202); // Beyond BA2 CPU architecture
pub const EM_XCORE: Machine = Machine(203); // XMOS xCORE processor family
pub const EM_MCHP_PIC: Machine = Machine(204); // Microchip 8-bit PIC(r) family
pub const EM_INTEL205: Machine = Machine(205); // Reserved by Intel
pub const EM_INTEL206: Machine = Machine(206); // Reserved by Intel
pub const EM_INTEL207: Machine = Machine(207); // Reserved by Intel
pub const EM_INTEL208: Machine = Machine(208); // Reserved by Intel
pub const EM_INTEL209: Machine = Machine(209); // Reserved by Intel
pub const EM_KM32: Machine = Machine(210); // KM211 KM32 32-bit processor
pub const EM_KMX32: Machine = Machine(211); // KM211 KMX32 32-bit processor
pub const EM_KMX16: Machine = Machine(212); // KM211 KMX16 16-bit processor
pub const EM_KMX8: Machine = Machine(213); // KM211 KMX8 8-bit processor
pub const EM_KVARC: Machine = Machine(214); // KM211 KVARC processor
pub const EM_CDP: Machine = Machine(215); // Paneve CDP architecture family
pub const EM_COGE: Machine = Machine(216); // Cognitive Smart Memory Processor
pub const EM_COOL: Machine = Machine(217); // Bluechip Systems CoolEngine
pub const EM_NORC: Machine = Machine(218); // Nanoradio Optimized RISC
pub const EM_CSR_KALIMBA: Machine = Machine(219); // CSR Kalimba architecture family
pub const EM_Z80: Machine = Machine(220); // Zilog Z80
pub const EM_VISIUM: Machine = Machine(221); // Controls and Data Services VISIUMcore processor
pub const EM_FT32: Machine = Machine(222); // FTDI Chip FT32 high performance 32-bit RISC architecture
pub const EM_MOXIE: Machine = Machine(223); // Moxie processor family
pub const EM_AMDGPU: Machine = Machine(224); // AMD GPU architecture
pub const EM_RISCV: Machine = Machine(243); // RISC-V
pub const EM_BPF: Machine = Machine(247); // Linux BPF

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            EM_NONE => "No machine",
            EM_M32 => "AT&T WE 32100",
            EM_SPARC => "SPARC",
            EM_386 => "Intel 80386",
            EM_68K => "Motorola 68000",
            EM_88K => "Motorola 88000",
            EM_IAMCU => "Intel MCU",
            EM_860 => "Intel 80860",
            EM_MIPS => "MIPS I Architecture",
            EM_S370 => "IBM System/370 Processor",
            EM_MIPS_RS3_LE => "MIPS RS3000 Little-endian",
            EM_PARISC => "Hewlett-Packard PA-RISC",
            EM_VPP500 => "Fujitsu VPP500",
            EM_SPARC32PLUS => "Enhanced instruction set SPARC",
            EM_960 => "Intel 80960",
            EM_PPC => "PowerPC",
            EM_PPC64 => "64-bit PowerPC",
            EM_S390 => "IBM System/390 Processor",
            EM_SPU => "IBM SPU/SPC",
            EM_V800 => "NEC V800",
            EM_FR20 => "Fujitsu FR20",
            EM_RH32 => "TRW RH-32",
            EM_RCE => "Motorola RCE",
            EM_ARM => "ARM 32-bit architecture (AARCH32)",
            EM_ALPHA => "Digital Alpha",
            EM_SH => "Hitachi SH",
            EM_SPARCV9 => "SPARC Version 9",
            EM_TRICORE => "Siemens TriCore embedded processor",
            EM_ARC => "Argonaut RISC Core, Argonaut Technologies Inc.",
            EM_H8_300 => "Hitachi H8/300",
            EM_H8_300H => "Hitachi H8/300H",
            EM_H8S => "Hitachi H8S",
            EM_H8_500 => "Hitachi H8/500",
            EM_IA_64 => "Intel IA-64 processor architecture",
            EM_MIPS_X => "Stanford MIPS-X",
            EM_COLDFIRE => "Motorola ColdFire",
            EM_68HC12 => "Motorola M68HC12",
            EM_MMA => "Fujitsu MMA Multimedia Accelerator",
            EM_PCP => "Siemens PCP",
            EM_NCPU => "Sony nCPU embedded RISC processor",
            EM_NDR1 => "Denso NDR1 microprocessor",
            EM_STARCORE => "Motorola Star*Core processor",
            EM_ME16 => "Toyota ME16 processor",
            EM_ST100 => "STMicroelectronics ST100 processor",
            EM_TINYJ => "Advanced Logic Corp. TinyJ embedded processor family",
            EM_X86_64 => "AMD x86-64 architecture",
            EM_PDSP => "Sony DSP Processor",
            EM_PDP10 => "Digital Equipment Corp. PDP-10",
            EM_PDP11 => "Digital Equipment Corp. PDP-11",
            EM_FX66 => "Siemens FX66 microcontroller",
            EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 bit microcontroller",
            EM_ST7 => "STMicroelectronics ST7 8-bit microcontroller",
            EM_68HC16 => "Motorola MC68HC16 Microcontroller",
            EM_68HC11 => "Motorola MC68HC11 Microcontroller",
            EM_68HC08 => "Motorola MC68HC08 Microcontroller",
            EM_68HC05 => "Motorola MC68HC05 Microcontroller",
            EM_SVX => "Silicon Graphics SVx",
            EM_ST19 => "STMicroelectronics ST19 8-bit microcontroller",
            EM_VAX => "Digital VAX",
            EM_CRIS => "Axis Communications 32-bit embedded processor",
            EM_JAVELIN => "Infineon Technologies 32-bit embedded processor",
            EM_FIREPATH => "Element 14 64-bit DSP Processor",
            EM_ZSP => "LSI Logic 16-bit DSP Processor",
            EM_MMIX => "Donald Knuth's educational 64-bit processor",
            EM_HUANY => "Harvard University machine-independent object files",
            EM_PRISM => "SiTera Prism",
            EM_AVR => "Atmel AVR 8-bit microcontroller",
            EM_FR30 => "Fujitsu FR30",
            EM_D10V => "Mitsubishi D10V",
            EM_D30V => "Mitsubishi D30V",
            EM_V850 => "NEC v850",
            EM_M32R => "Mitsubishi M32R",
            EM_MN10300 => "Matsushita MN10300",
            EM_MN10200 => "Matsushita MN10200",
            EM_PJ => "picoJava",
            EM_OPENRISC => "OpenRISC 32-bit embedded processor",
            EM_ARC_COMPACT => "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)",
            EM_XTENSA => "Tensilica Xtensa Architecture",
            EM_VIDEOCORE => "Alphamosaic VideoCore processor",
            EM_TMM_GPP => "Thompson Multimedia General Purpose Processor",
            EM_NS32K => "National Semiconductor 32000 series",
            EM_TPC => "Tenor Network TPC processor",
            EM_SNP1K => "Trebia SNP 1000 processor",
            EM_ST200 => "STMicroelectronics (www.st.com) ST200 microcontroller",
            EM_IP2K => "Ubicom IP2xxx microcontroller family",
            EM_MAX => "MAX Processor",
            EM_CR => "National Semiconductor CompactRISC microprocessor",
            EM_F2MC16 => "Fujitsu F2MC16",
            EM_MSP430 => "Texas Instruments embedded microcontroller msp430",
            EM_BLACKFIN => "Analog Devices Blackfin (DSP) processor",
            EM_SE_C33 => "S1C33 Family of Seiko Epson processors",
            EM_SEP => "Sharp embedded microprocessor",
            EM_ARCA => "Arca RISC Microprocessor",
            EM_UNICORE => "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University",
            EM_EXCESS => "eXcess: 16/32/64-bit configurable embedded CPU",
            EM_DXP => "Icera Semiconductor Inc. Deep Execution Processor",
            EM_ALTERA_NIOS2 => "Altera Nios II soft-core processor",
            EM_CRX => "National Semiconductor CompactRISC CRX microprocessor",
            EM_XGATE => "Motorola XGATE embedded processor",
            EM_C166 => "Infineon C16x/XC16x processor",
            EM_M16C => "Renesas M16C series microprocessors",
            EM_DSPIC30F => "Microchip Technology dsPIC30F Digital Signal Controller",
            EM_CE => "Freescale Communication Engine RISC core",
            EM_M32C => "Renesas M32C series microprocessors",
            EM_TSK3000 => "Altium TSK3000 core",
            EM_RS08 => "Freescale RS08 embedded processor",
            EM_SHARC => "Analog Devices SHARC family of 32-bit DSP processors",
            EM_ECOG2 => "Cyan Technology eCOG2 microprocessor",
            EM_SCORE7 => "Sunplus S+core7 RISC processor",
            EM_DSP24 => "New Japan Radio (NJR) 24-bit DSP Processor",
            EM_VIDEOCORE3 => "Broadcom VideoCore III processor",
            EM_LATTICEMICO32 => "RISC processor for Lattice FPGA architecture",
            EM_SE_C17 => "Seiko Epson C17 family",
            EM_TI_C6000 => "The Texas Instruments TMS320C6000 DSP family",
            EM_TI_C2000 => "The Texas Instruments TMS320C2000 DSP family",
            EM_TI_C5500 => "The Texas Instruments TMS320C55x DSP family",
            EM_TI_ARP32 => "Texas Instruments Application Specific RISC Processor, 32bit fetch",
            EM_TI_PRU => "Texas Instruments Programmable Realtime Unit",
            EM_MMDSP_PLUS => "STMicroelectronics 64bit VLIW Data Signal Processor",
            EM_CYPRESS_M8C => "Cypress M8C microprocessor",
            EM_R32C => "Renesas R32C series microprocessors",
            EM_TRIMEDIA => "NXP Semiconductors TriMedia architecture family",
            EM_QDSP6 => "QUALCOMM DSP6 Processor",
            EM_8051 => "Intel 8051 and variants",
            EM_STXP7X => "STMicroelectronics STxP7x family of configurable and extensible RISC processors",
            EM_NDS32 => "Andes Technology compact code size embedded RISC processor family",
            EM_ECOG1X => "Cyan Technology eCOG1X family",
            EM_MAXQ30 => "Dallas Semiconductor MAXQ30 Core Micro-controllers",
            EM_XIMO16 => "New Japan Radio (NJR) 16-bit DSP Processor",
            EM_MANIK => "M2000 Reconfigurable RISC Microprocessor",
            EM_CRAYNV2 => "Cray Inc. NV2 vector architecture",
            EM_RX => "Renesas RX family",
            EM_METAG => "Imagination Technologies META processor architecture",
            EM_MCST_ELBRUS => "MCST Elbrus general purpose hardware architecture",
            EM_ECOG16 => "Cyan Technology eCOG16 family",
            EM_CR16 => "National Semiconductor CompactRISC CR16 16-bit microprocessor",
            EM_ETPU => "Freescale Extended Time Processing Unit",
            EM_SLE9X => "Infineon Technologies SLE9X core",
            EM_L10M => "Intel L10M",
            EM_K10M => "Intel K10M",
            EM_AARCH64 => "ARM 64-bit architecture (AARCH64)",
            EM_AVR32 => "Atmel Corporation 32-bit microprocessor family",
            EM_STM8 => "STMicroeletronics STM8 8-bit microcontroller",
            EM_TILE64 => "Tilera TILE64 multicore architecture family",
            EM_TILEPRO => "Tilera TILEPro multicore architecture family",
            EM_MICROBLAZE => "Xilinx MicroBlaze 32-bit RISC soft processor core",
            EM_CUDA => "NVIDIA CUDA architecture",
            EM_TILEGX => "Tilera TILE-Gx multicore architecture family",
            EM_CLOUDSHIELD => "CloudShield architecture family",
            EM_COREA_1ST => "KIPO-KAIST Core-A 1st generation processor family",
            EM_COREA_2ND => "KIPO-KAIST Core-A 2nd generation processor family",
            EM_ARC_COMPACT2 => "Synopsys ARCompact V2",
            EM_OPEN8 => "Open8 8-bit RISC soft processor core",
            EM_RL78 => "Renesas RL78 family",
            EM_VIDEOCORE5 => "Broadcom VideoCore V processor",
            EM_78KOR => "Renesas 78KOR family",
            EM_56800EX => "Freescale 56800EX Digital Signal Controller (DSC)",
            EM_BA1 => "Beyond BA1 CPU architecture",
            EM_BA2 => "Beyond BA2 CPU architecture",
            EM_XCORE => "XMOS xCORE processor family",
            EM_MCHP_PIC => "Microchip 8-bit PIC(r) family",
            EM_INTEL205 => "Reserved by Intel",
            EM_INTEL206 => "Reserved by Intel",
            EM_INTEL207 => "Reserved by Intel",
            EM_INTEL208 => "Reserved by Intel",
            EM_INTEL209 => "Reserved by Intel",
            EM_KM32 => "KM211 KM32 32-bit processor",
            EM_KMX32 => "KM211 KMX32 32-bit processor",
            EM_KMX16 => "KM211 KMX16 16-bit processor",
            EM_KMX8 => "KM211 KMX8 8-bit processor",
            EM_KVARC => "KM211 KVARC processor",
            EM_CDP => "Paneve CDP architecture family",
            EM_COGE => "Cognitive Smart Memory Processor",
            EM_COOL => "Bluechip Systems CoolEngine",
            EM_NORC => "Nanoradio Optimized RISC",
            EM_CSR_KALIMBA => "CSR Kalimba architecture family",
            EM_Z80 => "Zilog Z80",
            EM_VISIUM => "Controls and Data Services VISIUMcore processor",
            EM_FT32 => "FTDI Chip FT32 high performance 32-bit RISC architecture",
            EM_MOXIE => "Moxie processor family",
            EM_AMDGPU => "AMD GPU architecture",
            EM_RISCV => "RISC-V",
            EM_BPF => "Linux BPF",
            _ => "Unknown Machine",
        };
        write!(f, "{}", str)
    }
}

/// Encapsulates the contents of the ELF File Header
///
/// The ELF File Header starts off every ELF file and both identifies the
/// file contents and informs how to interpret said contents. This includes
/// the width of certain fields (32-bit vs 64-bit), the data endianness, the
/// file type, and more.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileHeader {
    /// 32-bit vs 64-bit
    pub class:      Class,
    /// little vs big endian
    pub data:       Data,
    /// elf version
    pub version:    Version,
    /// OS ABI
    pub osabi:      OSABI,
    /// Version of the OS ABI
    pub abiversion: u8,
    /// ELF file type
    pub elftype:    Type,
    /// Target machine architecture
    pub machine:    Machine,
    /// Virtual address of program entry point
    pub entry:      u64,
}

impl FileHeader {
    pub fn new() -> FileHeader {
        FileHeader { class : ELFCLASSNONE, data : ELFDATANONE, version : EV_NONE,
            elftype : ET_NONE, machine : EM_NONE, osabi : ELFOSABI_NONE,
            abiversion : 0, entry : 0 }
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File Header for {} {} Elf {} for {} {}", self.class, self.data,
            self.elftype, self.osabi, self.machine)
    }
}

/// Represents ELF Program Header flags
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgFlag(pub u32);
pub const PF_NONE : ProgFlag = ProgFlag(0);
/// Executable program segment
pub const PF_X : ProgFlag = ProgFlag(1);
/// Writable program segment
pub const PF_W : ProgFlag = ProgFlag(2);
/// Readable program segment
pub const PF_R : ProgFlag = ProgFlag(4);

impl fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if (self.0 & PF_R.0) != 0 {
            write!(f, "R")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & PF_W.0) != 0 {
            write!(f, "W")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & PF_X.0) != 0 {
            write!(f, "E")
        } else {
            write!(f, " ")
        }
    }
}

/// Represents ELF Program Header type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgType(pub u32);
/// Program header table entry unused
pub const PT_NULL : ProgType = ProgType(0);
/// Loadable program segment
pub const PT_LOAD : ProgType = ProgType(1);
/// Dynamic linking information
pub const PT_DYNAMIC : ProgType = ProgType(2);
/// Program interpreter
pub const PT_INTERP : ProgType = ProgType(3);
/// Auxiliary information
pub const PT_NOTE : ProgType = ProgType(4);
/// Unused
pub const PT_SHLIB : ProgType = ProgType(5);
/// The program header table
pub const PT_PHDR : ProgType = ProgType(6);
/// Thread-local storage segment
pub const PT_TLS : ProgType = ProgType(7);
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME : ProgType = ProgType(0x6474e550);
/// Indicates stack executability
pub const PT_GNU_STACK : ProgType = ProgType(0x6474e551);
/// Read-only after relocation
pub const PT_GNU_RELRO : ProgType = ProgType(0x6474e552);

impl fmt::Debug for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_SHLIB => "SHLIB",
            PT_PHDR => "PHDR",
            PT_TLS => "TLS",
            PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            PT_GNU_STACK => "GNU_STACK",
            PT_GNU_RELRO => "GNU_RELRO",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Encapsulates the contents of an ELF Program Header
///
/// The program header table is an array of program header structures describing
/// the various segments for program execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Program segment type
    pub progtype: ProgType,
    /// Offset into the ELF file where this segment begins
    pub offset:   u64,
    /// Virtual adress where this segment should be loaded
    pub vaddr:    u64,
    /// Physical address where this segment should be loaded
    pub paddr:    u64,
    /// Size of this segment in the file
    pub filesz:   u64,
    /// Size of this segment in memory
    pub memsz:    u64,
    /// Flags for this segment
    pub flags:    ProgFlag,
    /// file and memory alignment
    pub align:    u64,
}

impl fmt::Display for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Program Header: Type: {} Offset: {:#010x} VirtAddr: {:#010x} PhysAddr: {:#010x} FileSize: {:#06x} MemSize: {:#06x} Flags: {} Align: {:#x}",
            self.progtype, self.offset, self.vaddr, self.paddr, self.filesz,
            self.memsz, self.flags, self.align)
    }
}

/// Represens ELF Section type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SectionType(pub u32);
/// Inactive section with undefined values
pub const SHT_NULL : SectionType = SectionType(0);
/// Information defined by the program, includes executable code and data
pub const SHT_PROGBITS : SectionType = SectionType(1);
/// Section data contains a symbol table
pub const SHT_SYMTAB : SectionType = SectionType(2);
/// Section data contains a string table
pub const SHT_STRTAB : SectionType = SectionType(3);
/// Section data contains relocation entries with explicit addends
pub const SHT_RELA : SectionType = SectionType(4);
/// Section data contains a symbol hash table. Must be present for dynamic linking
pub const SHT_HASH : SectionType = SectionType(5);
/// Section data contains information for dynamic linking
pub const SHT_DYNAMIC : SectionType = SectionType(6);
/// Section data contains information that marks the file in some way
pub const SHT_NOTE : SectionType = SectionType(7);
/// Section data occupies no space in the file but otherwise resembles SHT_PROGBITS
pub const SHT_NOBITS : SectionType = SectionType(8);
/// Section data contains relocation entries without explicit addends
pub const SHT_REL : SectionType = SectionType(9);
/// Section is reserved but has unspecified semantics
pub const SHT_SHLIB : SectionType = SectionType(10);
/// Section data contains a minimal set of dynamic linking symbols
pub const SHT_DYNSYM : SectionType = SectionType(11);
/// Section data contains an array of constructors
pub const SHT_INIT_ARRAY : SectionType = SectionType(14);
/// Section data contains an array of destructors
pub const SHT_FINI_ARRAY : SectionType = SectionType(15);
/// Section data contains an array of pre-constructors
pub const SHT_PREINIT_ARRAY : SectionType = SectionType(16);
/// Section group
pub const SHT_GROUP : SectionType = SectionType(17);
/// Extended symbol table section index
pub const SHT_SYMTAB_SHNDX : SectionType = SectionType(18);
/// Number of reserved SHT_* values
pub const SHT_NUM : SectionType = SectionType(19);
/// Object attributes
pub const SHT_GNU_ATTRIBUTES : SectionType = SectionType(0x6ffffff5);
/// GNU-style hash section
pub const SHT_GNU_HASH : SectionType = SectionType(0x6ffffff6);
/// Pre-link library list
pub const SHT_GNU_LIBLIST : SectionType = SectionType(0x6ffffff7);
/// Version definition section
pub const SHT_GNU_VERDEF : SectionType = SectionType(0x6ffffffd);
/// Version needs section
pub const SHT_GNU_VERNEED : SectionType = SectionType(0x6ffffffe);
/// Version symbol table
pub const SHT_GNU_VERSYM : SectionType = SectionType(0x6fffffff);

impl fmt::Debug for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for SectionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            SHT_NULL => "SHT_NULL",
            SHT_PROGBITS => "SHT_PROGBITS",
            SHT_SYMTAB => "SHT_SYMTAB",
            SHT_STRTAB => "SHT_STRTAB",
            SHT_RELA => "SHT_RELA",
            SHT_HASH => "SHT_HASH",
            SHT_DYNAMIC => "SHT_DYNAMIC",
            SHT_NOTE => "SHT_NOTE",
            SHT_NOBITS => "SHT_NOBITS",
            SHT_REL => "SHT_REL",
            SHT_SHLIB => "SHT_SHLIB",
            SHT_DYNSYM => "SHT_DYNSYM",
            SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
            SHT_GROUP => "SHT_GROUP",
            SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
            SHT_NUM => "SHT_NUM",
            SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
            SHT_GNU_HASH => "SHT_GNU_HASH",
            SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
            SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

///
/// Wrapper type for SectionFlag
///
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SectionFlag(pub u64);
/// Empty flags
pub const SHF_NONE : SectionFlag = SectionFlag(0);
/// Writable
pub const SHF_WRITE : SectionFlag = SectionFlag(1);
/// Occupies memory during execution
pub const SHF_ALLOC : SectionFlag = SectionFlag(2);
/// Executable
pub const SHF_EXECINSTR : SectionFlag = SectionFlag(4);
/// Might be merged
pub const SHF_MERGE : SectionFlag = SectionFlag(16);
/// Contains nul-terminated strings
pub const SHF_STRINGS : SectionFlag = SectionFlag(32);
/// `sh_info' contains SHT index
pub const SHF_INFO_LINK : SectionFlag = SectionFlag(64);
/// Preserve order after combining
pub const SHF_LINK_ORDER : SectionFlag = SectionFlag(128);
/// Non-standard OS specific handling required
pub const SHF_OS_NONCONFORMING : SectionFlag = SectionFlag(256);
/// Section is member of a group
pub const SHF_GROUP : SectionFlag = SectionFlag(512);
/// Section hold thread-local data
pub const SHF_TLS : SectionFlag = SectionFlag(1024);

impl fmt::Debug for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Encapsulates the contents of an ELF Section Header
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section Name
    pub name:      String,
    /// Section Type
    pub shtype:    SectionType,
    /// Section Flags
    pub flags:     SectionFlag,
    /// in-memory address where this section is loaded
    pub addr:      u64,
    /// Byte-offset into the file where this section starts
    pub offset:    u64,
    /// Section size in bytes
    pub size:      u64,
    /// Defined by section type
    pub link:      u32,
    /// Defined by section type
    pub info:      u32,
    /// address alignment
    pub addralign: u64,
    /// size of an entry if section data is an array of entries
    pub entsize:   u64,
}

impl fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Section Header: Name: {} Type: {} Flags: {} Addr: {:#010x} Offset: {:#06x} Size: {:#06x} Link: {} Info: {:#x} AddrAlign: {} EntSize: {}",
            self.name, self.shtype, self.flags, self.addr, self.offset,
            self.size, self.link, self.info, self.addralign, self.entsize)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);
/// Unspecified symbol type
pub const STT_NOTYPE : SymbolType = SymbolType(0);
/// Data object symbol
pub const STT_OBJECT : SymbolType = SymbolType(1);
/// Code object symbol
pub const STT_FUNC : SymbolType = SymbolType(2);
/// Section symbol
pub const STT_SECTION : SymbolType = SymbolType(3);
/// File name symbol
pub const STT_FILE : SymbolType = SymbolType(4);
/// Common data object symbol
pub const STT_COMMON : SymbolType = SymbolType(5);
/// Thread-local data object symbol
pub const STT_TLS	 : SymbolType = SymbolType(6);
/// Indirect code object symbol
pub const STT_GNU_IFUNC : SymbolType = SymbolType(10);

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STT_NOTYPE => "unspecified",
            STT_OBJECT => "data object",
            STT_FUNC => "code object",
            STT_SECTION => "section",
            STT_FILE => "file name",
            STT_COMMON => "common data object",
            STT_TLS => "thread-local data object",
            STT_GNU_IFUNC => "indirect code object",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);
/// Local symbol
pub const STB_LOCAL : SymbolBind = SymbolBind(0);
/// Global symbol
pub const STB_GLOBAL : SymbolBind = SymbolBind(1);
/// Weak symbol
pub const STB_WEAK : SymbolBind = SymbolBind(2);
/// Unique symbol
pub const STB_GNU_UNIQUE : SymbolBind = SymbolBind(10);

impl fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STB_LOCAL => "local",
            STB_GLOBAL => "global",
            STB_WEAK => "weak",
            STB_GNU_UNIQUE => "unique",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);
/// Default symbol visibility
pub const STV_DEFAULT : SymbolVis = SymbolVis(0);
/// Processor-specific hidden visibility
pub const STV_INTERNAL : SymbolVis = SymbolVis(1);
/// Hidden visibility
pub const STV_HIDDEN : SymbolVis = SymbolVis(2);
/// Protected visibility
pub const STV_PROTECTED : SymbolVis = SymbolVis(3);

impl fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            STV_DEFAULT => "default",
            STV_INTERNAL => "internal",
            STV_HIDDEN => "hidden",
            STV_PROTECTED => "protected",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol value
    pub value: u64,
    /// Symbol size
    pub size: u64,
    /// Section index
    pub shndx: u16,
    /// Symbol type
    pub symtype: SymbolType,
    /// Symbol binding
    pub bind: SymbolBind,
    /// Symbol visibility
    pub vis: SymbolVis,
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.value, self.size, self.symtype, self.bind, self.vis, self.shndx, self.name)
    }
}
