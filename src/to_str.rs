use crate::file::{Architecture, ObjectFileType, OSABI};
use crate::gabi;

pub fn e_osabi_to_str(e_osabi: u8) -> Option<&'static str> {
    match e_osabi {
        gabi::ELFOSABI_SYSV => Some("ELFOSABI_SYSV"),
        gabi::ELFOSABI_HPUX => Some("ELFOSABI_HPUX"),
        gabi::ELFOSABI_NETBSD => Some("ELFOSABI_NETBSD"),
        gabi::ELFOSABI_LINUX => Some("ELFOSABI_LINUX"),
        gabi::ELFOSABI_SOLARIS => Some("ELFOSABI_SOLARIS"),
        gabi::ELFOSABI_AIX => Some("ELFOSABI_AIX"),
        gabi::ELFOSABI_IRIX => Some("ELFOSABI_IRIX"),
        gabi::ELFOSABI_FREEBSD => Some("ELFOSABI_FREEBSD"),
        gabi::ELFOSABI_TRU64 => Some("ELFOSABI_TRU64"),
        gabi::ELFOSABI_MODESTO => Some("ELFOSABI_MODESTO"),
        gabi::ELFOSABI_OPENBSD => Some("ELFOSABI_OPENBSD"),
        gabi::ELFOSABI_OPENVMS => Some("ELFOSABI_OPENVMS"),
        gabi::ELFOSABI_NSK => Some("ELFOSABI_NSK"),
        gabi::ELFOSABI_AROS => Some("ELFOSABI_AROS"),
        gabi::ELFOSABI_FENIXOS => Some("ELFOSABI_FENIXOS"),
        gabi::ELFOSABI_CLOUDABI => Some("ELFOSABI_CLOUDABI"),
        gabi::ELFOSABI_OPENVOS => Some("ELFOSABI_OPENVOS"),
        _ => None,
    }
}

impl core::fmt::Display for OSABI {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match e_osabi_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "e_osabi({})", self.0)
            }
        }
    }
}

pub fn e_type_to_human_str(e_type: u16) -> Option<&'static str> {
    match e_type {
        gabi::ET_NONE => Some("No file type"),
        gabi::ET_REL => Some("Relocatable file"),
        gabi::ET_EXEC => Some("Executable file"),
        gabi::ET_DYN => Some("Shared object file"),
        gabi::ET_CORE => Some("Core file"),
        _ => None,
    }
}

pub fn e_type_to_str(e_type: u16) -> Option<&'static str> {
    match e_type {
        gabi::ET_NONE => Some("ET_NONE"),
        gabi::ET_REL => Some("ET_REL"),
        gabi::ET_EXEC => Some("ET_EXEC"),
        gabi::ET_DYN => Some("ET_DYN"),
        gabi::ET_CORE => Some("ET_CORE"),
        _ => None,
    }
}

impl core::fmt::Display for ObjectFileType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match e_type_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "e_type({})", self.0)
            }
        }
    }
}

pub fn e_machine_to_human_str(e_machine: u16) -> Option<&'static str> {
    match e_machine {
        gabi::EM_NONE => Some("No machine"),
        gabi::EM_M32 => Some("AT&T WE 32100"),
        gabi::EM_SPARC => Some("SPARC"),
        gabi::EM_386 => Some("Intel 80386"),
        gabi::EM_68K => Some("Motorola 68000"),
        gabi::EM_88K => Some("Motorola 88000"),
        gabi::EM_IAMCU => Some("Intel MCU"),
        gabi::EM_860 => Some("Intel 80860"),
        gabi::EM_MIPS => Some("MIPS I Architecture"),
        gabi::EM_S370 => Some("IBM System/370 Processor"),
        gabi::EM_MIPS_RS3_LE => Some("MIPS RS3000 Little-endian"),
        gabi::EM_PARISC => Some("Hewlett-Packard PA-RISC"),
        gabi::EM_VPP500 => Some("Fujitsu VPP500"),
        gabi::EM_SPARC32PLUS => Some("Enhanced instruction set SPARC"),
        gabi::EM_960 => Some("Intel 80960"),
        gabi::EM_PPC => Some("PowerPC"),
        gabi::EM_PPC64 => Some("64-bit PowerPC"),
        gabi::EM_S390 => Some("IBM System/390 Processor"),
        gabi::EM_SPU => Some("IBM SPU/SPC"),
        gabi::EM_V800 => Some("NEC V800"),
        gabi::EM_FR20 => Some("Fujitsu FR20"),
        gabi::EM_RH32 => Some("TRW RH-32"),
        gabi::EM_RCE => Some("Motorola RCE"),
        gabi::EM_ARM => Some("ARM 32-bit architecture (AARCH32)"),
        gabi::EM_ALPHA => Some("Digital Alpha"),
        gabi::EM_SH => Some("Hitachi SH"),
        gabi::EM_SPARCV9 => Some("SPARC Version 9"),
        gabi::EM_TRICORE => Some("Siemens TriCore embedded processor"),
        gabi::EM_ARC => Some("Argonaut RISC Core, Argonaut Technologies Inc."),
        gabi::EM_H8_300 => Some("Hitachi H8/300"),
        gabi::EM_H8_300H => Some("Hitachi H8/300H"),
        gabi::EM_H8S => Some("Hitachi H8S"),
        gabi::EM_H8_500 => Some("Hitachi H8/500"),
        gabi::EM_IA_64 => Some("Intel IA-64 processor architecture"),
        gabi::EM_MIPS_X => Some("Stanford MIPS-X"),
        gabi::EM_COLDFIRE => Some("Motorola ColdFire"),
        gabi::EM_68HC12 => Some("Motorola M68HC12"),
        gabi::EM_MMA => Some("Fujitsu MMA Multimedia Accelerator"),
        gabi::EM_PCP => Some("Siemens PCP"),
        gabi::EM_NCPU => Some("Sony nCPU embedded RISC processor"),
        gabi::EM_NDR1 => Some("Denso NDR1 microprocessor"),
        gabi::EM_STARCORE => Some("Motorola Star*Core processor"),
        gabi::EM_ME16 => Some("Toyota ME16 processor"),
        gabi::EM_ST100 => Some("STMicroelectronics ST100 processor"),
        gabi::EM_TINYJ => Some("Advanced Logic Corp. TinyJ embedded processor family"),
        gabi::EM_X86_64 => Some("AMD x86-64 architecture"),
        gabi::EM_PDSP => Some("Sony DSP Processor"),
        gabi::EM_PDP10 => Some("Digital Equipment Corp. PDP-10"),
        gabi::EM_PDP11 => Some("Digital Equipment Corp. PDP-11"),
        gabi::EM_FX66 => Some("Siemens FX66 microcontroller"),
        gabi::EM_ST9PLUS => Some("STMicroelectronics ST9+ 8/16 bit microcontroller"),
        gabi::EM_ST7 => Some("STMicroelectronics ST7 8-bit microcontroller"),
        gabi::EM_68HC16 => Some("Motorola MC68HC16 Microcontroller"),
        gabi::EM_68HC11 => Some("Motorola MC68HC11 Microcontroller"),
        gabi::EM_68HC08 => Some("Motorola MC68HC08 Microcontroller"),
        gabi::EM_68HC05 => Some("Motorola MC68HC05 Microcontroller"),
        gabi::EM_SVX => Some("Silicon Graphics SVx"),
        gabi::EM_ST19 => Some("STMicroelectronics ST19 8-bit microcontroller"),
        gabi::EM_VAX => Some("Digital VAX"),
        gabi::EM_CRIS => Some("Axis Communications 32-bit embedded processor"),
        gabi::EM_JAVELIN => Some("Infineon Technologies 32-bit embedded processor"),
        gabi::EM_FIREPATH => Some("Element 14 64-bit DSP Processor"),
        gabi::EM_ZSP => Some("LSI Logic 16-bit DSP Processor"),
        gabi::EM_MMIX => Some("Donald Knuth's educational 64-bit processor"),
        gabi::EM_HUANY => Some("Harvard University machine-independent object files"),
        gabi::EM_PRISM => Some("SiTera Prism"),
        gabi::EM_AVR => Some("Atmel AVR 8-bit microcontroller"),
        gabi::EM_FR30 => Some("Fujitsu FR30"),
        gabi::EM_D10V => Some("Mitsubishi D10V"),
        gabi::EM_D30V => Some("Mitsubishi D30V"),
        gabi::EM_V850 => Some("NEC v850"),
        gabi::EM_M32R => Some("Mitsubishi M32R"),
        gabi::EM_MN10300 => Some("Matsushita MN10300"),
        gabi::EM_MN10200 => Some("Matsushita MN10200"),
        gabi::EM_PJ => Some("picoJava"),
        gabi::EM_OPENRISC => Some("OpenRISC 32-bit embedded processor"),
        gabi::EM_ARC_COMPACT => Some("ARC International ARCompact processor"),
        gabi::EM_XTENSA => Some("Tensilica Xtensa Architecture"),
        gabi::EM_VIDEOCORE => Some("Alphamosaic VideoCore processor"),
        gabi::EM_TMM_GPP => Some("Thompson Multimedia General Purpose Processor"),
        gabi::EM_NS32K => Some("National Semiconductor 32000 series"),
        gabi::EM_TPC => Some("Tenor Network TPC processor"),
        gabi::EM_SNP1K => Some("Trebia SNP 1000 processor"),
        gabi::EM_ST200 => Some("STMicroelectronics (www.st.com) ST200 microcontroller"),
        gabi::EM_IP2K => Some("Ubicom IP2xxx microcontroller family"),
        gabi::EM_MAX => Some("MAX Processor"),
        gabi::EM_CR => Some("National Semiconductor CompactRISC microprocessor"),
        gabi::EM_F2MC16 => Some("Fujitsu F2MC16"),
        gabi::EM_MSP430 => Some("Texas Instruments embedded microcontroller msp430"),
        gabi::EM_BLACKFIN => Some("Analog Devices Blackfin (DSP) processor"),
        gabi::EM_SE_C33 => Some("S1C33 Family of Seiko Epson processors"),
        gabi::EM_SEP => Some("Sharp embedded microprocessor"),
        gabi::EM_ARCA => Some("Arca RISC Microprocessor"),
        gabi::EM_UNICORE => {
            Some("Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University")
        }
        gabi::EM_EXCESS => Some("eXcess: 16/32/64-bit configurable embedded CPU"),
        gabi::EM_DXP => Some("Icera Semiconductor Inc. Deep Execution Processor"),
        gabi::EM_ALTERA_NIOS2 => Some("Altera Nios II soft-core processor"),
        gabi::EM_CRX => Some("National Semiconductor CompactRISC CRX microprocessor"),
        gabi::EM_XGATE => Some("Motorola XGATE embedded processor"),
        gabi::EM_C166 => Some("Infineon C16x/XC16x processor"),
        gabi::EM_M16C => Some("Renesas M16C series microprocessors"),
        gabi::EM_DSPIC30F => Some("Microchip Technology dsPIC30F Digital Signal Controller"),
        gabi::EM_CE => Some("Freescale Communication Engine RISC core"),
        gabi::EM_M32C => Some("Renesas M32C series microprocessors"),
        gabi::EM_TSK3000 => Some("Altium TSK3000 core"),
        gabi::EM_RS08 => Some("Freescale RS08 embedded processor"),
        gabi::EM_SHARC => Some("Analog Devices SHARC family of 32-bit DSP processors"),
        gabi::EM_ECOG2 => Some("Cyan Technology eCOG2 microprocessor"),
        gabi::EM_SCORE7 => Some("Sunplus S+core7 RISC processor"),
        gabi::EM_DSP24 => Some("New Japan Radio (NJR) 24-bit DSP Processor"),
        gabi::EM_VIDEOCORE3 => Some("Broadcom VideoCore III processor"),
        gabi::EM_LATTICEMICO32 => Some("RISC processor for Lattice FPGA architecture"),
        gabi::EM_SE_C17 => Some("Seiko Epson C17 family"),
        gabi::EM_TI_C6000 => Some("The Texas Instruments TMS320C6000 DSP family"),
        gabi::EM_TI_C2000 => Some("The Texas Instruments TMS320C2000 DSP family"),
        gabi::EM_TI_C5500 => Some("The Texas Instruments TMS320C55x DSP family"),
        gabi::EM_TI_ARP32 => {
            Some("Texas Instruments Application Specific RISC Processor, 32bit fetch")
        }
        gabi::EM_TI_PRU => Some("Texas Instruments Programmable Realtime Unit"),
        gabi::EM_MMDSP_PLUS => Some("STMicroelectronics 64bit VLIW Data Signal Processor"),
        gabi::EM_CYPRESS_M8C => Some("Cypress M8C microprocessor"),
        gabi::EM_R32C => Some("Renesas R32C series microprocessors"),
        gabi::EM_TRIMEDIA => Some("NXP Semiconductors TriMedia architecture family"),
        gabi::EM_QDSP6 => Some("QUALCOMM DSP6 Processor"),
        gabi::EM_8051 => Some("Intel 8051 and variants"),
        gabi::EM_STXP7X => {
            Some("STMicroelectronics STxP7x family of configurable and extensible RISC processors")
        }
        gabi::EM_NDS32 => Some("Andes Technology compact code size embedded RISC processor family"),
        gabi::EM_ECOG1X => Some("Cyan Technology eCOG1X family"),
        gabi::EM_MAXQ30 => Some("Dallas Semiconductor MAXQ30 Core Micro-controllers"),
        gabi::EM_XIMO16 => Some("New Japan Radio (NJR) 16-bit DSP Processor"),
        gabi::EM_MANIK => Some("M2000 Reconfigurable RISC Microprocessor"),
        gabi::EM_CRAYNV2 => Some("Cray Inc. NV2 vector architecture"),
        gabi::EM_RX => Some("Renesas RX family"),
        gabi::EM_METAG => Some("Imagination Technologies META processor architecture"),
        gabi::EM_MCST_ELBRUS => Some("MCST Elbrus general purpose hardware architecture"),
        gabi::EM_ECOG16 => Some("Cyan Technology eCOG16 family"),
        gabi::EM_CR16 => Some("National Semiconductor CompactRISC CR16 16-bit microprocessor"),
        gabi::EM_ETPU => Some("Freescale Extended Time Processing Unit"),
        gabi::EM_SLE9X => Some("Infineon Technologies SLE9X core"),
        gabi::EM_L10M => Some("Intel L10M"),
        gabi::EM_K10M => Some("Intel K10M"),
        gabi::EM_AARCH64 => Some("ARM 64-bit architecture (AARCH64)"),
        gabi::EM_AVR32 => Some("Atmel Corporation 32-bit microprocessor family"),
        gabi::EM_STM8 => Some("STMicroeletronics STM8 8-bit microcontroller"),
        gabi::EM_TILE64 => Some("Tilera TILE64 multicore architecture family"),
        gabi::EM_TILEPRO => Some("Tilera TILEPro multicore architecture family"),
        gabi::EM_MICROBLAZE => Some("Xilinx MicroBlaze 32-bit RISC soft processor core"),
        gabi::EM_CUDA => Some("NVIDIA CUDA architecture"),
        gabi::EM_TILEGX => Some("Tilera TILE-Gx multicore architecture family"),
        gabi::EM_CLOUDSHIELD => Some("CloudShield architecture family"),
        gabi::EM_COREA_1ST => Some("KIPO-KAIST Core-A 1st generation processor family"),
        gabi::EM_COREA_2ND => Some("KIPO-KAIST Core-A 2nd generation processor family"),
        gabi::EM_ARC_COMPACT2 => Some("Synopsys ARCompact V2"),
        gabi::EM_OPEN8 => Some("Open8 8-bit RISC soft processor core"),
        gabi::EM_RL78 => Some("Renesas RL78 family"),
        gabi::EM_VIDEOCORE5 => Some("Broadcom VideoCore V processor"),
        gabi::EM_78KOR => Some("Renesas 78KOR family"),
        gabi::EM_56800EX => Some("Freescale 56800EX Digital Signal Controller (DSC)"),
        gabi::EM_BA1 => Some("Beyond BA1 CPU architecture"),
        gabi::EM_BA2 => Some("Beyond BA2 CPU architecture"),
        gabi::EM_XCORE => Some("XMOS xCORE processor family"),
        gabi::EM_MCHP_PIC => Some("Microchip 8-bit PIC(r) family"),
        gabi::EM_INTEL205 => Some("Reserved by Intel"),
        gabi::EM_INTEL206 => Some("Reserved by Intel"),
        gabi::EM_INTEL207 => Some("Reserved by Intel"),
        gabi::EM_INTEL208 => Some("Reserved by Intel"),
        gabi::EM_INTEL209 => Some("Reserved by Intel"),
        gabi::EM_KM32 => Some("KM211 KM32 32-bit processor"),
        gabi::EM_KMX32 => Some("KM211 KMX32 32-bit processor"),
        gabi::EM_KMX16 => Some("KM211 KMX16 16-bit processor"),
        gabi::EM_KMX8 => Some("KM211 KMX8 8-bit processor"),
        gabi::EM_KVARC => Some("KM211 KVARC processor"),
        gabi::EM_CDP => Some("Paneve CDP architecture family"),
        gabi::EM_COGE => Some("Cognitive Smart Memory Processor"),
        gabi::EM_COOL => Some("Bluechip Systems CoolEngine"),
        gabi::EM_NORC => Some("Nanoradio Optimized RISC"),
        gabi::EM_CSR_KALIMBA => Some("CSR Kalimba architecture family"),
        gabi::EM_Z80 => Some("Zilog Z80"),
        gabi::EM_VISIUM => Some("Controls and Data Services VISIUMcore processor"),
        gabi::EM_FT32 => Some("FTDI Chip FT32 high performance 32-bit RISC architecture"),
        gabi::EM_MOXIE => Some("Moxie processor family"),
        gabi::EM_AMDGPU => Some("AMD GPU architecture"),
        gabi::EM_RISCV => Some("RISC-V"),
        gabi::EM_BPF => Some("Linux BPF"),
        _ => None,
    }
}

pub fn e_machine_to_str(e_machine: u16) -> Option<&'static str> {
    match e_machine {
        gabi::EM_NONE => Some("EM_NONE"),
        gabi::EM_M32 => Some("EM_M32"),
        gabi::EM_SPARC => Some("EM_SPARC"),
        gabi::EM_386 => Some("EM_386"),
        gabi::EM_68K => Some("EM_68K"),
        gabi::EM_88K => Some("EM_88K"),
        gabi::EM_IAMCU => Some("EM_IAMCU"),
        gabi::EM_860 => Some("EM_860"),
        gabi::EM_MIPS => Some("EM_MIPS"),
        gabi::EM_S370 => Some("EM_S370"),
        gabi::EM_MIPS_RS3_LE => Some("EM_MIPS_RS3_LE"),
        gabi::EM_PARISC => Some("EM_PARISC"),
        gabi::EM_VPP500 => Some("EM_VPP500"),
        gabi::EM_SPARC32PLUS => Some("EM_SPARC32PLUS"),
        gabi::EM_960 => Some("EM_960"),
        gabi::EM_PPC => Some("EM_PPC"),
        gabi::EM_PPC64 => Some("EM_PPC64"),
        gabi::EM_S390 => Some("EM_S390"),
        gabi::EM_SPU => Some("EM_SPU"),
        gabi::EM_V800 => Some("EM_V800"),
        gabi::EM_FR20 => Some("EM_FR20"),
        gabi::EM_RH32 => Some("EM_RH32"),
        gabi::EM_RCE => Some("EM_RCE"),
        gabi::EM_ARM => Some("EM_ARM"),
        gabi::EM_ALPHA => Some("EM_ALPHA"),
        gabi::EM_SH => Some("EM_SH"),
        gabi::EM_SPARCV9 => Some("EM_SPARCV9"),
        gabi::EM_TRICORE => Some("EM_TRICORE"),
        gabi::EM_ARC => Some("EM_ARC"),
        gabi::EM_H8_300 => Some("EM_H8_300"),
        gabi::EM_H8_300H => Some("EM_H8_300H"),
        gabi::EM_H8S => Some("EM_H8S"),
        gabi::EM_H8_500 => Some("EM_H8_500"),
        gabi::EM_IA_64 => Some("EM_IA_64"),
        gabi::EM_MIPS_X => Some("EM_MIPS_X"),
        gabi::EM_COLDFIRE => Some("EM_COLDFIRE"),
        gabi::EM_68HC12 => Some("EM_68HC12"),
        gabi::EM_MMA => Some("EM_MMA"),
        gabi::EM_PCP => Some("EM_PCP"),
        gabi::EM_NCPU => Some("EM_NCPU"),
        gabi::EM_NDR1 => Some("EM_NDR1"),
        gabi::EM_STARCORE => Some("EM_STARCORE"),
        gabi::EM_ME16 => Some("EM_ME16"),
        gabi::EM_ST100 => Some("EM_ST100"),
        gabi::EM_TINYJ => Some("EM_TINYJ"),
        gabi::EM_X86_64 => Some("EM_X86_64"),
        gabi::EM_PDSP => Some("EM_PDSP"),
        gabi::EM_PDP10 => Some("EM_PDP10"),
        gabi::EM_PDP11 => Some("EM_PDP11"),
        gabi::EM_FX66 => Some("EM_FX66"),
        gabi::EM_ST9PLUS => Some("EM_ST9PLUS"),
        gabi::EM_ST7 => Some("EM_ST7"),
        gabi::EM_68HC16 => Some("EM_68HC16"),
        gabi::EM_68HC11 => Some("EM_68HC11"),
        gabi::EM_68HC08 => Some("EM_68HC08"),
        gabi::EM_68HC05 => Some("EM_68HC05"),
        gabi::EM_SVX => Some("EM_SVX"),
        gabi::EM_ST19 => Some("EM_ST19"),
        gabi::EM_VAX => Some("EM_VAX"),
        gabi::EM_CRIS => Some("EM_CRIS"),
        gabi::EM_JAVELIN => Some("EM_JAVELIN"),
        gabi::EM_FIREPATH => Some("EM_FIREPATH"),
        gabi::EM_ZSP => Some("EM_ZSP"),
        gabi::EM_MMIX => Some("EM_MMIX"),
        gabi::EM_HUANY => Some("EM_HUANY"),
        gabi::EM_PRISM => Some("EM_PRISM"),
        gabi::EM_AVR => Some("EM_AVR"),
        gabi::EM_FR30 => Some("EM_FR30"),
        gabi::EM_D10V => Some("EM_D10V"),
        gabi::EM_D30V => Some("EM_D30V"),
        gabi::EM_V850 => Some("EM_V850"),
        gabi::EM_M32R => Some("EM_M32R"),
        gabi::EM_MN10300 => Some("EM_MN10300"),
        gabi::EM_MN10200 => Some("EM_MN10200"),
        gabi::EM_PJ => Some("EM_PJ"),
        gabi::EM_OPENRISC => Some("EM_OPENRISC"),
        gabi::EM_ARC_COMPACT => Some("EM_ARC_COMPACT"),
        gabi::EM_XTENSA => Some("EM_XTENSA"),
        gabi::EM_VIDEOCORE => Some("EM_VIDEOCORE"),
        gabi::EM_TMM_GPP => Some("EM_TMM_GPP"),
        gabi::EM_NS32K => Some("EM_NS32K"),
        gabi::EM_TPC => Some("EM_TPC"),
        gabi::EM_SNP1K => Some("EM_SNP1K"),
        gabi::EM_ST200 => Some("EM_ST200"),
        gabi::EM_IP2K => Some("EM_IP2K"),
        gabi::EM_MAX => Some("EM_MAX"),
        gabi::EM_CR => Some("EM_CR"),
        gabi::EM_F2MC16 => Some("EM_F2MC16"),
        gabi::EM_MSP430 => Some("EM_MSP430"),
        gabi::EM_BLACKFIN => Some("EM_BLACKFIN"),
        gabi::EM_SE_C33 => Some("EM_SE_C33"),
        gabi::EM_SEP => Some("EM_SEP"),
        gabi::EM_ARCA => Some("EM_ARCA"),
        gabi::EM_UNICORE => Some("EM_UNICORE"),
        gabi::EM_EXCESS => Some("EM_EXCESS"),
        gabi::EM_DXP => Some("EM_DXP"),
        gabi::EM_ALTERA_NIOS2 => Some("EM_ALTERA_NIOS2"),
        gabi::EM_CRX => Some("EM_CRX"),
        gabi::EM_XGATE => Some("EM_XGATE"),
        gabi::EM_C166 => Some("EM_C166"),
        gabi::EM_M16C => Some("EM_M16C"),
        gabi::EM_DSPIC30F => Some("EM_DSPIC30F"),
        gabi::EM_CE => Some("EM_CE"),
        gabi::EM_M32C => Some("EM_M32C"),
        gabi::EM_TSK3000 => Some("EM_TSK3000"),
        gabi::EM_RS08 => Some("EM_RS08"),
        gabi::EM_SHARC => Some("EM_SHARC"),
        gabi::EM_ECOG2 => Some("EM_ECOG2"),
        gabi::EM_SCORE7 => Some("EM_SCORE7"),
        gabi::EM_DSP24 => Some("EM_DSP24"),
        gabi::EM_VIDEOCORE3 => Some("EM_VIDEOCORE3"),
        gabi::EM_LATTICEMICO32 => Some("EM_LATTICEMICO32"),
        gabi::EM_SE_C17 => Some("EM_SE_C17"),
        gabi::EM_TI_C6000 => Some("EM_TI_C6000"),
        gabi::EM_TI_C2000 => Some("EM_TI_C2000"),
        gabi::EM_TI_C5500 => Some("EM_TI_C5500"),
        gabi::EM_TI_ARP32 => Some("EM_TI_ARP32"),
        gabi::EM_TI_PRU => Some("EM_TI_PRU"),
        gabi::EM_MMDSP_PLUS => Some("EM_MMDSP_PLUS"),
        gabi::EM_CYPRESS_M8C => Some("EM_CYPRESS_M8C"),
        gabi::EM_R32C => Some("EM_R32C"),
        gabi::EM_TRIMEDIA => Some("EM_TRIMEDIA"),
        gabi::EM_QDSP6 => Some("EM_QDSP6"),
        gabi::EM_8051 => Some("EM_8051"),
        gabi::EM_STXP7X => Some("EM_STXP7X"),
        gabi::EM_NDS32 => Some("EM_NDS32"),
        gabi::EM_ECOG1X => Some("EM_ECOG1X"),
        gabi::EM_MAXQ30 => Some("EM_MAXQ30"),
        gabi::EM_XIMO16 => Some("EM_XIMO16"),
        gabi::EM_MANIK => Some("EM_MANIK"),
        gabi::EM_CRAYNV2 => Some("EM_CRAYNV2"),
        gabi::EM_RX => Some("EM_RX"),
        gabi::EM_METAG => Some("EM_METAG"),
        gabi::EM_MCST_ELBRUS => Some("EM_MCST_ELBRUS"),
        gabi::EM_ECOG16 => Some("EM_ECOG16"),
        gabi::EM_CR16 => Some("EM_CR16"),
        gabi::EM_ETPU => Some("EM_ETPU"),
        gabi::EM_SLE9X => Some("EM_SLE9X"),
        gabi::EM_L10M => Some("EM_L10M"),
        gabi::EM_K10M => Some("EM_K10M"),
        gabi::EM_AARCH64 => Some("EM_AARCH64"),
        gabi::EM_AVR32 => Some("EM_AVR32"),
        gabi::EM_STM8 => Some("EM_STM8"),
        gabi::EM_TILE64 => Some("EM_TILE64"),
        gabi::EM_TILEPRO => Some("EM_TILEPRO"),
        gabi::EM_MICROBLAZE => Some("EM_MICROBLAZE"),
        gabi::EM_CUDA => Some("EM_CUDA"),
        gabi::EM_TILEGX => Some("EM_TILEGX"),
        gabi::EM_CLOUDSHIELD => Some("EM_CLOUDSHIELD"),
        gabi::EM_COREA_1ST => Some("EM_COREA_1ST"),
        gabi::EM_COREA_2ND => Some("EM_COREA_2ND"),
        gabi::EM_ARC_COMPACT2 => Some("EM_ARC_COMPACT2"),
        gabi::EM_OPEN8 => Some("EM_OPEN8"),
        gabi::EM_RL78 => Some("EM_RL78"),
        gabi::EM_VIDEOCORE5 => Some("EM_VIDEOCORE5"),
        gabi::EM_78KOR => Some("EM_78KOR"),
        gabi::EM_56800EX => Some("EM_56800EX"),
        gabi::EM_BA1 => Some("EM_BA1"),
        gabi::EM_BA2 => Some("EM_BA2"),
        gabi::EM_XCORE => Some("EM_XCORE"),
        gabi::EM_MCHP_PIC => Some("EM_MCHP_PIC"),
        gabi::EM_INTEL205 => Some("EM_INTEL205"),
        gabi::EM_INTEL206 => Some("EM_INTEL206"),
        gabi::EM_INTEL207 => Some("EM_INTEL207"),
        gabi::EM_INTEL208 => Some("EM_INTEL208"),
        gabi::EM_INTEL209 => Some("EM_INTEL209"),
        gabi::EM_KM32 => Some("EM_KM32"),
        gabi::EM_KMX32 => Some("EM_KMX32"),
        gabi::EM_KMX16 => Some("EM_KMX16"),
        gabi::EM_KMX8 => Some("EM_KMX8"),
        gabi::EM_KVARC => Some("EM_KVARC"),
        gabi::EM_CDP => Some("EM_CDP"),
        gabi::EM_COGE => Some("EM_COGE"),
        gabi::EM_COOL => Some("EM_COOL"),
        gabi::EM_NORC => Some("EM_NORC"),
        gabi::EM_CSR_KALIMBA => Some("EM_CSR_KALIMBA"),
        gabi::EM_Z80 => Some("EM_Z80"),
        gabi::EM_VISIUM => Some("EM_VISIUM"),
        gabi::EM_FT32 => Some("EM_FT32"),
        gabi::EM_MOXIE => Some("EM_MOXIE"),
        gabi::EM_AMDGPU => Some("EM_AMDGPU"),
        gabi::EM_RISCV => Some("RISC-V"),
        gabi::EM_BPF => Some("EM_BPF"),
        _ => None,
    }
}

impl core::fmt::Display for Architecture {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match e_machine_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "e_machine({})", self.0)
            }
        }
    }
}

pub fn sh_type_to_str(sh_type: u32) -> Option<&'static str> {
    match sh_type {
        gabi::SHT_NULL => Some("SHT_NULL"),
        gabi::SHT_PROGBITS => Some("SHT_PROGBITS"),
        gabi::SHT_SYMTAB => Some("SHT_SYMTAB"),
        gabi::SHT_STRTAB => Some("SHT_STRTAB"),
        gabi::SHT_RELA => Some("SHT_RELA"),
        gabi::SHT_HASH => Some("SHT_HASH"),
        gabi::SHT_DYNAMIC => Some("SHT_DYNAMIC"),
        gabi::SHT_NOTE => Some("SHT_NOTE"),
        gabi::SHT_NOBITS => Some("SHT_NOBITS"),
        gabi::SHT_REL => Some("SHT_REL"),
        gabi::SHT_SHLIB => Some("SHT_SHLIB"),
        gabi::SHT_DYNSYM => Some("SHT_DYNSYM"),
        gabi::SHT_INIT_ARRAY => Some("SHT_INIT_ARRAY"),
        gabi::SHT_FINI_ARRAY => Some("SHT_FINI_ARRAY"),
        gabi::SHT_PREINIT_ARRAY => Some("SHT_PREINIT_ARRAY"),
        gabi::SHT_GROUP => Some("SHT_GROUP"),
        gabi::SHT_SYMTAB_SHNDX => Some("SHT_SYMTAB_SHNDX"),
        gabi::SHT_GNU_ATTRIBUTES => Some("SHT_GNU_ATTRIBUTES"),
        gabi::SHT_GNU_HASH => Some("SHT_GNU_HASH"),
        gabi::SHT_GNU_LIBLIST => Some("SHT_GNU_LIBLIST"),
        gabi::SHT_GNU_VERDEF => Some("SHT_GNU_VERDEF"),
        gabi::SHT_GNU_VERNEED => Some("SHT_GNU_VERNEED"),
        gabi::SHT_GNU_VERSYM => Some("SHT_GNU_VERSYM"),
        _ => None,
    }
}

pub fn sh_type_to_string(sh_type: u32) -> String {
    match sh_type_to_str(sh_type) {
        Some(s) => s.to_string(),
        None => format!("sh_type({:#x})", sh_type),
    }
}

pub fn p_flags_to_string(p_flags: u32) -> String {
    match p_flags < 8 {
        true => {
            let r = if p_flags & gabi::PF_R != 0 { "R" } else { " " };
            let w = if p_flags & gabi::PF_W != 0 { "W" } else { " " };
            let x = if p_flags & gabi::PF_X != 0 { "E" } else { " " };
            format!("{r}{w}{x}")
        }
        false => format!("p_flags({:#x})", p_flags),
    }
}

pub fn p_type_to_str(p_type: u32) -> Option<&'static str> {
    match p_type {
        gabi::PT_NULL => Some("PT_NULL"),
        gabi::PT_LOAD => Some("PT_LOAD"),
        gabi::PT_DYNAMIC => Some("PT_DYNAMIC"),
        gabi::PT_INTERP => Some("PT_INTERP"),
        gabi::PT_NOTE => Some("PT_NOTE"),
        gabi::PT_SHLIB => Some("PT_SHLIB"),
        gabi::PT_PHDR => Some("PT_PHDR"),
        gabi::PT_TLS => Some("PT_TLS"),
        gabi::PT_GNU_EH_FRAME => Some("PT_GNU_EH_FRAME"),
        gabi::PT_GNU_STACK => Some("PT_GNU_STACK"),
        gabi::PT_GNU_RELRO => Some("PT_GNU_RELRO"),
        _ => None,
    }
}

pub fn p_type_to_string(p_type: u32) -> String {
    match p_type_to_str(p_type) {
        Some(s) => s.to_string(),
        None => format!("p_type({:#x})", p_type),
    }
}

pub fn st_symtype_to_str(st_symtype: u8) -> Option<&'static str> {
    match st_symtype {
        gabi::STT_NOTYPE => Some("STT_NOTYPE"),
        gabi::STT_OBJECT => Some("STT_OBJECT"),
        gabi::STT_FUNC => Some("STT_FUNC"),
        gabi::STT_SECTION => Some("STT_SECTION"),
        gabi::STT_FILE => Some("STT_FILE"),
        gabi::STT_COMMON => Some("STT_COMMON"),
        gabi::STT_TLS => Some("STT_TLS"),
        gabi::STT_GNU_IFUNC => Some("STT_GNU_IFUNC"),
        _ => None,
    }
}

pub fn st_symtype_to_string(st_symtype: u8) -> String {
    match st_symtype_to_str(st_symtype) {
        Some(s) => s.to_string(),
        None => format!("st_symtype({:#x})", st_symtype),
    }
}

pub fn st_bind_to_str(st_bind: u8) -> Option<&'static str> {
    match st_bind {
        gabi::STB_LOCAL => Some("STB_LOCAL"),
        gabi::STB_GLOBAL => Some("STB_GLOBAL"),
        gabi::STB_WEAK => Some("STB_WEAK"),
        gabi::STB_GNU_UNIQUE => Some("STB_GNU_UNIQUE"),
        _ => None,
    }
}

pub fn st_bind_to_string(st_bind: u8) -> String {
    match st_bind_to_str(st_bind) {
        Some(s) => s.to_string(),
        None => format!("st_bind({:#x})", st_bind),
    }
}

pub fn st_vis_to_str(st_vis: u8) -> Option<&'static str> {
    match st_vis {
        gabi::STV_DEFAULT => Some("STV_DEFAULT"),
        gabi::STV_INTERNAL => Some("STV_INTERNAL"),
        gabi::STV_HIDDEN => Some("STV_HIDDEN"),
        gabi::STV_PROTECTED => Some("STV_PROTECTED"),
        _ => None,
    }
}

pub fn st_vis_to_string(st_vis: u8) -> String {
    match st_vis_to_str(st_vis) {
        Some(s) => s.to_string(),
        None => format!("st_vis({:#x})", st_vis),
    }
}

pub fn ch_type_to_str(ch_type: u32) -> Option<&'static str> {
    match ch_type {
        gabi::ELFCOMPRESS_ZLIB => Some("ELFCOMPRESS_ZLIB"),
        gabi::ELFCOMPRESS_ZSTD => Some("ELFCOMPRESS_ZSTD "),
        _ => None,
    }
}
