use std::fmt;

use gabi;

/// Represents the ELF file class (32-bit vs 64-bit)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Class(pub u8);

// Allows us to do things like (self.ehdr.class == gabi::ELFCLASS32)
impl PartialEq<u8> for Class {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0 {
            gabi::ELFCLASSNONE => "Invalid",
            gabi::ELFCLASS32 => "32-bit",
            gabi::ELFCLASS64 => "64-bit",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Endian(pub u8);

impl fmt::Debug for Endian {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0 {
            gabi::ELFDATANONE => "Invalid",
            gabi::ELFDATA2LSB => "2's complement, little endian",
            gabi::ELFDATA2MSB => "2's complement, big endian",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file OS ABI
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OSABI(pub u8);

impl fmt::Debug for OSABI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for OSABI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0 {
            gabi::ELFOSABI_SYSV => "UNIX System V",
            gabi::ELFOSABI_HPUX => "HP-UX",
            gabi::ELFOSABI_NETBSD => "NetBSD",
            gabi::ELFOSABI_LINUX => "Linux with GNU extensions",
            gabi::ELFOSABI_SOLARIS => "Solaris",
            gabi::ELFOSABI_AIX => "AIX",
            gabi::ELFOSABI_IRIX => "SGI Irix",
            gabi::ELFOSABI_FREEBSD => "FreeBSD",
            gabi::ELFOSABI_TRU64 => "Compaq TRU64 UNIX",
            gabi::ELFOSABI_MODESTO => "Novell Modesto",
            gabi::ELFOSABI_OPENBSD => "OpenBSD",
            gabi::ELFOSABI_OPENVMS => "Open VMS",
            gabi::ELFOSABI_NSK => "Hewlett-Packard Non-Stop Kernel",
            gabi::ELFOSABI_AROS => "Amiga Research OS",
            gabi::ELFOSABI_FENIXOS => "The FenixOS highly scalable multi-core OS",
            gabi::ELFOSABI_CLOUDABI => "Nuxi CloudABI",
            gabi::ELFOSABI_OPENVOS => "Stratus Technologies OpenVOS",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file type (object, executable, shared lib, core)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ObjectFileType(pub u16);

impl fmt::Debug for ObjectFileType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for ObjectFileType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0 {
            gabi::ET_NONE => "No file type",
            gabi::ET_REL => "Relocatable file",
            gabi::ET_EXEC => "Executable file",
            gabi::ET_DYN => "Shared object file",
            gabi::ET_CORE => "Core file",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file machine architecture
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Architecture(pub u16);

impl fmt::Debug for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self.0 {
            gabi::EM_NONE => "No machine",
            gabi::EM_M32 => "AT&T WE 32100",
            gabi::EM_SPARC => "SPARC",
            gabi::EM_386 => "Intel 80386",
            gabi::EM_68K => "Motorola 68000",
            gabi::EM_88K => "Motorola 88000",
            gabi::EM_IAMCU => "Intel MCU",
            gabi::EM_860 => "Intel 80860",
            gabi::EM_MIPS => "MIPS I Architecture",
            gabi::EM_S370 => "IBM System/370 Processor",
            gabi::EM_MIPS_RS3_LE => "MIPS RS3000 Little-endian",
            gabi::EM_PARISC => "Hewlett-Packard PA-RISC",
            gabi::EM_VPP500 => "Fujitsu VPP500",
            gabi::EM_SPARC32PLUS => "Enhanced instruction set SPARC",
            gabi::EM_960 => "Intel 80960",
            gabi::EM_PPC => "PowerPC",
            gabi::EM_PPC64 => "64-bit PowerPC",
            gabi::EM_S390 => "IBM System/390 Processor",
            gabi::EM_SPU => "IBM SPU/SPC",
            gabi::EM_V800 => "NEC V800",
            gabi::EM_FR20 => "Fujitsu FR20",
            gabi::EM_RH32 => "TRW RH-32",
            gabi::EM_RCE => "Motorola RCE",
            gabi::EM_ARM => "ARM 32-bit architecture (AARCH32)",
            gabi::EM_ALPHA => "Digital Alpha",
            gabi::EM_SH => "Hitachi SH",
            gabi::EM_SPARCV9 => "SPARC Version 9",
            gabi::EM_TRICORE => "Siemens TriCore embedded processor",
            gabi::EM_ARC => "Argonaut RISC Core, Argonaut Technologies Inc.",
            gabi::EM_H8_300 => "Hitachi H8/300",
            gabi::EM_H8_300H => "Hitachi H8/300H",
            gabi::EM_H8S => "Hitachi H8S",
            gabi::EM_H8_500 => "Hitachi H8/500",
            gabi::EM_IA_64 => "Intel IA-64 processor architecture",
            gabi::EM_MIPS_X => "Stanford MIPS-X",
            gabi::EM_COLDFIRE => "Motorola ColdFire",
            gabi::EM_68HC12 => "Motorola M68HC12",
            gabi::EM_MMA => "Fujitsu MMA Multimedia Accelerator",
            gabi::EM_PCP => "Siemens PCP",
            gabi::EM_NCPU => "Sony nCPU embedded RISC processor",
            gabi::EM_NDR1 => "Denso NDR1 microprocessor",
            gabi::EM_STARCORE => "Motorola Star*Core processor",
            gabi::EM_ME16 => "Toyota ME16 processor",
            gabi::EM_ST100 => "STMicroelectronics ST100 processor",
            gabi::EM_TINYJ => "Advanced Logic Corp. TinyJ embedded processor family",
            gabi::EM_X86_64 => "AMD x86-64 architecture",
            gabi::EM_PDSP => "Sony DSP Processor",
            gabi::EM_PDP10 => "Digital Equipment Corp. PDP-10",
            gabi::EM_PDP11 => "Digital Equipment Corp. PDP-11",
            gabi::EM_FX66 => "Siemens FX66 microcontroller",
            gabi::EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 bit microcontroller",
            gabi::EM_ST7 => "STMicroelectronics ST7 8-bit microcontroller",
            gabi::EM_68HC16 => "Motorola MC68HC16 Microcontroller",
            gabi::EM_68HC11 => "Motorola MC68HC11 Microcontroller",
            gabi::EM_68HC08 => "Motorola MC68HC08 Microcontroller",
            gabi::EM_68HC05 => "Motorola MC68HC05 Microcontroller",
            gabi::EM_SVX => "Silicon Graphics SVx",
            gabi::EM_ST19 => "STMicroelectronics ST19 8-bit microcontroller",
            gabi::EM_VAX => "Digital VAX",
            gabi::EM_CRIS => "Axis Communications 32-bit embedded processor",
            gabi::EM_JAVELIN => "Infineon Technologies 32-bit embedded processor",
            gabi::EM_FIREPATH => "Element 14 64-bit DSP Processor",
            gabi::EM_ZSP => "LSI Logic 16-bit DSP Processor",
            gabi::EM_MMIX => "Donald Knuth's educational 64-bit processor",
            gabi::EM_HUANY => "Harvard University machine-independent object files",
            gabi::EM_PRISM => "SiTera Prism",
            gabi::EM_AVR => "Atmel AVR 8-bit microcontroller",
            gabi::EM_FR30 => "Fujitsu FR30",
            gabi::EM_D10V => "Mitsubishi D10V",
            gabi::EM_D30V => "Mitsubishi D30V",
            gabi::EM_V850 => "NEC v850",
            gabi::EM_M32R => "Mitsubishi M32R",
            gabi::EM_MN10300 => "Matsushita MN10300",
            gabi::EM_MN10200 => "Matsushita MN10200",
            gabi::EM_PJ => "picoJava",
            gabi::EM_OPENRISC => "OpenRISC 32-bit embedded processor",
            gabi::EM_ARC_COMPACT => {
                "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)"
            }
            gabi::EM_XTENSA => "Tensilica Xtensa Architecture",
            gabi::EM_VIDEOCORE => "Alphamosaic VideoCore processor",
            gabi::EM_TMM_GPP => "Thompson Multimedia General Purpose Processor",
            gabi::EM_NS32K => "National Semiconductor 32000 series",
            gabi::EM_TPC => "Tenor Network TPC processor",
            gabi::EM_SNP1K => "Trebia SNP 1000 processor",
            gabi::EM_ST200 => "STMicroelectronics (www.st.com) ST200 microcontroller",
            gabi::EM_IP2K => "Ubicom IP2xxx microcontroller family",
            gabi::EM_MAX => "MAX Processor",
            gabi::EM_CR => "National Semiconductor CompactRISC microprocessor",
            gabi::EM_F2MC16 => "Fujitsu F2MC16",
            gabi::EM_MSP430 => "Texas Instruments embedded microcontroller msp430",
            gabi::EM_BLACKFIN => "Analog Devices Blackfin (DSP) processor",
            gabi::EM_SE_C33 => "S1C33 Family of Seiko Epson processors",
            gabi::EM_SEP => "Sharp embedded microprocessor",
            gabi::EM_ARCA => "Arca RISC Microprocessor",
            gabi::EM_UNICORE => {
                "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University"
            }
            gabi::EM_EXCESS => "eXcess: 16/32/64-bit configurable embedded CPU",
            gabi::EM_DXP => "Icera Semiconductor Inc. Deep Execution Processor",
            gabi::EM_ALTERA_NIOS2 => "Altera Nios II soft-core processor",
            gabi::EM_CRX => "National Semiconductor CompactRISC CRX microprocessor",
            gabi::EM_XGATE => "Motorola XGATE embedded processor",
            gabi::EM_C166 => "Infineon C16x/XC16x processor",
            gabi::EM_M16C => "Renesas M16C series microprocessors",
            gabi::EM_DSPIC30F => "Microchip Technology dsPIC30F Digital Signal Controller",
            gabi::EM_CE => "Freescale Communication Engine RISC core",
            gabi::EM_M32C => "Renesas M32C series microprocessors",
            gabi::EM_TSK3000 => "Altium TSK3000 core",
            gabi::EM_RS08 => "Freescale RS08 embedded processor",
            gabi::EM_SHARC => "Analog Devices SHARC family of 32-bit DSP processors",
            gabi::EM_ECOG2 => "Cyan Technology eCOG2 microprocessor",
            gabi::EM_SCORE7 => "Sunplus S+core7 RISC processor",
            gabi::EM_DSP24 => "New Japan Radio (NJR) 24-bit DSP Processor",
            gabi::EM_VIDEOCORE3 => "Broadcom VideoCore III processor",
            gabi::EM_LATTICEMICO32 => "RISC processor for Lattice FPGA architecture",
            gabi::EM_SE_C17 => "Seiko Epson C17 family",
            gabi::EM_TI_C6000 => "The Texas Instruments TMS320C6000 DSP family",
            gabi::EM_TI_C2000 => "The Texas Instruments TMS320C2000 DSP family",
            gabi::EM_TI_C5500 => "The Texas Instruments TMS320C55x DSP family",
            gabi::EM_TI_ARP32 => {
                "Texas Instruments Application Specific RISC Processor, 32bit fetch"
            }
            gabi::EM_TI_PRU => "Texas Instruments Programmable Realtime Unit",
            gabi::EM_MMDSP_PLUS => "STMicroelectronics 64bit VLIW Data Signal Processor",
            gabi::EM_CYPRESS_M8C => "Cypress M8C microprocessor",
            gabi::EM_R32C => "Renesas R32C series microprocessors",
            gabi::EM_TRIMEDIA => "NXP Semiconductors TriMedia architecture family",
            gabi::EM_QDSP6 => "QUALCOMM DSP6 Processor",
            gabi::EM_8051 => "Intel 8051 and variants",
            gabi::EM_STXP7X => {
                "STMicroelectronics STxP7x family of configurable and extensible RISC processors"
            }
            gabi::EM_NDS32 => "Andes Technology compact code size embedded RISC processor family",
            gabi::EM_ECOG1X => "Cyan Technology eCOG1X family",
            gabi::EM_MAXQ30 => "Dallas Semiconductor MAXQ30 Core Micro-controllers",
            gabi::EM_XIMO16 => "New Japan Radio (NJR) 16-bit DSP Processor",
            gabi::EM_MANIK => "M2000 Reconfigurable RISC Microprocessor",
            gabi::EM_CRAYNV2 => "Cray Inc. NV2 vector architecture",
            gabi::EM_RX => "Renesas RX family",
            gabi::EM_METAG => "Imagination Technologies META processor architecture",
            gabi::EM_MCST_ELBRUS => "MCST Elbrus general purpose hardware architecture",
            gabi::EM_ECOG16 => "Cyan Technology eCOG16 family",
            gabi::EM_CR16 => "National Semiconductor CompactRISC CR16 16-bit microprocessor",
            gabi::EM_ETPU => "Freescale Extended Time Processing Unit",
            gabi::EM_SLE9X => "Infineon Technologies SLE9X core",
            gabi::EM_L10M => "Intel L10M",
            gabi::EM_K10M => "Intel K10M",
            gabi::EM_AARCH64 => "ARM 64-bit architecture (AARCH64)",
            gabi::EM_AVR32 => "Atmel Corporation 32-bit microprocessor family",
            gabi::EM_STM8 => "STMicroeletronics STM8 8-bit microcontroller",
            gabi::EM_TILE64 => "Tilera TILE64 multicore architecture family",
            gabi::EM_TILEPRO => "Tilera TILEPro multicore architecture family",
            gabi::EM_MICROBLAZE => "Xilinx MicroBlaze 32-bit RISC soft processor core",
            gabi::EM_CUDA => "NVIDIA CUDA architecture",
            gabi::EM_TILEGX => "Tilera TILE-Gx multicore architecture family",
            gabi::EM_CLOUDSHIELD => "CloudShield architecture family",
            gabi::EM_COREA_1ST => "KIPO-KAIST Core-A 1st generation processor family",
            gabi::EM_COREA_2ND => "KIPO-KAIST Core-A 2nd generation processor family",
            gabi::EM_ARC_COMPACT2 => "Synopsys ARCompact V2",
            gabi::EM_OPEN8 => "Open8 8-bit RISC soft processor core",
            gabi::EM_RL78 => "Renesas RL78 family",
            gabi::EM_VIDEOCORE5 => "Broadcom VideoCore V processor",
            gabi::EM_78KOR => "Renesas 78KOR family",
            gabi::EM_56800EX => "Freescale 56800EX Digital Signal Controller (DSC)",
            gabi::EM_BA1 => "Beyond BA1 CPU architecture",
            gabi::EM_BA2 => "Beyond BA2 CPU architecture",
            gabi::EM_XCORE => "XMOS xCORE processor family",
            gabi::EM_MCHP_PIC => "Microchip 8-bit PIC(r) family",
            gabi::EM_INTEL205 => "Reserved by Intel",
            gabi::EM_INTEL206 => "Reserved by Intel",
            gabi::EM_INTEL207 => "Reserved by Intel",
            gabi::EM_INTEL208 => "Reserved by Intel",
            gabi::EM_INTEL209 => "Reserved by Intel",
            gabi::EM_KM32 => "KM211 KM32 32-bit processor",
            gabi::EM_KMX32 => "KM211 KMX32 32-bit processor",
            gabi::EM_KMX16 => "KM211 KMX16 16-bit processor",
            gabi::EM_KMX8 => "KM211 KMX8 8-bit processor",
            gabi::EM_KVARC => "KM211 KVARC processor",
            gabi::EM_CDP => "Paneve CDP architecture family",
            gabi::EM_COGE => "Cognitive Smart Memory Processor",
            gabi::EM_COOL => "Bluechip Systems CoolEngine",
            gabi::EM_NORC => "Nanoradio Optimized RISC",
            gabi::EM_CSR_KALIMBA => "CSR Kalimba architecture family",
            gabi::EM_Z80 => "Zilog Z80",
            gabi::EM_VISIUM => "Controls and Data Services VISIUMcore processor",
            gabi::EM_FT32 => "FTDI Chip FT32 high performance 32-bit RISC architecture",
            gabi::EM_MOXIE => "Moxie processor family",
            gabi::EM_AMDGPU => "AMD GPU architecture",
            gabi::EM_RISCV => "RISC-V",
            gabi::EM_BPF => "Linux BPF",
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
    pub class: Class,
    /// little vs big endian
    pub endianness: Endian,
    /// elf version
    pub version: u32,
    /// OS ABI
    pub osabi: OSABI,
    /// Version of the OS ABI
    pub abiversion: u8,
    /// ELF file type
    pub elftype: ObjectFileType,
    /// Target machine architecture
    pub arch: Architecture,
    /// Virtual address of program entry point
    /// This member gives the virtual address to which the system first transfers control,
    /// thus starting the process. If the file has no associated entry point, this member holds zero.
    ///
    /// Note: Type is Elf32_Addr or Elf64_Addr which are either 4 or 8 bytes. We aren't trying to zero-copy
    /// parse the FileHeader since there's only one per file and its only ~45 bytes anyway, so we use
    /// u64 for the three Elf*_Addr and Elf*_Off fields here.
    pub e_entry: u64,
    /// This member holds the program header table's file offset in bytes. If the file has no program header
    /// table, this member holds zero.
    pub e_phoff: u64,
    /// This member holds the section header table's file offset in bytes. If the file has no section header
    /// table, this member holds zero.
    pub e_shoff: u64,
    /// This member holds processor-specific flags associated with the file. Flag names take the form EF_machine_flag.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table. Thus the product of e_phentsize and e_phnum
    /// gives the table's size in bytes. If a file has no program header table, e_phnum holds the value zero.
    pub e_phnum: u16,
    /// This member holds a section header's size in bytes. A section header is one entry in the section header table;
    /// all entries are the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table. Thus the product of e_shentsize and e_shnum
    /// gives the section header table's size in bytes. If a file has no section header table, e_shnum holds the value zero.
    ///
    /// If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), this member has the value zero and
    /// the actual number of section header table entries is contained in the sh_size field of the section header at index 0.
    /// (Otherwise, the sh_size member of the initial entry contains 0.)
    pub e_shnum: u16,
    /// This member holds the section header table index of the entry associated with the section name string table. If the
    /// file has no section name string table, this member holds the value SHN_UNDEF.
    ///
    /// If the section name string table section index is greater than or equal to SHN_LORESERVE (0xff00), this member has
    /// the value SHN_XINDEX (0xffff) and the actual index of the section name string table section is contained in the
    /// sh_link field of the section header at index 0. (Otherwise, the sh_link member of the initial entry contains 0.)
    pub e_shstrndx: u16,
}

impl FileHeader {
    pub fn new() -> FileHeader {
        FileHeader {
            class: Class(gabi::ELFCLASSNONE),
            endianness: Endian(gabi::ELFDATANONE),
            version: gabi::EV_NONE as u32,
            elftype: ObjectFileType(gabi::ET_NONE),
            arch: Architecture(gabi::EM_NONE),
            osabi: OSABI(gabi::ELFOSABI_NONE),
            abiversion: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "File Header for {} {} Elf {} for {} {}",
            self.class, self.endianness, self.elftype, self.osabi, self.arch
        )
    }
}

/// Represents ELF Program Header flags
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgFlag(pub u32);
pub const PF_NONE: ProgFlag = ProgFlag(0);
/// Executable program segment
pub const PF_X: ProgFlag = ProgFlag(1);
/// Writable program segment
pub const PF_W: ProgFlag = ProgFlag(2);
/// Readable program segment
pub const PF_R: ProgFlag = ProgFlag(4);

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
pub const PT_NULL: ProgType = ProgType(0);
/// Loadable program segment
pub const PT_LOAD: ProgType = ProgType(1);
/// Dynamic linking information
pub const PT_DYNAMIC: ProgType = ProgType(2);
/// Program interpreter
pub const PT_INTERP: ProgType = ProgType(3);
/// Auxiliary information
pub const PT_NOTE: ProgType = ProgType(4);
/// Unused
pub const PT_SHLIB: ProgType = ProgType(5);
/// The program header table
pub const PT_PHDR: ProgType = ProgType(6);
/// Thread-local storage segment
pub const PT_TLS: ProgType = ProgType(7);
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: ProgType = ProgType(0x6474e550);
/// Indicates stack executability
pub const PT_GNU_STACK: ProgType = ProgType(0x6474e551);
/// Read-only after relocation
pub const PT_GNU_RELRO: ProgType = ProgType(0x6474e552);

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
    pub offset: u64,
    /// Virtual adress where this segment should be loaded
    pub vaddr: u64,
    /// Physical address where this segment should be loaded
    pub paddr: u64,
    /// Size of this segment in the file
    pub filesz: u64,
    /// Size of this segment in memory
    pub memsz: u64,
    /// Flags for this segment
    pub flags: ProgFlag,
    /// file and memory alignment
    pub align: u64,
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
pub const SHT_NULL: SectionType = SectionType(0);
/// Information defined by the program, includes executable code and data
pub const SHT_PROGBITS: SectionType = SectionType(1);
/// Section data contains a symbol table
pub const SHT_SYMTAB: SectionType = SectionType(2);
/// Section data contains a string table
pub const SHT_STRTAB: SectionType = SectionType(3);
/// Section data contains relocation entries with explicit addends
pub const SHT_RELA: SectionType = SectionType(4);
/// Section data contains a symbol hash table. Must be present for dynamic linking
pub const SHT_HASH: SectionType = SectionType(5);
/// Section data contains information for dynamic linking
pub const SHT_DYNAMIC: SectionType = SectionType(6);
/// Section data contains information that marks the file in some way
pub const SHT_NOTE: SectionType = SectionType(7);
/// Section data occupies no space in the file but otherwise resembles SHT_PROGBITS
pub const SHT_NOBITS: SectionType = SectionType(8);
/// Section data contains relocation entries without explicit addends
pub const SHT_REL: SectionType = SectionType(9);
/// Section is reserved but has unspecified semantics
pub const SHT_SHLIB: SectionType = SectionType(10);
/// Section data contains a minimal set of dynamic linking symbols
pub const SHT_DYNSYM: SectionType = SectionType(11);
/// Section data contains an array of constructors
pub const SHT_INIT_ARRAY: SectionType = SectionType(14);
/// Section data contains an array of destructors
pub const SHT_FINI_ARRAY: SectionType = SectionType(15);
/// Section data contains an array of pre-constructors
pub const SHT_PREINIT_ARRAY: SectionType = SectionType(16);
/// Section group
pub const SHT_GROUP: SectionType = SectionType(17);
/// Extended symbol table section index
pub const SHT_SYMTAB_SHNDX: SectionType = SectionType(18);
/// Number of reserved SHT_* values
pub const SHT_NUM: SectionType = SectionType(19);
/// Object attributes
pub const SHT_GNU_ATTRIBUTES: SectionType = SectionType(0x6ffffff5);
/// GNU-style hash section
pub const SHT_GNU_HASH: SectionType = SectionType(0x6ffffff6);
/// Pre-link library list
pub const SHT_GNU_LIBLIST: SectionType = SectionType(0x6ffffff7);
/// Version definition section
pub const SHT_GNU_VERDEF: SectionType = SectionType(0x6ffffffd);
/// Version needs section
pub const SHT_GNU_VERNEED: SectionType = SectionType(0x6ffffffe);
/// Version symbol table
pub const SHT_GNU_VERSYM: SectionType = SectionType(0x6fffffff);

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
pub const SHF_NONE: SectionFlag = SectionFlag(0);
/// Writable
pub const SHF_WRITE: SectionFlag = SectionFlag(1);
/// Occupies memory during execution
pub const SHF_ALLOC: SectionFlag = SectionFlag(2);
/// Executable
pub const SHF_EXECINSTR: SectionFlag = SectionFlag(4);
/// Might be merged
pub const SHF_MERGE: SectionFlag = SectionFlag(16);
/// Contains nul-terminated strings
pub const SHF_STRINGS: SectionFlag = SectionFlag(32);
/// `sh_info' contains SHT index
pub const SHF_INFO_LINK: SectionFlag = SectionFlag(64);
/// Preserve order after combining
pub const SHF_LINK_ORDER: SectionFlag = SectionFlag(128);
/// Non-standard OS specific handling required
pub const SHF_OS_NONCONFORMING: SectionFlag = SectionFlag(256);
/// Section is member of a group
pub const SHF_GROUP: SectionFlag = SectionFlag(512);
/// Section hold thread-local data
pub const SHF_TLS: SectionFlag = SectionFlag(1024);

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
    pub name: String,
    /// Section Type
    pub shtype: SectionType,
    /// Section Flags
    pub flags: SectionFlag,
    /// in-memory address where this section is loaded
    pub addr: u64,
    /// Byte-offset into the file where this section starts
    pub offset: u64,
    /// Section size in bytes
    pub size: u64,
    /// Defined by section type
    pub link: u32,
    /// Defined by section type
    pub info: u32,
    /// address alignment
    pub addralign: u64,
    /// size of an entry if section data is an array of entries
    pub entsize: u64,
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
pub const STT_NOTYPE: SymbolType = SymbolType(0);
/// Data object symbol
pub const STT_OBJECT: SymbolType = SymbolType(1);
/// Code object symbol
pub const STT_FUNC: SymbolType = SymbolType(2);
/// Section symbol
pub const STT_SECTION: SymbolType = SymbolType(3);
/// File name symbol
pub const STT_FILE: SymbolType = SymbolType(4);
/// Common data object symbol
pub const STT_COMMON: SymbolType = SymbolType(5);
/// Thread-local data object symbol
pub const STT_TLS: SymbolType = SymbolType(6);
/// Indirect code object symbol
pub const STT_GNU_IFUNC: SymbolType = SymbolType(10);

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
pub const STB_LOCAL: SymbolBind = SymbolBind(0);
/// Global symbol
pub const STB_GLOBAL: SymbolBind = SymbolBind(1);
/// Weak symbol
pub const STB_WEAK: SymbolBind = SymbolBind(2);
/// Unique symbol
pub const STB_GNU_UNIQUE: SymbolBind = SymbolBind(10);

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
pub const STV_DEFAULT: SymbolVis = SymbolVis(0);
/// Processor-specific hidden visibility
pub const STV_INTERNAL: SymbolVis = SymbolVis(1);
/// Hidden visibility
pub const STV_HIDDEN: SymbolVis = SymbolVis(2);
/// Protected visibility
pub const STV_PROTECTED: SymbolVis = SymbolVis(3);

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
        write!(
            f,
            "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.value, self.size, self.symtype, self.bind, self.vis, self.shndx, self.name
        )
    }
}
