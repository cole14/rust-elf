use std::fs;
use std::io;
use std::io::{Read, Seek};
use std::path::Path;

use crate::gabi;
use crate::parse::{Endian, Parse, ParseError, ReadExt, Reader};
use crate::section;
use crate::segment;
use crate::string_table::StringTable;
use crate::symbol;

pub struct File {
    pub ehdr: FileHeader,
    pub phdrs: Vec<segment::ProgramHeader>,
    pub sections: section::SectionTable,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?} {:?} {:?}", self.ehdr, self.phdrs, self.sections)
    }
}

impl std::fmt::Display for File {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{{ {} }}", self.ehdr)?;
        writeln!(f, "{{ ")?;
        for phdr in self.phdrs.iter() {
            writeln!(f, "    {}, ", phdr)?;
        }
        writeln!(f, "}}")?;
        writeln!(f, "{{")?;
        for shdr in self.sections.iter() {
            writeln!(f, "    {}, ", shdr)?;
        }
        write!(f, "}}")
    }
}

impl File {
    pub fn open_path<T: AsRef<Path>>(path: T) -> Result<File, ParseError> {
        // Open the file for reading
        let mut io_file = fs::File::open(path)?;

        File::open_stream(&mut io_file)
    }

    pub fn open_stream<T: Read + Seek>(io_file: &mut T) -> Result<File, ParseError> {
        let ehdr = FileHeader::parse(io_file)?;
        let mut reader = Reader::new(io_file, ehdr.endianness);

        // Parse the program headers
        reader.seek(io::SeekFrom::Start(ehdr.e_phoff))?;
        let mut phdrs = Vec::<segment::ProgramHeader>::default();

        for _ in 0..ehdr.e_phnum {
            let phdr = segment::ProgramHeader::parse(ehdr.class, &mut reader)?;
            phdrs.push(phdr);
        }

        let table = section::SectionTable::parse(&ehdr, &mut reader)?;

        Ok(File {
            ehdr: ehdr,
            phdrs: phdrs,
            sections: table,
        })
    }

    /// Get the symbol table (section of type SHT_SYMTAB) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_SYMTAB.
    pub fn symbol_table<'data>(
        &'data self,
    ) -> Result<Option<(symbol::SymbolTable<'data>, StringTable<'data>)>, ParseError> {
        return match self
            .sections
            .iter()
            .find(|section| section.shdr.sh_type == gabi::SHT_SYMTAB)
        {
            Some(section) => {
                let strtab_section = self.sections.get(section.shdr.sh_link as usize)?;
                let strtab = StringTable::new(strtab_section.data);
                Ok(Some((
                    symbol::SymbolTable::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        section.shdr.sh_entsize,
                        section.data,
                    )?,
                    strtab,
                )))
            }
            None => Ok(None),
        };
    }

    /// Get the dynamic symbol table (section of type SHT_DYNSYM) and its associated string table.
    ///
    /// The GABI specifies that ELF object files may have zero or one sections of type SHT_DYNSYM.
    pub fn dynamic_symbol_table<'data>(
        &'data self,
    ) -> Result<Option<(symbol::SymbolTable<'data>, StringTable<'data>)>, ParseError> {
        return match self
            .sections
            .iter()
            .find(|section| section.shdr.sh_type == gabi::SHT_DYNSYM)
        {
            Some(section) => {
                let strtab_section = self.sections.get(section.shdr.sh_link as usize)?;
                let strtab = StringTable::new(strtab_section.data);
                Ok(Some((
                    symbol::SymbolTable::new(
                        self.ehdr.endianness,
                        self.ehdr.class,
                        section.shdr.sh_entsize,
                        section.data,
                    )?,
                    strtab,
                )))
            }
            None => Ok(None),
        };
    }

    pub fn get_section(&self, name: &str) -> Option<section::Section> {
        self.sections.get_by_name(name)
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

// Read the platform-independent ident bytes
impl FileHeader {
    fn parse_ident<R: std::io::Read>(
        io_file: &mut R,
        buf: &mut [u8; gabi::EI_NIDENT],
    ) -> Result<(), ParseError> {
        io_file.read_exact(buf)?;

        // Verify the magic number
        let magic = buf.split_at(gabi::EI_CLASS).0;
        if magic != gabi::ELFMAGIC {
            return Err(ParseError(format!("Invalid Magic Bytes: {magic:?}")));
        }

        // Verify ELF Version
        let version = buf[gabi::EI_VERSION];
        if version != gabi::EV_CURRENT {
            return Err(ParseError(format!("Unsupported ELF Version: {version:?}")));
        }

        // Verify endianness is something we know how to parse
        let endian = buf[gabi::EI_DATA];
        if endian != gabi::ELFDATA2LSB && endian != gabi::ELFDATA2MSB {
            return Err(ParseError(format!(
                "Unsupported ELF Endianness: {endian:?}"
            )));
        }

        return Ok(());
    }

    pub fn parse<R: std::io::Read + std::io::Seek>(reader: &mut R) -> Result<Self, ParseError> {
        let mut ident = [0u8; gabi::EI_NIDENT];
        Self::parse_ident(reader, &mut ident)?;

        let class = Class(ident[gabi::EI_CLASS]);
        let endian = if ident[gabi::EI_DATA] == gabi::ELFDATA2LSB {
            Endian::Little
        } else {
            Endian::Big
        };

        let mut io_r = Reader::new(reader, endian);

        let elftype = ObjectFileType(io_r.read_u16()?);
        let arch = Architecture(io_r.read_u16()?);
        let version = io_r.read_u32()?;

        let entry: u64;
        let phoff: u64;
        let shoff: u64;

        if class == gabi::ELFCLASS32 {
            entry = io_r.read_u32()? as u64;
            phoff = io_r.read_u32()? as u64;
            shoff = io_r.read_u32()? as u64;
        } else {
            entry = io_r.read_u64()?;
            phoff = io_r.read_u64()?;
            shoff = io_r.read_u64()?;
        }

        let flags = io_r.read_u32()?;
        let ehsize = io_r.read_u16()?;
        let phentsize = io_r.read_u16()?;
        let phnum = io_r.read_u16()?;
        let shentsize = io_r.read_u16()?;
        let shnum = io_r.read_u16()?;
        let shstrndx = io_r.read_u16()?;

        return Ok(FileHeader {
            class: class,
            endianness: endian,
            version: version,
            elftype: elftype,
            arch: arch,
            osabi: OSABI(ident[gabi::EI_OSABI]),
            abiversion: ident[gabi::EI_ABIVERSION],
            e_entry: entry,
            e_phoff: phoff,
            e_shoff: shoff,
            e_flags: flags,
            e_ehsize: ehsize,
            e_phentsize: phentsize,
            e_phnum: phnum,
            e_shentsize: shentsize,
            e_shnum: shnum,
            e_shstrndx: shstrndx,
        });
    }
}

impl std::fmt::Display for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "File Header for {} {} Elf {} for {} {}",
            self.class, self.endianness, self.elftype, self.osabi, self.arch
        )
    }
}

/// Represents the ELF file class (32-bit vs 64-bit)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Class(pub u8);

// Allows us to do things like (self.ehdr.class == gabi::ELFCLASS32)
impl PartialEq<u8> for Class {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Debug for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::ELFCLASSNONE => "Invalid",
            gabi::ELFCLASS32 => "32-bit",
            gabi::ELFCLASS64 => "64-bit",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file OS ABI
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OSABI(pub u8);

impl std::fmt::Debug for OSABI {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for OSABI {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl std::fmt::Debug for ObjectFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for ObjectFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

impl std::fmt::Debug for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

#[cfg(test)]
mod interface_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_open_path() {
        let file = File::open_path(PathBuf::from("tests/samples/test1")).expect("Open test1");
        let bss = file
            .get_section(".bss")
            .expect("Could not find .bss section");
        assert!(bss.data.iter().all(|&b| b == 0));
    }
}

#[cfg(test)]
mod parse_tests {
    use crate::file::{Architecture, Class, Endian, FileHeader, ObjectFileType, OSABI};
    use crate::gabi;
    use std::io::Cursor;

    #[test]
    fn test_parse_ident_empty_buf_errors() {
        let data: [u8; 0] = [];
        let mut ident: [u8; gabi::EI_NIDENT] = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ident_valid() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_ok());
    }

    #[test]
    fn test_parse_ident_invalid_mag0() {
        let data: [u8; gabi::EI_NIDENT] = [
            42,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ident_invalid_mag1() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            42,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ident_invalid_mag2() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            42,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ident_invalid_mag3() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            42,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ident_invalid_version() {
        let data: [u8; gabi::EI_NIDENT] = [
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            42,
            gabi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mut ident = [0u8; gabi::EI_NIDENT];
        assert!(FileHeader::parse_ident(&mut data.as_ref(), &mut ident).is_err());
    }

    #[test]
    fn test_parse_ehdr32_works() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + 36, 0u8);
        for n in 0u8..36 {
            data[gabi::EI_NIDENT + n as usize] = n;
        }

        let slice = data.as_mut_slice();
        let mut cur = Cursor::new(slice.as_ref());
        assert_eq!(
            FileHeader::parse(&mut cur).unwrap(),
            FileHeader {
                class: Class(gabi::ELFCLASS32),
                endianness: Endian::Little,
                version: 0x7060504,
                osabi: OSABI(gabi::ELFOSABI_LINUX),
                abiversion: 7,
                elftype: ObjectFileType(0x100),
                arch: Architecture(0x302),
                e_entry: 0x0B0A0908,
                e_phoff: 0x0F0E0D0C,
                e_shoff: 0x13121110,
                e_flags: 0x17161514,
                e_ehsize: 0x1918,
                e_phentsize: 0x1B1A,
                e_phnum: 0x1D1C,
                e_shentsize: 0x1F1E,
                e_shnum: 0x2120,
                e_shstrndx: 0x2322,
            }
        );
    }

    #[test]
    fn test_parse_ehdr32_fuzz_too_short() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS32,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + 36, 0u8);

        for n in 0..36 {
            let mut cur = Cursor::new(data.as_mut_slice().split_at(gabi::EI_NIDENT + n).0.as_ref());
            assert!(FileHeader::parse(&mut cur).is_err());
        }
    }

    #[test]
    fn test_parse_ehdr64_works() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS64,
            gabi::ELFDATA2MSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + 48, 0u8);
        for n in 0u8..48 {
            data[gabi::EI_NIDENT + n as usize] = n;
        }

        let slice = data.as_mut_slice();
        let mut cur = Cursor::new(slice.as_ref());
        assert_eq!(
            FileHeader::parse(&mut cur).unwrap(),
            FileHeader {
                class: Class(gabi::ELFCLASS64),
                endianness: Endian::Big,
                version: 0x04050607,
                osabi: OSABI(gabi::ELFOSABI_LINUX),
                abiversion: 7,
                elftype: ObjectFileType(0x0001),
                arch: Architecture(0x0203),
                e_entry: 0x08090A0B0C0D0E0F,
                e_phoff: 0x1011121314151617,
                e_shoff: 0x18191A1B1C1D1E1F,
                e_flags: 0x20212223,
                e_ehsize: 0x2425,
                e_phentsize: 0x2627,
                e_phnum: 0x2829,
                e_shentsize: 0x2A2B,
                e_shnum: 0x2C2D,
                e_shstrndx: 0x2E2F,
            }
        );
    }

    #[test]
    fn test_parse_ehdr64_fuzz_too_short() {
        let mut data: Vec<u8> = vec![
            gabi::ELFMAG0,
            gabi::ELFMAG1,
            gabi::ELFMAG2,
            gabi::ELFMAG3,
            gabi::ELFCLASS64,
            gabi::ELFDATA2LSB,
            gabi::EV_CURRENT,
            gabi::ELFOSABI_LINUX,
            7,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        data.resize(gabi::EI_NIDENT + 48, 0u8);

        for n in 0..48 {
            let mut cur = Cursor::new(data.as_mut_slice().split_at(gabi::EI_NIDENT + n).0.as_ref());
            assert!(FileHeader::parse(&mut cur).is_err());
        }
    }
}
