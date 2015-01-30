
use std::fmt;
use std::default;

///
/// Values and locations for parsing elf header ident byte array
///
pub const EI_NIDENT: usize = 16;
pub const ELFMAGIC: [u8;4] = [0x7f, 0x45, 0x4c, 0x46];
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;
pub const EI_ABIVERSION: usize = 8;

///
/// Wrapper type for Class
///
#[derive(Copy, PartialEq)]
pub struct Class(pub u8);
pub const ELFCLASSNONE : Class = Class(0);
pub const ELFCLASS32 : Class = Class(1);
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

///
/// Wrapper type for Data
///
#[derive(Copy, PartialEq)]
pub struct Data(pub u8);
pub const ELFDATANONE : Data = Data(0);
pub const ELFDATA2LSB : Data = Data(1);
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

///
/// Wrapper type for Version
/// This field represents the values both found in the e_ident byte array
/// and the e_version field.
///
#[derive(Copy)]
pub struct Version(pub u32);
pub const EV_NONE : Version = Version(0);
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

///
/// Wrapper type for OSABI
///
#[derive(Copy)]
pub struct OSABI(pub u8);
pub const ELFOSABI_NONE : OSABI = OSABI(0);
pub const ELFOSABI_SYSV : OSABI = OSABI(0);
pub const ELFOSABI_HPUX : OSABI = OSABI(1);
pub const ELFOSABI_NETBSD : OSABI = OSABI(2);
pub const ELFOSABI_LINUX : OSABI = OSABI(3);
pub const ELFOSABI_SOLARIS : OSABI = OSABI(6);
pub const ELFOSABI_AIX : OSABI = OSABI(7);
pub const ELFOSABI_IRIX : OSABI = OSABI(8);
pub const ELFOSABI_FREEBSD : OSABI = OSABI(9);
pub const ELFOSABI_TRU64 : OSABI = OSABI(10);
pub const ELFOSABI_MODESTO : OSABI = OSABI(11);
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
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

///
/// Wrapper type for Type
///
#[derive(Copy)]
pub struct Type(pub u16);
pub const ET_NONE : Type = Type(0);
pub const ET_REL : Type = Type(1);
pub const ET_EXEC : Type = Type(2);
pub const ET_DYN : Type = Type(3);
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

///
/// Wrapper type for Machine
///
#[derive(Copy)]
pub struct Machine(pub u16);
pub const EM_NONE : Machine = Machine(0);
pub const EM_M32 : Machine = Machine(1);
pub const EM_SPARC : Machine = Machine(2);
pub const EM_386 : Machine = Machine(3);
pub const EM_68K : Machine = Machine(4);
pub const EM_88K : Machine = Machine(5);
pub const EM_860 : Machine = Machine(7);
pub const EM_MIPS : Machine = Machine(8);
pub const EM_S370 : Machine = Machine(9);
pub const EM_MIPS_RS3_LE : Machine = Machine(10);
pub const EM_PARISC : Machine = Machine(15);
pub const EM_VPP500 : Machine = Machine(17);
pub const EM_SPARC32PLUS : Machine = Machine(18);
pub const EM_960 : Machine = Machine(19);
pub const EM_PPC : Machine = Machine(20);
pub const EM_PPC64 : Machine = Machine(21);
pub const EM_S390 : Machine = Machine(22);
pub const EM_V800 : Machine = Machine(36);
pub const EM_FR20 : Machine = Machine(37);
pub const EM_RH32 : Machine = Machine(38);
pub const EM_RCE : Machine = Machine(39);
pub const EM_ARM : Machine = Machine(40);
pub const EM_FAKE_ALPHA : Machine = Machine(41);
pub const EM_SH : Machine = Machine(42);
pub const EM_SPARCV9 : Machine = Machine(43);
pub const EM_TRICORE : Machine = Machine(44);
pub const EM_ARC : Machine = Machine(45);
pub const EM_H8_300 : Machine = Machine(46);
pub const EM_H8_300H : Machine = Machine(47);
pub const EM_H8S : Machine = Machine(48);
pub const EM_H8_500 : Machine = Machine(49);
pub const EM_IA_64 : Machine = Machine(50);
pub const EM_MIPS_X : Machine = Machine(51);
pub const EM_COLDFIRE : Machine = Machine(52);
pub const EM_68HC12 : Machine = Machine(53);
pub const EM_MMA : Machine = Machine(54);
pub const EM_PCP : Machine = Machine(55);
pub const EM_NCPU : Machine = Machine(56);
pub const EM_NDR1 : Machine = Machine(57);
pub const EM_STARCORE : Machine = Machine(58);
pub const EM_ME16 : Machine = Machine(59);
pub const EM_ST100 : Machine = Machine(60);
pub const EM_TINYJ : Machine = Machine(61);
pub const EM_X86_64 : Machine = Machine(62);
pub const EM_PDSP : Machine = Machine(63);
pub const EM_FX66 : Machine = Machine(66);
pub const EM_ST9PLUS : Machine = Machine(67);
pub const EM_ST7 : Machine = Machine(68);
pub const EM_68HC16 : Machine = Machine(69);
pub const EM_68HC11 : Machine = Machine(70);
pub const EM_68HC08 : Machine = Machine(71);
pub const EM_68HC05 : Machine = Machine(72);
pub const EM_SVX : Machine = Machine(73);
pub const EM_ST19 : Machine = Machine(74);
pub const EM_VAX : Machine = Machine(75);
pub const EM_CRIS : Machine = Machine(76);
pub const EM_JAVELIN : Machine = Machine(77);
pub const EM_FIREPATH : Machine = Machine(78);
pub const EM_ZSP : Machine = Machine(79);
pub const EM_MMIX : Machine = Machine(80);
pub const EM_HUANY : Machine = Machine(81);
pub const EM_PRISM : Machine = Machine(82);
pub const EM_AVR : Machine = Machine(83);
pub const EM_FR30 : Machine = Machine(84);
pub const EM_D10V : Machine = Machine(85);
pub const EM_D30V : Machine = Machine(86);
pub const EM_V850 : Machine = Machine(87);
pub const EM_M32R : Machine = Machine(88);
pub const EM_MN10300 : Machine = Machine(89);
pub const EM_MN10200 : Machine = Machine(90);
pub const EM_PJ : Machine = Machine(91);
pub const EM_OPENRISC : Machine = Machine(92);
pub const EM_ARC_A5 : Machine = Machine(93);
pub const EM_XTENSA : Machine = Machine(94);
pub const EM_AARCH64 : Machine = Machine(183);
pub const EM_TILEPRO : Machine = Machine(188);
pub const EM_MICROBLAZE : Machine = Machine(189);
pub const EM_TILEGX : Machine = Machine(191);

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
            EM_SPARC => "SUN SPARC",
            EM_386 => "Intel 80386",
            EM_68K => "Motorola m68k family",
            EM_88K => "Motorola m88k family",
            EM_860 => "Intel 80860",
            EM_MIPS => "MIPS R3000 big-endian",
            EM_S370 => "IBM System/370",
            EM_MIPS_RS3_LE => "MIPS R3000 little-endian",
            EM_PARISC => "HPPA",
            EM_VPP500 => "Fujitsu VPP500",
            EM_SPARC32PLUS => "Sun's 'v8plus'",
            EM_960 => "Intel 80960",
            EM_PPC => "PowerPC",
            EM_PPC64 => "PowerPC 64-bit",
            EM_S390 => "IBM S390",
            EM_V800 => "NEC V800 series",
            EM_FR20 => "Fujitsu FR20",
            EM_RH32 => "TRW RH-32",
            EM_RCE => "Motorola RCE",
            EM_ARM => "ARM",
            EM_FAKE_ALPHA => "Digital Alpha",
            EM_SH => "Hitachi SH",
            EM_SPARCV9 => "SPARC v9 64-bit",
            EM_TRICORE => "Siemens Tricore",
            EM_ARC => "Argonaut RISC Core",
            EM_H8_300 => "Hitachi H8/300",
            EM_H8_300H => "Hitachi H8/300H",
            EM_H8S => "Hitachi H8S",
            EM_H8_500 => "Hitachi H8/500",
            EM_IA_64 => "Intel Merced",
            EM_MIPS_X => "Stanford MIPS-X",
            EM_COLDFIRE => "Motorola Coldfire",
            EM_68HC12 => "Motorola M68HC12",
            EM_MMA => "Fujitsu MMA Multimedia Accelerato",
            EM_PCP => "Siemens PCP",
            EM_NCPU => "Sony nCPU embeeded RISC",
            EM_NDR1 => "Denso NDR1 microprocessor",
            EM_STARCORE => "Motorola Start*Core processor",
            EM_ME16 => "Toyota ME16 processor",
            EM_ST100 => "STMicroelectronic ST100 processor",
            EM_TINYJ => "Advanced Logic Corp. Tinyj emb.fa",
            EM_X86_64 => "AMD x86-64 architecture",
            EM_PDSP => "Sony DSP Processor",
            EM_FX66 => "Siemens FX66 microcontroller",
            EM_ST9PLUS => "STMicroelectronics ST9+ 8/16 mc",
            EM_ST7 => "STmicroelectronics ST7 8 bit mc",
            EM_68HC16 => "Motorola MC68HC16 microcontroller",
            EM_68HC11 => "Motorola MC68HC11 microcontroller",
            EM_68HC08 => "Motorola MC68HC08 microcontroller",
            EM_68HC05 => "Motorola MC68HC05 microcontroller",
            EM_SVX => "Silicon Graphics SVx",
            EM_ST19 => "STMicroelectronics ST19 8 bit mc",
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
            EM_ARC_A5 => "ARC Cores Tangent-A5",
            EM_XTENSA => "Tensilica Xtensa Architecture",
            EM_AARCH64 => "ARM AARCH64",
            EM_TILEPRO => "Tilera TILEPro",
            EM_MICROBLAZE => "Xilinx MicroBlaze",
            EM_TILEGX => "Tilera TILE-Gx",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

///
/// ELF File Header
///
#[derive(Copy, Debug)]
pub struct FileHeader {
    pub class:      Class,
    pub data:       Data,
    pub version:    Version,
    pub osabi:      OSABI,
    pub abiversion: u8,
    pub elftype:    Type,
    pub machine:    Machine,
    pub entry:      u64,
}

impl default::Default for FileHeader {
    fn default() -> FileHeader {
        FileHeader { class : ELFCLASSNONE, data : ELFDATANONE, version : EV_NONE,
            elftype : ET_NONE, machine : EM_NONE, osabi : ELFOSABI_NONE,
            abiversion : 0, entry : 0 }
    }
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File Header for {} {} Elf {} for {} {}\n", self.class, self.data,
            self.elftype, self.osabi, self.machine)
    }
}

