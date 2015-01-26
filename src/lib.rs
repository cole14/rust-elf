#![allow(unstable)]

use std::fmt;
use std::default;

pub type Elf32Addr = u32;
pub type Elf32Off = u32;

pub const EINIDENT: usize = 16;

#[derive(Copy, Show)]
pub enum Class {
    ELFCLASSNONE = 0,
    ELFCLASS32 = 1,
    ELFCLASS64 = 2,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            Class::ELFCLASSNONE => "Invalid",
            Class::ELFCLASS32 => "32-bit",
            Class::ELFCLASS64 => "64-bit",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy, Show)]
pub enum Data {
    ELFDATANONE = 0,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            Data::ELFDATANONE => "Invalid",
            Data::ELFDATA2LSB => "2's complement, little endian",
            Data::ELFDATA2MSB => "2's complement, big endian",
        };
        write!(f, "{}", str)
    }
}

#[derive(Copy)]
pub struct Version(pub u8);
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

#[derive(Copy, Show)]
pub struct Elf32Ehdr {
    pub e_class:     Class,
    pub e_data:      Data,
    pub e_version:   Version,
    pub e_type:      u16,
    pub e_machine:   u16,
    pub e_entry:     Elf32Addr,
    pub e_phoff:     Elf32Off,
    pub e_shoff:     Elf32Off,
    pub e_flags:     u32,
    pub e_ehsize:    u16,
    pub e_phentsize: u16,
    pub e_phnum:     u16,
    pub e_shentsize: u16,
    pub e_shnum:     u16,
    pub e_shstrndx:  u16,
}

impl default::Default for Elf32Ehdr {
    fn default() -> Elf32Ehdr {
        Elf32Ehdr { e_class : Class::ELFCLASSNONE, e_data : Data::ELFDATANONE, e_type : 0, e_machine : 0,
        e_version : EV_NONE, e_entry : 0, e_phoff : 0, e_shoff : 0, e_flags : 0, e_ehsize : 0, e_phentsize : 0,
        e_phnum : 0, e_shentsize : 0, e_shnum : 0, e_shstrndx : 0 }
    }
}

#[allow(unused_must_use)]
impl fmt::Display for Elf32Ehdr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Elf Header:\n");
        write!(f, "  Class: {}\n", self.e_class);
        write!(f, "  Data: {}\n", self.e_data);
        //write!(f, "  OS/ABI: {}\n", self.e_ident[7]);
        write!(f, "  Type: {}\n", self.e_type);
        write!(f, "  Machine: {}\n", self.e_machine);
        write!(f, "  Version: {}\n", self.e_version);
        write!(f, "  Entry point address: {}\n", self.e_entry);
        write!(f, "  Start of program headers: {}\n", self.e_phoff);
        write!(f, "  Start of section headers: {}\n", self.e_shoff);
        write!(f, "  Flags: {}\n", self.e_flags);
        write!(f, "  Size of this header: {}\n", self.e_ehsize);
        write!(f, "  Size of program headers: {}\n", self.e_phentsize);
        write!(f, "  Number of program headers: {}\n", self.e_phnum);
        write!(f, "  Size of section headers: {}\n", self.e_shentsize);
        write!(f, "  Number of section headers: {}\n", self.e_shnum);
        write!(f, "  Section header string table index: {}", self.e_shstrndx)
    }
}

