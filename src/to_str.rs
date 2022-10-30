use crate::gabi;
use crate::section::SectionType;
use crate::segment::{ProgFlag, ProgType};
use crate::symbol::{SymbolBind, SymbolType, SymbolVis};

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

impl core::fmt::Display for SectionType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match sh_type_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "sh_type({})", self.0)
            }
        }
    }
}

impl core::fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if (self.0 & gabi::PF_R) != 0 {
            write!(f, "R")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & gabi::PF_W) != 0 {
            write!(f, "W")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & gabi::PF_X) != 0 {
            write!(f, "E")
        } else {
            write!(f, " ")
        }
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

impl core::fmt::Display for ProgType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match p_type_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "p_type({})", self.0)
            }
        }
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

impl core::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match st_symtype_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "st_symtype({})", self.0)
            }
        }
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

impl core::fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match st_bind_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "st_bind({})", self.0)
            }
        }
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

impl core::fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match st_vis_to_str(self.0) {
            Some(s) => {
                write!(f, "{s}")
            }
            None => {
                write!(f, "st_vis({})", self.0)
            }
        }
    }
}

pub fn ch_type_to_str(ch_type: u32) -> Option<&'static str> {
    match ch_type {
        gabi::ELFCOMPRESS_ZLIB => Some("ELFCOMPRESS_ZLIB"),
        gabi::ELFCOMPRESS_ZSTD => Some("ELFCOMPRESS_ZSTD "),
        _ => None,
    }
}
