use crate::gabi;
use crate::symbol::{SymbolBind, SymbolType, SymbolVis};

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
                write!(f, "{}", format!("st_symtype({})", self.0))
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
                write!(f, "{}", format!("st_bind({})", self.0))
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
                write!(f, "{}", format!("st_vis({})", self.0))
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
