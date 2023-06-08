//! Parsing symbol table sections: `.symtab`, `.dynsym`
use crate::abi;
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable};

pub type SymbolTable<'data, E> = ParsingTable<'data, E, Symbol>;

/// C-style 32-bit ELF Symbol definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Sym {
    pub st_name: u32,
    pub st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u32,
}

/// C-style 64-bit ELF Symbol definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// This member holds an index into the symbol table's string table,
    /// which holds the character representations of the symbol names. If the
    /// value is non-zero, it represents a string table index that gives the
    /// symbol name. Otherwise, the symbol table entry has no name.
    pub st_name: u32,

    /// Every symbol table entry is defined in relation to some section. This
    /// member holds the relevant section header table index. As the sh_link and
    /// sh_info interpretation table and the related text describe, some section
    /// indexes indicate special meanings.
    ///
    /// If this member contains SHN_XINDEX, then the actual section header index
    /// is too large to fit in this field. The actual value is contained in the
    /// associated section of type SHT_SYMTAB_SHNDX.
    pub st_shndx: u16,

    /// This member specifies the symbol's type and binding attributes.
    pub(super) st_info: u8,

    /// This member currently specifies a symbol's visibility.
    pub(super) st_other: u8,

    /// This member gives the value of the associated symbol. Depending on the
    /// context, this may be an absolute value, an address, and so on.
    ///
    /// * In relocatable files, st_value holds alignment constraints for a
    ///   symbol whose section index is SHN_COMMON.
    /// * In relocatable files, st_value holds a section offset for a defined
    ///   symbol. st_value is an offset from the beginning of the section that
    ///   st_shndx identifies.
    /// * In executable and shared object files, st_value holds a virtual
    ///   address. To make these files' symbols more useful for the dynamic
    ///   linker, the section offset (file interpretation) gives way to a
    ///   virtual address (memory interpretation) for which the section number
    ///   is irrelevant.
    pub st_value: u64,

    /// This member gives the symbol's size.
    /// For example, a data object's size is the number of bytes contained in
    /// the object. This member holds 0 if the symbol has no size or an unknown
    /// size.
    pub st_size: u64,
}

impl Symbol {
    /// Returns true if a symbol is undefined in this ELF object.
    ///
    /// When linking and loading, undefined symbols in this object get linked to
    /// a defined symbol in another object.
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == abi::SHN_UNDEF
    }

    pub fn st_symtype(&self) -> u8 {
        self.st_info & 0xf
    }

    pub fn st_bind(&self) -> u8 {
        self.st_info >> 4
    }

    pub fn st_vis(&self) -> u8 {
        self.st_other & 0x3
    }
}

impl ParseAt for Symbol {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        let st_name: u32;
        let st_value: u64;
        let st_size: u64;
        let st_shndx: u16;
        let st_info: u8;
        let st_other: u8;

        if class == Class::ELF32 {
            st_name = endian.parse_u32_at(offset, data)?;
            st_value = endian.parse_u32_at(offset, data)? as u64;
            st_size = endian.parse_u32_at(offset, data)? as u64;
            st_info = endian.parse_u8_at(offset, data)?;
            st_other = endian.parse_u8_at(offset, data)?;
            st_shndx = endian.parse_u16_at(offset, data)?;
        } else {
            st_name = endian.parse_u32_at(offset, data)?;
            st_info = endian.parse_u8_at(offset, data)?;
            st_other = endian.parse_u8_at(offset, data)?;
            st_shndx = endian.parse_u16_at(offset, data)?;
            st_value = endian.parse_u64_at(offset, data)?;
            st_size = endian.parse_u64_at(offset, data)?;
        }

        Ok(Symbol {
            st_name,
            st_value,
            st_size,
            st_shndx,
            st_info,
            st_other,
        })
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 16,
            Class::ELF64 => 24,
        }
    }
}

#[cfg(test)]
mod symbol_tests {
    use super::*;

    #[test]
    fn symbol_undefined() {
        let undef_sym = Symbol {
            st_name: 0,
            st_value: 0,
            st_size: 0,
            st_shndx: 0,
            st_info: 0,
            st_other: 0,
        };
        assert!(undef_sym.is_undefined());

        let def_sym = Symbol {
            st_name: 0,
            st_value: 0,
            st_size: 0,
            st_shndx: 42,
            st_info: 0,
            st_other: 0,
        };
        assert!(!def_sym.is_undefined());
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_sym32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            Symbol {
                st_name: 0x03020100,
                st_value: 0x07060504,
                st_size: 0x0B0A0908,
                st_shndx: 0x0F0E,
                st_info: 0x0C,
                st_other: 0x0D,
            },
        );
    }

    #[test]
    fn parse_sym32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            Symbol {
                st_name: 0x00010203,
                st_value: 0x04050607,
                st_size: 0x08090A0B,
                st_shndx: 0x0E0F,
                st_info: 0x0C,
                st_other: 0x0D,
            },
        );
    }

    #[test]
    fn parse_sym64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            Symbol {
                st_name: 0x03020100,
                st_value: 0x0F0E0D0C0B0A0908,
                st_size: 0x1716151413121110,
                st_shndx: 0x0706,
                st_info: 0x04,
                st_other: 0x05,
            },
        );
    }

    #[test]
    fn parse_sym64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            Symbol {
                st_name: 0x00010203,
                st_value: 0x08090A0B0C0D0E0F,
                st_size: 0x1011121314151617,
                st_shndx: 0x0607,
                st_info: 0x04,
                st_other: 0x05,
            },
        );
    }

    #[test]
    fn parse_sym32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Symbol>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_sym32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Symbol>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_sym64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Symbol>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_sym64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Symbol>(BigEndian, Class::ELF64);
    }
}
