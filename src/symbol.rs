use crate::gabi;
use crate::parse::{
    parse_u16_at, parse_u32_at, parse_u64_at, parse_u8_at, Class, Endian, ParseAt, ParseError,
    ParsingTable,
};

pub type SymbolTable<'data> = ParsingTable<'data, Symbol>;

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
        self.st_shndx == gabi::SHN_UNDEF
    }

    pub fn st_symtype(&self) -> SymbolType {
        SymbolType(self.st_info & 0xf)
    }

    pub fn st_bind(&self) -> SymbolBind {
        SymbolBind(self.st_info >> 4)
    }

    pub fn st_vis(&self) -> SymbolVis {
        SymbolVis(self.st_other & 0x3)
    }
}

impl ParseAt for Symbol {
    fn parse_at(
        endian: Endian,
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
            st_name = parse_u32_at(endian, offset, data)?;
            st_value = parse_u32_at(endian, offset, data)? as u64;
            st_size = parse_u32_at(endian, offset, data)? as u64;
            st_info = parse_u8_at(offset, data)?;
            st_other = parse_u8_at(offset, data)?;
            st_shndx = parse_u16_at(endian, offset, data)?;
        } else {
            st_name = parse_u32_at(endian, offset, data)?;
            st_info = parse_u8_at(offset, data)?;
            st_other = parse_u8_at(offset, data)?;
            st_shndx = parse_u16_at(endian, offset, data)?;
            st_value = parse_u64_at(endian, offset, data)?;
            st_size = parse_u64_at(endian, offset, data)?;
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
            Class::ELF32 => ELF32SYMSIZE,
            Class::ELF64 => ELF64SYMSIZE,
        }
    }
}

const ELF32SYMSIZE: usize = 16;
const ELF64SYMSIZE: usize = 24;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);

#[cfg(test)]
mod table_tests {
    use super::*;

    const ELF32SYMSIZE: usize = 16;
    const ELF64SYMSIZE: usize = 24;

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

    #[test]
    fn get_32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32SYMSIZE];
        for n in 0..ELF32SYMSIZE {
            data[n] = n as u8;
        }
        let table = SymbolTable::new(Endian::Little, Class::ELF32, ELF32SYMSIZE, &data).unwrap();

        assert_eq!(
            table.get(0).unwrap(),
            Symbol {
                st_name: 0x03020100,
                st_value: 0x07060504,
                st_size: 0x0B0A0908,
                st_shndx: 0x0F0E,
                st_info: 0x0C,
                st_other: 0x0D,
            }
        );
        let result = table.get(42);
        assert!(
            matches!(result, Err(ParseError::BadOffset(42))),
            "Unexpected Error type found: {result:?}"
        );
    }

    #[test]
    fn get_64_msb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF64SYMSIZE];
        for n in 0..ELF64SYMSIZE {
            data[n] = n as u8;
        }

        let table = SymbolTable::new(Endian::Big, Class::ELF64, ELF64SYMSIZE, &data).unwrap();

        assert_eq!(
            table.get(0).unwrap(),
            Symbol {
                st_name: 0x00010203,
                st_value: 0x08090A0B0C0D0E0F,
                st_size: 0x1011121314151617,
                st_shndx: 0x0607,
                st_info: 0x04,
                st_other: 0x05,
            }
        );
    }
}
