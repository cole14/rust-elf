use crate::gabi;
use crate::parse::{Class, Endian, ParseAtExt, ParseError};

#[derive(Debug)]
pub struct SymbolTable<'data> {
    endianness: Endian,
    class: Class,
    entsize: u64,
    data: &'data [u8],
}

const ELF32SYMSIZE: u64 = 16;
const ELF64SYMSIZE: u64 = 24;

impl<'data> SymbolTable<'data> {
    pub fn new(
        endianness: Endian,
        class: Class,
        entsize: u64,
        data: &'data [u8],
    ) -> Result<Self, ParseError> {
        // Validate that the entsize matches with what we know how to parse
        match class {
            Class::ELF32 => {
                if entsize != ELF32SYMSIZE {
                    return Err(ParseError::BadEntsize((entsize, ELF32SYMSIZE)));
                }
            }
            Class::ELF64 => {
                if entsize != ELF64SYMSIZE {
                    return Err(ParseError::BadEntsize((entsize, ELF64SYMSIZE)));
                }
            }
        }

        Ok(SymbolTable {
            endianness,
            class,
            data,
            entsize,
        })
    }

    pub fn get(&self, index: u64) -> Result<Symbol, ParseError> {
        let num_table_entries = self.data.len() as u64 / self.entsize;
        if index as u64 > num_table_entries {
            return Err(ParseError::BadOffset(index));
        }

        let mut offset: usize = (self.entsize * index) as usize;
        Symbol::parse_at(self.endianness, self.class, &mut offset, &self.data)
    }

    pub fn iter(&self) -> SymbolTableIterator {
        SymbolTableIterator::new(self)
    }
}

pub struct SymbolTableIterator<'data> {
    table: &'data SymbolTable<'data>,
    idx: u64,
}

impl<'data> SymbolTableIterator<'data> {
    pub fn new(table: &'data SymbolTable) -> Self {
        SymbolTableIterator {
            table: table,
            // The GABI defines index 0 to always have a zero-ed out undefined
            // symbol that we don't want to expose via symbol iterators.
            idx: 1,
        }
    }
}

impl<'data> Iterator for SymbolTableIterator<'data> {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx * self.table.entsize >= self.table.data.len() as u64 {
            return None;
        }

        let idx = self.idx;
        self.idx += 1;
        self.table.get(idx).ok()
    }
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
    st_info: u8,

    /// This member currently specifies a symbol's visibility.
    st_other: u8,

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
    pub fn parse_at<P: ParseAtExt>(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        let st_name: u32;
        let st_value: u64;
        let st_size: u64;
        let st_shndx: u16;
        let st_info: u8;
        let st_other: u8;

        if class == Class::ELF32 {
            st_name = parser.parse_u32_at(endian, offset)?;
            st_value = parser.parse_u32_at(endian, offset)? as u64;
            st_size = parser.parse_u32_at(endian, offset)? as u64;
            st_info = parser.parse_u8_at(offset)?;
            st_other = parser.parse_u8_at(offset)?;
            st_shndx = parser.parse_u16_at(endian, offset)?;
        } else {
            st_name = parser.parse_u32_at(endian, offset)?;
            st_info = parser.parse_u8_at(offset)?;
            st_other = parser.parse_u8_at(offset)?;
            st_shndx = parser.parse_u16_at(endian, offset)?;
            st_value = parser.parse_u64_at(endian, offset)?;
            st_size = parser.parse_u64_at(endian, offset)?;
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

impl core::fmt::Display for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.st_value,
            self.st_size,
            self.st_symtype(),
            self.st_bind(),
            self.st_vis(),
            self.st_shndx,
            self.st_name
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);

impl core::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::STT_NOTYPE => "STT_NOTYPE",
            gabi::STT_OBJECT => "STT_OBJECT",
            gabi::STT_FUNC => "STT_FUNC",
            gabi::STT_SECTION => "STT_SECTION",
            gabi::STT_FILE => "STT_FILE",
            gabi::STT_COMMON => "STT_COMMON",
            gabi::STT_TLS => "STT_TLS",
            gabi::STT_GNU_IFUNC => "STT_GNU_IFUNC",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);

impl core::fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::STB_LOCAL => "STB_LOCAL",
            gabi::STB_GLOBAL => "STB_GLOBAL",
            gabi::STB_WEAK => "STB_WEAK",
            gabi::STB_GNU_UNIQUE => "STB_GNU_UNIQUE",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);

impl core::fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::STV_DEFAULT => "STV_DEFAULT",
            gabi::STV_INTERNAL => "STV_INTERNAL",
            gabi::STV_HIDDEN => "STV_HIDDEN",
            gabi::STV_PROTECTED => "STV_PROTECTED",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    #[test]
    fn get_32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32SYMSIZE as usize];
        for n in 0..ELF32SYMSIZE {
            data[n as usize] = n as u8;
        }
        let table = SymbolTable::new(Endian::Little, Class::ELF32, ELF32SYMSIZE, &data)
            .expect("Failed to create SymbolTable");

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
        let mut data = [0u8; ELF64SYMSIZE as usize];
        for n in 0..ELF64SYMSIZE {
            data[n as usize] = n as u8;
        }

        let table = SymbolTable::new(Endian::Big, Class::ELF64, ELF64SYMSIZE, &data)
            .expect("Failed to create SymbolTable");

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
