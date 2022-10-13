use crate::file::Class;
use crate::gabi;
use crate::parse::{Endian, Parse, ParseError, ReadExt, Reader};

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
            Class(gabi::ELFCLASS32) => {
                if entsize != ELF32SYMSIZE {
                    return Err(ParseError(format!(
                        "Invalid symbol entsize {entsize} for ELF32. Should be {ELF32SYMSIZE}."
                    )));
                }
            }
            Class(gabi::ELFCLASS64) => {
                if entsize != ELF64SYMSIZE {
                    return Err(ParseError(format!(
                        "Invalid symbol entsize {entsize} for ELF32. Should be {ELF32SYMSIZE}."
                    )));
                }
            }
            _ => {
                return Err(ParseError(format!(
                    "Cannot parse symbol for unknown ELF class {class}."
                )));
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
        let entsize = self.entsize;

        if self.class == gabi::ELFCLASS32 && self.entsize != ELF32SYMSIZE {
            return Err(ParseError(format!(
                "Invalid symbol entsize {entsize} for ELF32. Should be {ELF32SYMSIZE}."
            )));
        }

        let num_table_entries = self.data.len() as u64 / entsize;
        if index as u64 > num_table_entries {
            return Err(ParseError(format!(
                "Invalid symbol table index {index} for table size {num_table_entries}"
            )));
        }

        let start = entsize * index;
        let mut cur = std::io::Cursor::new(self.data);
        cur.set_position(start);
        let mut reader = Reader::new(&mut cur, self.endianness);

        let symbol = Symbol::parse(self.class, &mut reader)?;

        Ok(symbol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: u32,
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

impl<R> Parse<R> for Symbol
where
    R: ReadExt,
{
    fn parse(class: Class, reader: &mut R) -> Result<Self, ParseError> {
        let name: u32;
        let value: u64;
        let size: u64;
        let shndx: u16;
        let mut info: [u8; 1] = [0u8];
        let mut other: [u8; 1] = [0u8];

        if class == gabi::ELFCLASS32 {
            name = reader.read_u32()?;
            value = reader.read_u32()? as u64;
            size = reader.read_u32()? as u64;
            reader.read_exact(&mut info)?;
            reader.read_exact(&mut other)?;
            shndx = reader.read_u16()?;
        } else {
            name = reader.read_u32()?;
            reader.read_exact(&mut info)?;
            reader.read_exact(&mut other)?;
            shndx = reader.read_u16()?;
            value = reader.read_u64()?;
            size = reader.read_u64()?;
        }

        Ok(Symbol {
            name: name,
            value: value,
            size: size,
            shndx: shndx,
            symtype: SymbolType(info[0] & 0xf),
            bind: SymbolBind(info[0] >> 4),
            vis: SymbolVis(other[0] & 0x3),
        })
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Symbol: Value: {:#010x} Size: {:#06x} Type: {} Bind: {} Vis: {} Section: {} Name: {}",
            self.value, self.size, self.symtype, self.bind, self.vis, self.shndx, self.name
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolType(pub u8);

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STT_NOTYPE => "unspecified",
            gabi::STT_OBJECT => "data object",
            gabi::STT_FUNC => "code object",
            gabi::STT_SECTION => "section",
            gabi::STT_FILE => "file name",
            gabi::STT_COMMON => "common data object",
            gabi::STT_TLS => "thread-local data object",
            gabi::STT_GNU_IFUNC => "indirect code object",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolBind(pub u8);

impl std::fmt::Display for SymbolBind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STB_LOCAL => "local",
            gabi::STB_GLOBAL => "global",
            gabi::STB_WEAK => "weak",
            gabi::STB_GNU_UNIQUE => "unique",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymbolVis(pub u8);

impl std::fmt::Display for SymbolVis {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::STV_DEFAULT => "default",
            gabi::STV_INTERNAL => "internal",
            gabi::STV_HIDDEN => "hidden",
            gabi::STV_PROTECTED => "protected",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use crate::gabi;

    #[test]
    fn get_32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32SYMSIZE as usize];
        for n in 0..ELF32SYMSIZE {
            data[n as usize] = n as u8;
        }
        let table = SymbolTable::new(Endian::Little, Class(gabi::ELFCLASS32), ELF32SYMSIZE, &data)
            .expect("Failed to create SymbolTable");

        assert_eq!(
            table.get(0).unwrap(),
            Symbol {
                name: 0x03020100,
                value: 0x07060504,
                size: 0x0B0A0908,
                shndx: 0x0F0E,
                symtype: SymbolType(12),
                bind: SymbolBind(0),
                vis: SymbolVis(1)
            }
        );
        assert!(table.get(42).is_err());
    }

    #[test]
    fn get_64_msb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF64SYMSIZE as usize];
        for n in 0..ELF64SYMSIZE {
            data[n as usize] = n as u8;
        }

        let table = SymbolTable::new(Endian::Big, Class(gabi::ELFCLASS64), ELF64SYMSIZE, &data)
            .expect("Failed to create SymbolTable");

        assert_eq!(
            table.get(0).unwrap(),
            Symbol {
                name: 0x00010203,
                value: 0x08090A0B0C0D0E0F,
                size: 0x1011121314151617,
                shndx: 0x0607,
                symtype: SymbolType(4),
                bind: SymbolBind(0),
                vis: SymbolVis(1)
            }
        );
    }
}
