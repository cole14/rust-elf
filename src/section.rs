use std::io::SeekFrom;

use crate::file::{Class, FileHeader};
use crate::gabi;
use crate::parse::{Parse, ParseError, ReadExt};
use crate::string_table::StringTable;

#[derive(Debug)]
pub struct SectionTable {
    headers: Vec<SectionHeader>,
    section_data: Vec<Vec<u8>>,
    sh_strndx: usize,
}

impl SectionTable {
    pub fn new(headers: Vec<SectionHeader>, section_data: Vec<Vec<u8>>, sh_strndx: usize) -> Self {
        SectionTable {
            headers,
            section_data,
            sh_strndx,
        }
    }

    pub fn parse<R: ReadExt>(ehdr: &FileHeader, reader: &mut R) -> Result<Self, ParseError> {
        let mut headers = Vec::<SectionHeader>::with_capacity(ehdr.e_shnum as usize);
        let mut section_data = Vec::<Vec<u8>>::with_capacity(ehdr.e_shnum as usize);

        // Parse the section headers
        reader.seek(SeekFrom::Start(ehdr.e_shoff))?;
        for _ in 0..ehdr.e_shnum {
            let shdr = SectionHeader::parse(ehdr.class, reader)?;
            headers.push(shdr);
        }

        // Read the section data
        for i in 0..ehdr.e_shnum as usize {
            let shdr = headers[i];
            let mut data = Vec::<u8>::with_capacity(shdr.sh_size as usize);

            if shdr.sh_type != SectionType(gabi::SHT_NOBITS) {
                reader.seek(SeekFrom::Start(shdr.sh_offset))?;

                data.resize(shdr.sh_size as usize, 0u8);
                reader.read_exact(&mut data)?;
            }

            section_data.push(data);
        }

        Ok(SectionTable::new(
            headers,
            section_data,
            ehdr.e_shstrndx as usize,
        ))
    }

    pub fn get(&self, index: usize) -> Result<Section, ParseError> {
        let table_size = self.headers.len();
        let shdr = self.headers.get(index).ok_or(ParseError(format!(
            "Invalid section table index: {index} table_size: {table_size}"
        )))?;
        let data = self.section_data.get(index).ok_or(ParseError(format!(
            "Invalid section table index: {index} table_size: {table_size}"
        )))?;

        Ok(Section { shdr, data })
    }

    pub fn get_by_name(&self, name: &str) -> Option<Section> {
        let strings_scn = self.get(self.sh_strndx);
        if strings_scn.is_err() {
            return None;
        }

        let strings = StringTable::new(strings_scn.unwrap().data);

        match core::iter::zip(&self.headers, &self.section_data)
            .find(|(shdr, _)| strings.get(shdr.sh_name as usize) == Ok(name))
        {
            Some((shdr, data)) => Some(Section { shdr, data }),
            None => None,
        }
    }

    pub fn iter(&self) -> SectionTableIterator {
        SectionTableIterator::new(self)
    }
}

impl Default for SectionTable {
    fn default() -> Self {
        SectionTable {
            headers: Vec::<SectionHeader>::default(),
            section_data: Vec::<Vec<u8>>::default(),
            sh_strndx: 0,
        }
    }
}

pub struct SectionTableIterator<'data> {
    table: &'data SectionTable,
    idx: usize,
}

impl<'data> SectionTableIterator<'data> {
    pub fn new(table: &'data SectionTable) -> Self {
        SectionTableIterator {
            table: table,
            idx: 0,
        }
    }
}

impl<'data> Iterator for SectionTableIterator<'data> {
    type Item = Section<'data>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.table.headers.len() {
            return None;
        }
        let idx = self.idx;
        self.idx += 1;
        Some(Section {
            shdr: &self.table.headers[idx],
            data: &self.table.section_data[idx],
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Section<'data> {
    pub shdr: &'data SectionHeader,
    pub data: &'data [u8],
}

impl<'data> core::fmt::Display for Section<'data> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.shdr)
    }
}

/// Encapsulates the contents of an ELF Section Header
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section Name
    pub sh_name: u32,
    /// Section Type
    pub sh_type: SectionType,
    /// Section Flags
    pub sh_flags: SectionFlag,
    /// in-memory address where this section is loaded
    pub sh_addr: u64,
    /// Byte-offset into the file where this section starts
    pub sh_offset: u64,
    /// Section size in bytes
    pub sh_size: u64,
    /// Defined by section type
    pub sh_link: u32,
    /// Defined by section type
    pub sh_info: u32,
    /// address alignment
    pub sh_addralign: u64,
    /// size of an entry if section data is an array of entries
    pub sh_entsize: u64,
}

impl<R> Parse<R> for SectionHeader
where
    R: ReadExt,
{
    fn parse(class: Class, reader: &mut R) -> Result<Self, ParseError> {
        if class == gabi::ELFCLASS32 {
            return Ok(SectionHeader {
                sh_name: reader.read_u32()?,
                sh_type: SectionType(reader.read_u32()?),
                sh_flags: SectionFlag(reader.read_u32()? as u64),
                sh_addr: reader.read_u32()? as u64,
                sh_offset: reader.read_u32()? as u64,
                sh_size: reader.read_u32()? as u64,
                sh_link: reader.read_u32()?,
                sh_info: reader.read_u32()?,
                sh_addralign: reader.read_u32()? as u64,
                sh_entsize: reader.read_u32()? as u64,
            });
        }

        Ok(SectionHeader {
            sh_name: reader.read_u32()?,
            sh_type: SectionType(reader.read_u32()?),
            sh_flags: SectionFlag(reader.read_u64()?),
            sh_addr: reader.read_u64()?,
            sh_offset: reader.read_u64()?,
            sh_size: reader.read_u64()?,
            sh_link: reader.read_u32()?,
            sh_info: reader.read_u32()?,
            sh_addralign: reader.read_u64()?,
            sh_entsize: reader.read_u64()?,
        })
    }
}

impl core::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Section Header: Name: {} Type: {} Flags: {} Addr: {:#010x} Offset: {:#06x} Size: {:#06x} Link: {} Info: {:#x} AddrAlign: {} EntSize: {}",
            self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset,
            self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize)
    }
}

/// Represens ELF Section type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SectionType(pub u32);

impl PartialEq<u32> for SectionType {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl core::fmt::Debug for SectionType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for SectionType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self.0 {
            gabi::SHT_NULL => "SHT_NULL",
            gabi::SHT_PROGBITS => "SHT_PROGBITS",
            gabi::SHT_SYMTAB => "SHT_SYMTAB",
            gabi::SHT_STRTAB => "SHT_STRTAB",
            gabi::SHT_RELA => "SHT_RELA",
            gabi::SHT_HASH => "SHT_HASH",
            gabi::SHT_DYNAMIC => "SHT_DYNAMIC",
            gabi::SHT_NOTE => "SHT_NOTE",
            gabi::SHT_NOBITS => "SHT_NOBITS",
            gabi::SHT_REL => "SHT_REL",
            gabi::SHT_SHLIB => "SHT_SHLIB",
            gabi::SHT_DYNSYM => "SHT_DYNSYM",
            gabi::SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            gabi::SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            gabi::SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
            gabi::SHT_GROUP => "SHT_GROUP",
            gabi::SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
            gabi::SHT_NUM => "SHT_NUM",
            gabi::SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
            gabi::SHT_GNU_HASH => "SHT_GNU_HASH",
            gabi::SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
            gabi::SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            gabi::SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            gabi::SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
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

impl core::fmt::Debug for SectionFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use crate::gabi;

    #[test]
    fn get_on_empty_table() {
        let table = SectionTable::default();
        assert!(table.get(0).is_err());
        assert!(table.get(42).is_err());
    }

    #[test]
    fn get_by_name_does_not_exist() {
        let table = SectionTable::default();
        assert!(table.get_by_name(".footab").is_none());
    }

    #[test]
    fn get_variants_work() {
        // Set up 1 .bss section, 1 .strtab section
        let mut headers = Vec::<SectionHeader>::with_capacity(2);
        headers.push(SectionHeader {
            sh_name: 1,
            sh_type: SectionType(gabi::SHT_NOBITS),
            sh_flags: SectionFlag(0),
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
        headers.push(SectionHeader {
            sh_name: 6,
            sh_type: SectionType(gabi::SHT_STRTAB),
            sh_flags: SectionFlag(0),
            sh_addr: 0,
            sh_offset: 0,
            sh_size: 0,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });

        let mut section_data = Vec::<Vec<u8>>::with_capacity(2);
        // .bss section has no data
        section_data.push(Vec::<u8>::default());
        // .strtab is the string table
        section_data.push(vec![
            0u8, 0x2E, 0x62, 0x73, 0x73, 0u8, 0x2E, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0u8,
        ]);

        // SUT
        let table = SectionTable::new(headers, section_data, 1);

        let bss_by_name = table.get_by_name(".bss").expect("Couldn't find .bss");
        assert_eq!(bss_by_name.shdr.sh_type, SectionType(gabi::SHT_NOBITS));
        assert_eq!(bss_by_name.data.len(), 0);

        let strtab_by_name = table.get_by_name(".strtab").expect("Couldn't find .strtab");
        assert_eq!(strtab_by_name.shdr.sh_type, SectionType(gabi::SHT_STRTAB));
        assert_eq!(strtab_by_name.data.len(), 14);

        let bss_by_index = table.get(0).expect("Couldn't find .bss");
        let strtab_by_index = table.get(1).expect("Couldn't find .strtab");
        assert_eq!(bss_by_index, bss_by_name);
        assert_eq!(strtab_by_index, strtab_by_name);
    }
}

#[cfg(test)]
mod shdr_tests {
    use crate::file::Class;
    use crate::gabi;
    use crate::parse::{Endian, Parse, Reader};
    use crate::section::{SectionFlag, SectionHeader, SectionType};
    use std::io::Cursor;

    #[test]
    fn parse_shdr32_fuzz_too_short() {
        let data = [0u8; 40];
        for n in 0..40 {
            let mut cur = Cursor::new(data.split_at(n).0.as_ref());
            let mut reader = Reader::new(&mut cur, Endian::Little);
            assert!(SectionHeader::parse(Class(gabi::ELFCLASS32), &mut reader).is_err());
        }
    }

    #[test]
    fn parse_shdr32_works() {
        let mut data = [0u8; 40];
        for n in 0u8..40 {
            data[n as usize] = n;
        }

        let mut cur = Cursor::new(data.as_ref());
        let mut reader = Reader::new(&mut cur, Endian::Little);
        assert_eq!(
            SectionHeader::parse(Class(gabi::ELFCLASS32), &mut reader).unwrap(),
            SectionHeader {
                sh_name: 0x03020100,
                sh_type: SectionType(0x07060504),
                sh_flags: SectionFlag(0xB0A0908),
                sh_addr: 0x0F0E0D0C,
                sh_offset: 0x13121110,
                sh_size: 0x17161514,
                sh_link: 0x1B1A1918,
                sh_info: 0x1F1E1D1C,
                sh_addralign: 0x23222120,
                sh_entsize: 0x27262524,
            }
        );
    }

    #[test]
    fn parse_shdr64_fuzz_too_short() {
        let data = [0u8; 64];
        for n in 0..64 {
            let mut cur = Cursor::new(data.split_at(n).0.as_ref());
            let mut reader = Reader::new(&mut cur, Endian::Big);
            assert!(SectionHeader::parse(Class(gabi::ELFCLASS64), &mut reader).is_err());
        }
    }

    #[test]
    fn parse_shdr64_works() {
        let mut data = [0u8; 64];
        for n in 0u8..64 {
            data[n as usize] = n;
        }

        let mut cur = Cursor::new(data.as_ref());
        let mut reader = Reader::new(&mut cur, Endian::Big);
        assert_eq!(
            SectionHeader::parse(Class(gabi::ELFCLASS64), &mut reader).unwrap(),
            SectionHeader {
                sh_name: 0x00010203,
                sh_type: SectionType(0x04050607),
                sh_flags: SectionFlag(0x08090A0B0C0D0E0F),
                sh_addr: 0x1011121314151617,
                sh_offset: 0x18191A1B1C1D1E1F,
                sh_size: 0x2021222324252627,
                sh_link: 0x28292A2B,
                sh_info: 0x2C2D2E2F,
                sh_addralign: 0x3031323334353637,
                sh_entsize: 0x38393A3B3C3D3E3F,
            }
        );
    }
}
