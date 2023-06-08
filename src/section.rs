//! Parsing the Section Header table
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable};

pub type SectionHeaderTable<'data, E> = ParsingTable<'data, E, SectionHeader>;

/// C-style 32-bit ELF Section Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

/// C-style 64-bit ELF Section Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Encapsulates the contents of an ELF Section Header
///
/// This is a Rust-native type that represents a Section Header that is bit-width-agnostic.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section Name
    pub sh_name: u32,
    /// Section Type
    pub sh_type: u32,
    /// Section Flags
    pub sh_flags: u64,
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

impl ParseAt for SectionHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(SectionHeader {
                sh_name: endian.parse_u32_at(offset, data)?,
                sh_type: endian.parse_u32_at(offset, data)?,
                sh_flags: endian.parse_u32_at(offset, data)? as u64,
                sh_addr: endian.parse_u32_at(offset, data)? as u64,
                sh_offset: endian.parse_u32_at(offset, data)? as u64,
                sh_size: endian.parse_u32_at(offset, data)? as u64,
                sh_link: endian.parse_u32_at(offset, data)?,
                sh_info: endian.parse_u32_at(offset, data)?,
                sh_addralign: endian.parse_u32_at(offset, data)? as u64,
                sh_entsize: endian.parse_u32_at(offset, data)? as u64,
            }),
            Class::ELF64 => Ok(SectionHeader {
                sh_name: endian.parse_u32_at(offset, data)?,
                sh_type: endian.parse_u32_at(offset, data)?,
                sh_flags: endian.parse_u64_at(offset, data)?,
                sh_addr: endian.parse_u64_at(offset, data)?,
                sh_offset: endian.parse_u64_at(offset, data)?,
                sh_size: endian.parse_u64_at(offset, data)?,
                sh_link: endian.parse_u32_at(offset, data)?,
                sh_info: endian.parse_u32_at(offset, data)?,
                sh_addralign: endian.parse_u64_at(offset, data)?,
                sh_entsize: endian.parse_u64_at(offset, data)?,
            }),
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 40,
            Class::ELF64 => 64,
        }
    }
}

impl SectionHeader {
    /// Helper method which uses checked integer math to get a tuple of (start,end) for
    /// this SectionHeader's (sh_offset, sh_offset + sh_size)
    pub(crate) fn get_data_range(&self) -> Result<(usize, usize), ParseError> {
        let start: usize = self.sh_offset.try_into()?;
        let size: usize = self.sh_size.try_into()?;
        let end = start.checked_add(size).ok_or(ParseError::IntegerOverflow)?;
        Ok((start, end))
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_shdr32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            SectionHeader {
                sh_name: 0x03020100,
                sh_type: 0x07060504,
                sh_flags: 0xB0A0908,
                sh_addr: 0x0F0E0D0C,
                sh_offset: 0x13121110,
                sh_size: 0x17161514,
                sh_link: 0x1B1A1918,
                sh_info: 0x1F1E1D1C,
                sh_addralign: 0x23222120,
                sh_entsize: 0x27262524,
            },
        );
    }

    #[test]
    fn parse_shdr32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            SectionHeader {
                sh_name: 0x00010203,
                sh_type: 0x04050607,
                sh_flags: 0x08090A0B,
                sh_addr: 0x0C0D0E0F,
                sh_offset: 0x10111213,
                sh_size: 0x14151617,
                sh_link: 0x18191A1B,
                sh_info: 0x1C1D1E1F,
                sh_addralign: 0x20212223,
                sh_entsize: 0x24252627,
            },
        );
    }

    #[test]
    fn parse_shdr64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            SectionHeader {
                sh_name: 0x03020100,
                sh_type: 0x07060504,
                sh_flags: 0x0F0E0D0C0B0A0908,
                sh_addr: 0x1716151413121110,
                sh_offset: 0x1F1E1D1C1B1A1918,
                sh_size: 0x2726252423222120,
                sh_link: 0x2B2A2928,
                sh_info: 0x2F2E2D2C,
                sh_addralign: 0x3736353433323130,
                sh_entsize: 0x3F3E3D3C3B3A3938,
            },
        );
    }

    #[test]
    fn parse_shdr64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            SectionHeader {
                sh_name: 0x00010203,
                sh_type: 0x04050607,
                sh_flags: 0x08090A0B0C0D0E0F,
                sh_addr: 0x1011121314151617,
                sh_offset: 0x18191A1B1C1D1E1F,
                sh_size: 0x2021222324252627,
                sh_link: 0x28292A2B,
                sh_info: 0x2C2D2E2F,
                sh_addralign: 0x3031323334353637,
                sh_entsize: 0x38393A3B3C3D3E3F,
            },
        );
    }

    #[test]
    fn parse_shdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SectionHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_shdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SectionHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_shdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SectionHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_shdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, SectionHeader>(BigEndian, Class::ELF64);
    }
}
