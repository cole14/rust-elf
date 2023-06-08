//! Parsing the Program Header table aka Segment table aka `Elf_Phdr`
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable};

pub type SegmentTable<'data, E> = ParsingTable<'data, E, ProgramHeader>;

/// C-style 32-bit ELF Program Segment Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

/// C-style 64-bit ELF Program Segment Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Encapsulates the contents of an ELF Program Header
///
/// The program header table is an array of program header structures describing
/// the various segments for program execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Program segment type
    pub p_type: u32,
    /// Offset into the ELF file where this segment begins
    pub p_offset: u64,
    /// Virtual adress where this segment should be loaded
    pub p_vaddr: u64,
    /// Physical address where this segment should be loaded
    pub p_paddr: u64,
    /// Size of this segment in the file
    pub p_filesz: u64,
    /// Size of this segment in memory
    pub p_memsz: u64,
    /// Flags for this segment
    pub p_flags: u32,
    /// file and memory alignment
    pub p_align: u64,
}

impl ParseAt for ProgramHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        if class == Class::ELF32 {
            return Ok(ProgramHeader {
                p_type: endian.parse_u32_at(offset, data)?,
                p_offset: endian.parse_u32_at(offset, data)? as u64,
                p_vaddr: endian.parse_u32_at(offset, data)? as u64,
                p_paddr: endian.parse_u32_at(offset, data)? as u64,
                p_filesz: endian.parse_u32_at(offset, data)? as u64,
                p_memsz: endian.parse_u32_at(offset, data)? as u64,
                p_flags: endian.parse_u32_at(offset, data)?,
                p_align: endian.parse_u32_at(offset, data)? as u64,
            });
        }

        // Note: 64-bit fields are in a different order
        let p_type = endian.parse_u32_at(offset, data)?;
        let p_flags = endian.parse_u32_at(offset, data)?;
        let p_offset = endian.parse_u64_at(offset, data)?;
        let p_vaddr = endian.parse_u64_at(offset, data)?;
        let p_paddr = endian.parse_u64_at(offset, data)?;
        let p_filesz = endian.parse_u64_at(offset, data)?;
        let p_memsz = endian.parse_u64_at(offset, data)?;
        let p_align = endian.parse_u64_at(offset, data)?;
        Ok(ProgramHeader {
            p_type,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_flags,
            p_align,
        })
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 32,
            Class::ELF64 => 56,
        }
    }
}

impl ProgramHeader {
    /// Helper method which uses checked integer math to get a tuple of (start, end) for
    /// the location in bytes for this ProgramHeader's data in the file.
    /// i.e. (p_offset, p_offset + p_filesz)
    pub(crate) fn get_file_data_range(&self) -> Result<(usize, usize), ParseError> {
        let start: usize = self.p_offset.try_into()?;
        let size: usize = self.p_filesz.try_into()?;
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
    fn parse_phdr32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            ProgramHeader {
                p_type: 0x03020100,
                p_offset: 0x07060504,
                p_vaddr: 0xB0A0908,
                p_paddr: 0x0F0E0D0C,
                p_filesz: 0x13121110,
                p_memsz: 0x17161514,
                p_flags: 0x1B1A1918,
                p_align: 0x1F1E1D1C,
            },
        );
    }

    #[test]
    fn parse_phdr32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            ProgramHeader {
                p_type: 0x00010203,
                p_offset: 0x04050607,
                p_vaddr: 0x08090A0B,
                p_paddr: 0x0C0D0E0F,
                p_filesz: 0x10111213,
                p_memsz: 0x14151617,
                p_flags: 0x18191A1B,
                p_align: 0x1C1D1E1F,
            },
        );
    }

    #[test]
    fn parse_phdr64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            ProgramHeader {
                p_type: 0x03020100,
                p_offset: 0x0F0E0D0C0B0A0908,
                p_vaddr: 0x1716151413121110,
                p_paddr: 0x1F1E1D1C1B1A1918,
                p_filesz: 0x2726252423222120,
                p_memsz: 0x2F2E2D2C2B2A2928,
                p_flags: 0x07060504,
                p_align: 0x3736353433323130,
            },
        );
    }

    #[test]
    fn parse_phdr64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            ProgramHeader {
                p_type: 0x00010203,
                p_offset: 0x08090A0B0C0D0E0F,
                p_vaddr: 0x1011121314151617,
                p_paddr: 0x18191A1B1C1D1E1F,
                p_filesz: 0x2021222324252627,
                p_memsz: 0x28292A2B2C2D2E2F,
                p_flags: 0x04050607,
                p_align: 0x3031323334353637,
            },
        );
    }

    #[test]
    fn parse_phdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, ProgramHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_phdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, ProgramHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_phdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, ProgramHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_phdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, ProgramHeader>(BigEndian, Class::ELF64);
    }
}
