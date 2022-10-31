use crate::parse::{parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError, ParsingTable};

pub type SegmentTable<'data> = ParsingTable<'data, ProgramHeader>;

/// Encapsulates the contents of an ELF Program Header
///
/// The program header table is an array of program header structures describing
/// the various segments for program execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Program segment type
    pub p_type: ProgType,
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
    pub p_flags: ProgFlag,
    /// file and memory alignment
    pub p_align: u64,
}

impl ParseAt for ProgramHeader {
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        if class == Class::ELF32 {
            return Ok(ProgramHeader {
                p_type: ProgType(parse_u32_at(endian, offset, data)?),
                p_offset: parse_u32_at(endian, offset, data)? as u64,
                p_vaddr: parse_u32_at(endian, offset, data)? as u64,
                p_paddr: parse_u32_at(endian, offset, data)? as u64,
                p_filesz: parse_u32_at(endian, offset, data)? as u64,
                p_memsz: parse_u32_at(endian, offset, data)? as u64,
                p_flags: ProgFlag(parse_u32_at(endian, offset, data)?),
                p_align: parse_u32_at(endian, offset, data)? as u64,
            });
        }

        // Note: 64-bit fields are in a different order
        let p_type = parse_u32_at(endian, offset, data)?;
        let p_flags = parse_u32_at(endian, offset, data)?;
        let p_offset = parse_u64_at(endian, offset, data)?;
        let p_vaddr = parse_u64_at(endian, offset, data)?;
        let p_paddr = parse_u64_at(endian, offset, data)?;
        let p_filesz = parse_u64_at(endian, offset, data)?;
        let p_memsz = parse_u64_at(endian, offset, data)?;
        let p_align = parse_u64_at(endian, offset, data)?;
        Ok(ProgramHeader {
            p_type: ProgType(p_type),
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_flags: ProgFlag(p_flags),
            p_align,
        })
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => ELF32PHDRSIZE,
            Class::ELF64 => ELF64PHDRSIZE,
        }
    }
}

const ELF32PHDRSIZE: usize = 32;
const ELF64PHDRSIZE: usize = 56;

/// Represents ELF Program Header flags
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgFlag(pub u32);

impl core::fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Represents ELF Program Header type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgType(pub u32);

impl PartialEq<u32> for ProgType {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl core::fmt::Debug for ProgType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_phdr32_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF32,
            ProgramHeader {
                p_type: ProgType(0x03020100),
                p_offset: 0x07060504,
                p_vaddr: 0xB0A0908,
                p_paddr: 0x0F0E0D0C,
                p_filesz: 0x13121110,
                p_memsz: 0x17161514,
                p_flags: ProgFlag(0x1B1A1918),
                p_align: 0x1F1E1D1C,
            },
        );
    }

    #[test]
    fn parse_phdr32_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF32,
            ProgramHeader {
                p_type: ProgType(0x00010203),
                p_offset: 0x04050607,
                p_vaddr: 0x08090A0B,
                p_paddr: 0x0C0D0E0F,
                p_filesz: 0x10111213,
                p_memsz: 0x14151617,
                p_flags: ProgFlag(0x18191A1B),
                p_align: 0x1C1D1E1F,
            },
        );
    }

    #[test]
    fn parse_phdr64_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF64,
            ProgramHeader {
                p_type: ProgType(0x03020100),
                p_offset: 0x0F0E0D0C0B0A0908,
                p_vaddr: 0x1716151413121110,
                p_paddr: 0x1F1E1D1C1B1A1918,
                p_filesz: 0x2726252423222120,
                p_memsz: 0x2F2E2D2C2B2A2928,
                p_flags: ProgFlag(0x07060504),
                p_align: 0x3736353433323130,
            },
        );
    }

    #[test]
    fn parse_phdr64_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF64,
            ProgramHeader {
                p_type: ProgType(0x00010203),
                p_offset: 0x08090A0B0C0D0E0F,
                p_vaddr: 0x1011121314151617,
                p_paddr: 0x18191A1B1C1D1E1F,
                p_filesz: 0x2021222324252627,
                p_memsz: 0x28292A2B2C2D2E2F,
                p_flags: ProgFlag(0x04050607),
                p_align: 0x3031323334353637,
            },
        );
    }

    #[test]
    fn parse_phdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<ProgramHeader>(Endian::Little, Class::ELF32);
    }

    #[test]
    fn parse_phdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<ProgramHeader>(Endian::Big, Class::ELF32);
    }

    #[test]
    fn parse_phdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<ProgramHeader>(Endian::Little, Class::ELF64);
    }

    #[test]
    fn parse_phdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<ProgramHeader>(Endian::Big, Class::ELF64);
    }
}
