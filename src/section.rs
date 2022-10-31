use crate::parse::{parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError, ParsingTable};

pub type SectionHeaderTable<'data> = ParsingTable<'data, SectionHeader>;

/// Encapsulates the contents of an ELF Section Header
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section Name
    pub sh_name: u32,
    /// Section Type
    pub sh_type: SectionType,
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
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(SectionHeader {
                sh_name: parse_u32_at(endian, offset, data)?,
                sh_type: SectionType(parse_u32_at(endian, offset, data)?),
                sh_flags: parse_u32_at(endian, offset, data)? as u64,
                sh_addr: parse_u32_at(endian, offset, data)? as u64,
                sh_offset: parse_u32_at(endian, offset, data)? as u64,
                sh_size: parse_u32_at(endian, offset, data)? as u64,
                sh_link: parse_u32_at(endian, offset, data)?,
                sh_info: parse_u32_at(endian, offset, data)?,
                sh_addralign: parse_u32_at(endian, offset, data)? as u64,
                sh_entsize: parse_u32_at(endian, offset, data)? as u64,
            }),
            Class::ELF64 => Ok(SectionHeader {
                sh_name: parse_u32_at(endian, offset, data)?,
                sh_type: SectionType(parse_u32_at(endian, offset, data)?),
                sh_flags: parse_u64_at(endian, offset, data)?,
                sh_addr: parse_u64_at(endian, offset, data)?,
                sh_offset: parse_u64_at(endian, offset, data)?,
                sh_size: parse_u64_at(endian, offset, data)?,
                sh_link: parse_u32_at(endian, offset, data)?,
                sh_info: parse_u32_at(endian, offset, data)?,
                sh_addralign: parse_u64_at(endian, offset, data)?,
                sh_entsize: parse_u64_at(endian, offset, data)?,
            }),
        }
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

#[cfg(test)]
mod shdr_tests {
    use super::*;

    const ELF32SHDRSIZE: u16 = 40;
    const ELF64SHDRSIZE: u16 = 64;

    #[test]
    fn parse_shdr32_fuzz_too_short() {
        let data = [0u8; ELF32SHDRSIZE as usize];
        for n in 0..ELF32SHDRSIZE as usize {
            let buf = data.split_at(n).0.as_ref();
            let mut offset = 0;
            let result = SectionHeader::parse_at(Endian::Little, Class::ELF32, &mut offset, buf);
            assert!(
                matches!(result, Err(ParseError::BadOffset(_))),
                "Unexpected Error type found: {result:?}"
            );
        }
    }

    #[test]
    fn parse_shdr32_works() {
        let mut data = [0u8; ELF32SHDRSIZE as usize];
        for n in 0..ELF32SHDRSIZE as u8 {
            data[n as usize] = n;
        }

        let mut offset = 0;
        assert_eq!(
            SectionHeader::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
                .unwrap(),
            SectionHeader {
                sh_name: 0x03020100,
                sh_type: SectionType(0x07060504),
                sh_flags: 0xB0A0908,
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
        let data = [0u8; ELF64SHDRSIZE as usize];
        for n in 0..ELF64SHDRSIZE as usize {
            let buf = data.split_at(n).0.as_ref();
            let mut offset = 0;
            let result = SectionHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, buf);
            assert!(
                matches!(result, Err(ParseError::BadOffset(_))),
                "Unexpected Error type found: {result:?}"
            );
        }
    }

    #[test]
    fn parse_shdr64_works() {
        let mut data = [0u8; ELF64SHDRSIZE as usize];
        for n in 0..ELF64SHDRSIZE as u8 {
            data[n as usize] = n;
        }

        let mut offset = 0;
        assert_eq!(
            SectionHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref()).unwrap(),
            SectionHeader {
                sh_name: 0x00010203,
                sh_type: SectionType(0x04050607),
                sh_flags: 0x08090A0B0C0D0E0F,
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
