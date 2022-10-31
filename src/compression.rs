use crate::parse::{parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionHeader {
    pub ch_type: u32,
    pub ch_size: u64,
    pub ch_addralign: u64,
}

impl ParseAt for CompressionHeader {
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(CompressionHeader {
                ch_type: parse_u32_at(endian, offset, data)?,
                ch_size: parse_u32_at(endian, offset, data)? as u64,
                ch_addralign: parse_u32_at(endian, offset, data)? as u64,
            }),
            Class::ELF64 => {
                let ch_type = parse_u32_at(endian, offset, data)?;
                let _ch_reserved = parse_u32_at(endian, offset, data)?;
                Ok(CompressionHeader {
                    ch_type,
                    ch_size: parse_u64_at(endian, offset, data)?,
                    ch_addralign: parse_u64_at(endian, offset, data)?,
                })
            }
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => ELF32CHDRSIZE,
            Class::ELF64 => ELF64CHDRSIZE,
        }
    }
}

const ELF32CHDRSIZE: usize = 12;
const ELF64CHDRSIZE: usize = 24;

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_chdr32_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF32,
            CompressionHeader {
                ch_type: 0x03020100,
                ch_size: 0x07060504,
                ch_addralign: 0x0B0A0908,
            },
        );
    }

    #[test]
    fn parse_chdr32_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF32,
            CompressionHeader {
                ch_type: 0x00010203,
                ch_size: 0x04050607,
                ch_addralign: 0x08090A0B,
            },
        );
    }

    #[test]
    fn parse_chdr64_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF64,
            CompressionHeader {
                ch_type: 0x03020100,
                ch_size: 0x0F0E0D0C0B0A0908,
                ch_addralign: 0x1716151413121110,
            },
        );
    }

    #[test]
    fn parse_chdr64_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF64,
            CompressionHeader {
                ch_type: 0x00010203,
                ch_size: 0x08090A0B0C0D0E0F,
                ch_addralign: 0x1011121314151617,
            },
        );
    }

    #[test]
    fn parse_chdr32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<CompressionHeader>(Endian::Little, Class::ELF32);
    }

    #[test]
    fn parse_chdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<CompressionHeader>(Endian::Big, Class::ELF32);
    }

    #[test]
    fn parse_chdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<CompressionHeader>(Endian::Little, Class::ELF64);
    }

    #[test]
    fn parse_chdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<CompressionHeader>(Endian::Big, Class::ELF64);
    }
}
