use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionHeader {
    pub ch_type: u32,
    pub ch_size: u64,
    pub ch_addralign: u64,
}

impl ParseAt for CompressionHeader {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(CompressionHeader {
                ch_type: parser.parse_u32_at(endian, offset)?,
                ch_size: parser.parse_u32_at(endian, offset)? as u64,
                ch_addralign: parser.parse_u32_at(endian, offset)? as u64,
            }),
            Class::ELF64 => {
                let ch_type = parser.parse_u32_at(endian, offset)?;
                let _ch_reserved = parser.parse_u32_at(endian, offset)?;
                Ok(CompressionHeader {
                    ch_type,
                    ch_size: parser.parse_u64_at(endian, offset)?,
                    ch_addralign: parser.parse_u64_at(endian, offset)?,
                })
            }
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    const ELF32CHDRSIZE: usize = 12;
    const ELF64CHDRSIZE: usize = 24;

    #[test]
    fn parse_dyn32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32CHDRSIZE as usize];
        for n in 0..ELF32CHDRSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry =
            CompressionHeader::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
                .expect("Failed to parse CompressionHeader");

        assert_eq!(
            entry,
            CompressionHeader {
                ch_type: 0x03020100,
                ch_size: 0x07060504,
                ch_addralign: 0x0B0A0908,
            }
        );
        assert_eq!(offset, ELF32CHDRSIZE);
    }

    #[test]
    fn parse_dyn32_fuzz_too_short() {
        let data = [0u8; ELF32CHDRSIZE];
        for n in 0..ELF32CHDRSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = CompressionHeader::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_dyn64_msb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF64CHDRSIZE as usize];
        for n in 0..ELF64CHDRSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry =
            CompressionHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
                .expect("Failed to parse Dyn");

        assert_eq!(
            entry,
            CompressionHeader {
                ch_type: 0x00010203,
                ch_size: 0x08090A0B0C0D0E0F,
                ch_addralign: 0x1011121314151617,
            }
        );
        assert_eq!(offset, ELF64CHDRSIZE);
    }

    #[test]
    fn parse_dyn64_fuzz_too_short() {
        let data = [0u8; ELF64CHDRSIZE];
        for n in 0..ELF64CHDRSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = CompressionHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
