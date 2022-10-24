use crate::parse::{Class, Endian, EndianParseExt, ParseAt, ParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoteHeader {
    pub n_namesz: u64,
    pub n_descsz: u64,
    pub n_type: u64,
}

impl ParseAt for NoteHeader {
    fn parse_at<P: EndianParseExt>(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(NoteHeader {
                n_namesz: parser.parse_u32_at(endian, offset)? as u64,
                n_descsz: parser.parse_u32_at(endian, offset)? as u64,
                n_type: parser.parse_u32_at(endian, offset)? as u64,
            }),
            Class::ELF64 => Ok(NoteHeader {
                n_namesz: parser.parse_u64_at(endian, offset)?,
                n_descsz: parser.parse_u64_at(endian, offset)?,
                n_type: parser.parse_u64_at(endian, offset)?,
            }),
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    const ELF32NOTESIZE: usize = 12;
    const ELF64NOTESIZE: usize = 24;

    #[test]
    fn parse_nhdr32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32NOTESIZE as usize];
        for n in 0..ELF32NOTESIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = NoteHeader::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
            .expect("Failed to parse NoteHeader");

        assert_eq!(
            entry,
            NoteHeader {
                n_namesz: 0x03020100,
                n_descsz: 0x07060504,
                n_type: 0x0B0A0908,
            }
        );
        assert_eq!(offset, ELF32NOTESIZE);
    }

    #[test]
    fn parse_nhdr32_fuzz_too_short() {
        let data = [0u8; ELF32NOTESIZE];
        for n in 0..ELF32NOTESIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = NoteHeader::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_nhdr64_msb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF64NOTESIZE as usize];
        for n in 0..ELF64NOTESIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = NoteHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
            .expect("Failed to parse NoteHeader");

        assert_eq!(
            entry,
            NoteHeader {
                n_namesz: 0x0001020304050607,
                n_descsz: 0x08090A0B0C0D0E0F,
                n_type: 0x1011121314151617,
            }
        );
        assert_eq!(offset, ELF64NOTESIZE);
    }

    #[test]
    fn parse_nhdr64_fuzz_too_short() {
        let data = [0u8; ELF64NOTESIZE];
        for n in 0..ELF64NOTESIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = NoteHeader::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
