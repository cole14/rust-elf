use crate::parse::{Class, Endian, ParseAtExt, ParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dyn {
    pub d_tag: i64,
    d_un: i64,
}

impl Dyn {
    pub fn parse_at<P: ParseAtExt>(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        parser: &P,
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(Dyn {
                d_tag: parser.parse_i32_at(endian, offset)? as i64,
                d_un: parser.parse_i32_at(endian, offset)? as i64,
            }),
            Class::ELF64 => Ok(Dyn {
                d_tag: parser.parse_i64_at(endian, offset)?,
                d_un: parser.parse_i64_at(endian, offset)?,
            }),
        }
    }

    pub fn d_val(self) -> i64 {
        self.d_un
    }

    pub fn d_ptr(self) -> i64 {
        self.d_un
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    const ELF32DYNSIZE: usize = 8;
    const ELF64DYNSIZE: usize = 16;

    #[test]
    fn parse_dyn32_lsb() {
        // All symbol tables are defined to have a zeroed out symbol at index 0.
        let mut data = [0u8; ELF32DYNSIZE as usize];
        for n in 0..ELF32DYNSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = Dyn::parse_at(Endian::Little, Class::ELF32, &mut offset, &data.as_ref())
            .expect("Failed to parse Dyn");

        assert_eq!(
            entry,
            Dyn {
                d_tag: 0x03020100,
                d_un: 0x07060504,
            }
        );
        assert_eq!(offset, ELF32DYNSIZE);
    }

    #[test]
    fn parse_dyn32_fuzz_too_short() {
        let data = [0u8; ELF32DYNSIZE];
        for n in 0..ELF32DYNSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Dyn::parse_at(Endian::Big, Class::ELF32, &mut offset, &buf)
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
        let mut data = [0u8; ELF64DYNSIZE as usize];
        for n in 0..ELF64DYNSIZE {
            data[n as usize] = n as u8;
        }

        let mut offset = 0;
        let entry = Dyn::parse_at(Endian::Big, Class::ELF64, &mut offset, &data.as_ref())
            .expect("Failed to parse Dyn");

        assert_eq!(
            entry,
            Dyn {
                d_tag: 0x0001020304050607,
                d_un: 0x08090A0B0C0D0E0F,
            }
        );
        assert_eq!(offset, ELF64DYNSIZE);
    }

    #[test]
    fn parse_dyn64_fuzz_too_short() {
        let data = [0u8; ELF64DYNSIZE];
        for n in 0..ELF64DYNSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Dyn::parse_at(Endian::Big, Class::ELF64, &mut offset, &buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
