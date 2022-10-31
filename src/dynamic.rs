use crate::parse::{
    parse_i32_at, parse_i64_at, parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError,
    ParsingIterator,
};

pub type DynIterator<'data> = ParsingIterator<'data, Dyn>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dyn {
    pub d_tag: i64,
    pub(super) d_un: u64,
}

impl Dyn {
    pub fn d_val(self) -> u64 {
        self.d_un
    }

    pub fn d_ptr(self) -> u64 {
        self.d_un
    }
}

impl ParseAt for Dyn {
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(Dyn {
                d_tag: parse_i32_at(endian, offset, data)? as i64,
                d_un: parse_u32_at(endian, offset, data)? as u64,
            }),
            Class::ELF64 => Ok(Dyn {
                d_tag: parse_i64_at(endian, offset, data)?,
                d_un: parse_u64_at(endian, offset, data)?,
            }),
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => ELF32DYNSIZE,
            Class::ELF64 => ELF64DYNSIZE,
        }
    }
}

const ELF32DYNSIZE: usize = 8;
const ELF64DYNSIZE: usize = 16;

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_dyn32_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF32,
            Dyn {
                d_tag: 0x03020100,
                d_un: 0x07060504,
            },
        );
    }

    #[test]
    fn parse_dyn32_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF32,
            Dyn {
                d_tag: 0x00010203,
                d_un: 0x04050607,
            },
        );
    }

    #[test]
    fn parse_dyn64_lsb() {
        test_parse_for(
            Endian::Little,
            Class::ELF64,
            Dyn {
                d_tag: 0x0706050403020100,
                d_un: 0x0F0E0D0C0B0A0908,
            },
        );
    }

    #[test]
    fn parse_dyn64_msb() {
        test_parse_for(
            Endian::Big,
            Class::ELF64,
            Dyn {
                d_tag: 0x0001020304050607,
                d_un: 0x08090A0B0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_dyn32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Dyn>(Endian::Little, Class::ELF32);
    }

    #[test]
    fn parse_dyn32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Dyn>(Endian::Big, Class::ELF32);
    }

    #[test]
    fn parse_dyn64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Dyn>(Endian::Little, Class::ELF64);
    }

    #[test]
    fn parse_dyn64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Dyn>(Endian::Big, Class::ELF64);
    }
}
