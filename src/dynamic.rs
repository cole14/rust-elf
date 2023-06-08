//! Parsing `.dynamic` section or [PT_DYNAMIC](crate::abi::PT_DYNAMIC) segment contents
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingTable};

pub type DynamicTable<'data, E> = ParsingTable<'data, E, Dyn>;

/// C-style 32-bit ELF Dynamic section entry definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Dyn {
    pub d_tag: i32,
    // union of both {d_val, d_ptr}
    pub d_un: u32,
}

/// C-style 64-bit ELF Dynamic section entry definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Dyn {
    pub d_tag: i64,
    // union of both {d_val, d_ptr}
    pub d_un: u64,
}

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
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(Dyn {
                d_tag: endian.parse_i32_at(offset, data)? as i64,
                d_un: endian.parse_u32_at(offset, data)? as u64,
            }),
            Class::ELF64 => Ok(Dyn {
                d_tag: endian.parse_i64_at(offset, data)?,
                d_un: endian.parse_u64_at(offset, data)?,
            }),
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 8,
            Class::ELF64 => 16,
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_dyn32_lsb() {
        test_parse_for(
            LittleEndian,
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
            BigEndian,
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
            LittleEndian,
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
            BigEndian,
            Class::ELF64,
            Dyn {
                d_tag: 0x0001020304050607,
                d_un: 0x08090A0B0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_dyn32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Dyn>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_dyn32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Dyn>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_dyn64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Dyn>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_dyn64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Dyn>(BigEndian, Class::ELF64);
    }
}
