//! Parsing relocation sections: `.rel.*`, `.rela.*`, [SHT_REL](crate::abi::SHT_REL), [SHT_RELA](crate::abi::SHT_RELA)
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError, ParsingIterator};

pub type RelIterator<'data, E> = ParsingIterator<'data, E, Rel>;
pub type RelaIterator<'data, E> = ParsingIterator<'data, E, Rela>;

/// C-style 32-bit ELF Relocation definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Rel {
    pub r_offset: u32,
    pub r_info: u32,
}

/// C-style 64-bit ELF Relocation definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Rel {
    pub r_offset: u64,
    pub r_info: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rel {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
}

impl ParseAt for Rel {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => {
                let r_offset = endian.parse_u32_at(offset, data)? as u64;
                let r_info = endian.parse_u32_at(offset, data)?;
                Ok(Rel {
                    r_offset,
                    r_sym: r_info >> 8,
                    r_type: r_info & 0xFF,
                })
            }
            Class::ELF64 => {
                let r_offset = endian.parse_u64_at(offset, data)?;
                let r_info = endian.parse_u64_at(offset, data)?;
                Ok(Rel {
                    r_offset,
                    r_sym: (r_info >> 32) as u32,
                    r_type: (r_info & 0xFFFFFFFF) as u32,
                })
            }
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

/// C-style 32-bit ELF Relocation (with addend) definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Rela {
    pub r_offset: u32,
    pub r_info: u32,
    pub r_addend: i32,
}

/// C-style 64-bit ELF Relocation (with addend) definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rela {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
    pub r_addend: i64,
}

impl ParseAt for Rela {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => {
                let r_offset = endian.parse_u32_at(offset, data)? as u64;
                let r_info = endian.parse_u32_at(offset, data)?;
                let r_addend = endian.parse_i32_at(offset, data)? as i64;
                Ok(Rela {
                    r_offset,
                    r_sym: r_info >> 8,
                    r_type: r_info & 0xFF,
                    r_addend,
                })
            }
            Class::ELF64 => {
                let r_offset = endian.parse_u64_at(offset, data)?;
                let r_info = endian.parse_u64_at(offset, data)?;
                let r_addend = endian.parse_i64_at(offset, data)?;
                Ok(Rela {
                    r_offset,
                    r_sym: (r_info >> 32) as u32,
                    r_type: (r_info & 0xFFFFFFFF) as u32,
                    r_addend,
                })
            }
        }
    }

    #[inline]
    fn size_for(class: Class) -> usize {
        match class {
            Class::ELF32 => 12,
            Class::ELF64 => 24,
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::{BigEndian, LittleEndian};
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_rel32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            Rel {
                r_offset: 0x03020100,
                r_sym: 0x00070605,
                r_type: 0x00000004,
            },
        );
    }

    #[test]
    fn parse_rel32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            Rel {
                r_offset: 0x00010203,
                r_sym: 0x00040506,
                r_type: 0x00000007,
            },
        );
    }

    #[test]
    fn parse_rel64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            Rel {
                r_offset: 0x0706050403020100,
                r_sym: 0x0F0E0D0C,
                r_type: 0x0B0A0908,
            },
        );
    }

    #[test]
    fn parse_rel64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            Rel {
                r_offset: 0x0001020304050607,
                r_sym: 0x08090A0B,
                r_type: 0x0C0D0E0F,
            },
        );
    }

    #[test]
    fn parse_rel32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rel>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_rel32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rel>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_rel64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rel>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_rel64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rel>(BigEndian, Class::ELF64);
    }

    #[test]
    fn parse_rela32_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF32,
            Rela {
                r_offset: 0x03020100,
                r_sym: 0x00070605,
                r_type: 0x00000004,
                r_addend: 0x0B0A0908,
            },
        );
    }

    #[test]
    fn parse_rela32_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF32,
            Rela {
                r_offset: 0x00010203,
                r_sym: 0x00040506,
                r_type: 0x00000007,
                r_addend: 0x08090A0B,
            },
        );
    }

    #[test]
    fn parse_rela64_lsb() {
        test_parse_for(
            LittleEndian,
            Class::ELF64,
            Rela {
                r_offset: 0x0706050403020100,
                r_sym: 0x0F0E0D0C,
                r_type: 0x0B0A0908,
                r_addend: 0x1716151413121110,
            },
        );
    }

    #[test]
    fn parse_rela64_msb() {
        test_parse_for(
            BigEndian,
            Class::ELF64,
            Rela {
                r_offset: 0x0001020304050607,
                r_sym: 0x08090A0B,
                r_type: 0x0C0D0E0F,
                r_addend: 0x1011121314151617,
            },
        );
    }

    #[test]
    fn parse_rela32_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rela>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_rela32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rela>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_rela64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rela>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_rela64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, Rela>(BigEndian, Class::ELF64);
    }
}
