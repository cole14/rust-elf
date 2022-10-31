use crate::parse::{
    parse_i32_at, parse_i64_at, parse_u32_at, parse_u64_at, Class, Endian, ParseAt, ParseError,
    ParsingIterator,
};

pub type RelIterator<'data> = ParsingIterator<'data, Rel>;
pub type RelaIterator<'data> = ParsingIterator<'data, Rela>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rel {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
}

impl ParseAt for Rel {
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => {
                let r_offset = parse_u32_at(endian, offset, data)? as u64;
                let r_info = parse_u32_at(endian, offset, data)?;
                Ok(Rel {
                    r_offset,
                    r_sym: r_info >> 8,
                    r_type: r_info & 0xFF,
                })
            }
            Class::ELF64 => {
                let r_offset = parse_u64_at(endian, offset, data)?;
                let r_info = parse_u64_at(endian, offset, data)?;
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
            Class::ELF32 => ELF32RELSIZE,
            Class::ELF64 => ELF64RELSIZE,
        }
    }
}

const ELF32RELSIZE: usize = 8;
const ELF64RELSIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rela {
    pub r_offset: u64,
    pub r_sym: u32,
    pub r_type: u32,
    pub r_addend: i64,
}

impl ParseAt for Rela {
    fn parse_at(
        endian: Endian,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => {
                let r_offset = parse_u32_at(endian, offset, data)? as u64;
                let r_info = parse_u32_at(endian, offset, data)?;
                let r_addend = parse_i32_at(endian, offset, data)? as i64;
                Ok(Rela {
                    r_offset,
                    r_sym: r_info >> 8,
                    r_type: r_info & 0xFF,
                    r_addend,
                })
            }
            Class::ELF64 => {
                let r_offset = parse_u64_at(endian, offset, data)?;
                let r_info = parse_u64_at(endian, offset, data)?;
                let r_addend = parse_i64_at(endian, offset, data)?;
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
            Class::ELF32 => ELF32RELASIZE,
            Class::ELF64 => ELF64RELASIZE,
        }
    }
}

const ELF32RELASIZE: usize = 12;
const ELF64RELASIZE: usize = 24;

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::parse::{test_parse_for, test_parse_fuzz_too_short};

    #[test]
    fn parse_rel32_lsb() {
        test_parse_for(
            Endian::Little,
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
            Endian::Big,
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
            Endian::Little,
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
            Endian::Big,
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
        test_parse_fuzz_too_short::<Rel>(Endian::Little, Class::ELF32);
    }

    #[test]
    fn parse_rel32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rel>(Endian::Big, Class::ELF32);
    }

    #[test]
    fn parse_rel64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rel>(Endian::Little, Class::ELF64);
    }

    #[test]
    fn parse_rel64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rel>(Endian::Big, Class::ELF64);
    }

    #[test]
    fn parse_rela32_lsb() {
        test_parse_for(
            Endian::Little,
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
            Endian::Big,
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
            Endian::Little,
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
            Endian::Big,
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
        test_parse_fuzz_too_short::<Rela>(Endian::Little, Class::ELF32);
    }

    #[test]
    fn parse_rela32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rela>(Endian::Big, Class::ELF32);
    }

    #[test]
    fn parse_rela64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rela>(Endian::Little, Class::ELF64);
    }

    #[test]
    fn parse_rela64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<Rela>(Endian::Big, Class::ELF64);
    }
}
