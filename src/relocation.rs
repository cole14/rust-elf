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

    #[test]
    fn parse_rel32_lsb() {
        let mut data = [0u8; ELF32RELSIZE];
        for n in 0..ELF32RELSIZE {
            data[n] = n as u8;
        }

        let mut offset = 0;
        let entry = Rel::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse Rel");

        assert_eq!(
            entry,
            Rel {
                r_offset: 0x03020100,
                r_sym: 0x00070605,
                r_type: 0x00000004,
            }
        );
        assert_eq!(offset, ELF32RELSIZE);
    }

    #[test]
    fn parse_rel32_fuzz_too_short() {
        let data = [0u8; ELF32RELSIZE];
        for n in 0..ELF32RELSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Rel::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_rel64_msb() {
        let mut data = [0u8; ELF64RELSIZE];
        for n in 0..ELF64RELSIZE {
            data[n] = n as u8;
        }

        let mut offset = 0;
        let entry = Rel::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse Rel");

        assert_eq!(
            entry,
            Rel {
                r_offset: 0x0001020304050607,
                r_sym: 0x08090A0B,
                r_type: 0x0C0D0E0F,
            }
        );
        assert_eq!(offset, ELF64RELSIZE);
    }

    #[test]
    fn parse_rel64_fuzz_too_short() {
        let data = [0u8; ELF64RELSIZE];
        for n in 0..ELF64RELSIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Rel::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_rela32_lsb() {
        let mut data = [0u8; ELF32RELASIZE];
        for n in 0..ELF32RELASIZE {
            data[n] = n as u8;
        }

        let mut offset = 0;
        let entry = Rela::parse_at(Endian::Little, Class::ELF32, &mut offset, data.as_ref())
            .expect("Failed to parse Rela");

        assert_eq!(
            entry,
            Rela {
                r_offset: 0x03020100,
                r_sym: 0x00070605,
                r_type: 0x00000004,
                r_addend: 0x0B0A0908,
            }
        );
        assert_eq!(offset, ELF32RELASIZE);
    }

    #[test]
    fn parse_rela32_fuzz_too_short() {
        let data = [0u8; ELF32RELASIZE];
        for n in 0..ELF32RELASIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Rela::parse_at(Endian::Big, Class::ELF32, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }

    #[test]
    fn parse_rela64_msb() {
        let mut data = [0u8; ELF64RELASIZE];
        for n in 0..ELF64RELASIZE {
            data[n] = n as u8;
        }

        let mut offset = 0;
        let entry = Rela::parse_at(Endian::Big, Class::ELF64, &mut offset, data.as_ref())
            .expect("Failed to parse Rela");

        assert_eq!(
            entry,
            Rela {
                r_offset: 0x0001020304050607,
                r_sym: 0x08090A0B,
                r_type: 0x0C0D0E0F,
                r_addend: 0x1011121314151617
            }
        );
        assert_eq!(offset, ELF64RELASIZE);
    }

    #[test]
    fn parse_rela64_fuzz_too_short() {
        let data = [0u8; ELF64RELASIZE];
        for n in 0..ELF64RELASIZE {
            let buf = data.split_at(n).0.as_ref();
            let mut offset: usize = 0;
            let error = Rela::parse_at(Endian::Big, Class::ELF64, &mut offset, buf)
                .expect_err("Expected an error");
            assert!(
                matches!(error, ParseError::BadOffset(_)),
                "Unexpected Error type found: {error}"
            );
        }
    }
}
