//! Parsing [CompressionHeader] from compressed ELF sections
//!
//! Note: This library does not provide any decompression functionality, but
//! does expose parsed ELF compression headers alongside the raw compressed data.
//!
//! It is up to users of the library to choose the decompression library of
//! their choice when dealing with compressed section contents.
use crate::endian::EndianParse;
use crate::file::Class;
use crate::parse::{ParseAt, ParseError};

/// C-style 32-bit ELF Compression Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Chdr {
    pub ch_type: u32,
    pub ch_size: u32,
    pub ch_addralign: u32,
}

/// C-style 64-bit ELF Compression Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Chdr {
    pub ch_type: u32,
    pub ch_reserved: u32,
    pub ch_size: u64,
    pub ch_addralign: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionHeader {
    pub ch_type: u32,
    pub ch_size: u64,
    pub ch_addralign: u64,
}

impl ParseAt for CompressionHeader {
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match class {
            Class::ELF32 => Ok(CompressionHeader {
                ch_type: endian.parse_u32_at(offset, data)?,
                ch_size: endian.parse_u32_at(offset, data)? as u64,
                ch_addralign: endian.parse_u32_at(offset, data)? as u64,
            }),
            Class::ELF64 => {
                let ch_type = endian.parse_u32_at(offset, data)?;
                let _ch_reserved = endian.parse_u32_at(offset, data)?;
                Ok(CompressionHeader {
                    ch_type,
                    ch_size: endian.parse_u64_at(offset, data)?,
                    ch_addralign: endian.parse_u64_at(offset, data)?,
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
    fn parse_chdr32_lsb() {
        test_parse_for(
            LittleEndian,
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
            BigEndian,
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
            LittleEndian,
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
            BigEndian,
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
        test_parse_fuzz_too_short::<_, CompressionHeader>(LittleEndian, Class::ELF32);
    }

    #[test]
    fn parse_chdr32_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, CompressionHeader>(BigEndian, Class::ELF32);
    }

    #[test]
    fn parse_chdr64_lsb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, CompressionHeader>(LittleEndian, Class::ELF64);
    }

    #[test]
    fn parse_chdr64_msb_fuzz_too_short() {
        test_parse_fuzz_too_short::<_, CompressionHeader>(BigEndian, Class::ELF64);
    }
}
