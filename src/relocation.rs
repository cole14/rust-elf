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
#[allow(non_camel_case_types)]
pub struct Elf32_Rel {
    pub r_offset: u32,
    pub r_info: u32,
}

/// C-style 64-bit ELF Relocation definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
#[allow(non_camel_case_types)]
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
#[allow(non_camel_case_types)]
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
#[allow(non_camel_case_types)]
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

/// APS2 is what Chrome for Android uses. It stores the same fields as REL/RELA`, but uses variable length ints (LEB128) and run-length encoding.
///
/// format: https://android.googlesource.com/platform/bionic/+/52a7e7e1bcb7513ddf798eff4c0b713c26861cb5/tools/relocation_packer/src/delta_encoder.h
/// llvm implementation: https://github.com/llvm/llvm-project/blob/ca53611c905f82628ab2e40185307995b552e14d/llvm/lib/Object/ELF.cpp#L450
pub mod aps2 {
    use crate::file::Class;
    use crate::parse::{leb128, ParseError};
    use crate::relocation::{Rel, Rela};

    const MAGIC_PREFIX: [u8; 4] = [b'A', b'P', b'S', b'2'];

    pub type AndroidRelIterator<'data> = ParsingIterator<'data, false>;
    pub type AndroidRelaIterator<'data> = ParsingIterator<'data, true>;

    #[derive(Debug, Clone, Copy)]
    struct GroupFlag(u8);
    impl GroupFlag {
        const GROUP_FLAG_BY_INFO: u8 = 0x1;
        const GROUP_FLAG_BY_OFFSET_DELTA: u8 = 0x2;
        const GROUP_FLAG_BY_ADDEND: u8 = 0x4;
        const GROUP_FLAG_HAS_ADDEND: u8 = 0x8;

        pub fn is_relocation_grouped_by_offset_delta(&self) -> bool {
            self.0 & Self::GROUP_FLAG_BY_OFFSET_DELTA != 0
        }
        pub fn is_relocation_grouped_by_info(&self) -> bool {
            self.0 & Self::GROUP_FLAG_BY_INFO != 0
        }

        pub fn is_relocation_grouped_by_addend(&self) -> bool {
            self.0 & Self::GROUP_FLAG_BY_ADDEND != 0
        }

        pub fn is_relocation_group_has_addend(&self) -> bool {
            self.0 & Self::GROUP_FLAG_HAS_ADDEND != 0
        }
    }

    impl From<i64> for GroupFlag {
        fn from(flag: i64) -> Self {
            Self(flag as u8)
        }
    }

    #[derive(Debug, Clone)]
    struct GroupedRelocation {
        class: Class,
        r_offset: u64,
        r_info: u64,
        r_addend: i64,
    }

    impl From<GroupedRelocation> for Rela {
        fn from(value: GroupedRelocation) -> Self {
            let r_info = value.r_info;
            match value.class {
                Class::ELF32 => Rela {
                    r_offset: value.r_offset,
                    r_sym: (r_info >> 8) as u32,
                    r_type: (r_info & 0xFF) as u32,
                    r_addend: value.r_addend,
                },
                Class::ELF64 => Rela {
                    r_offset: value.r_offset,
                    r_sym: (r_info >> 32) as u32,
                    r_type: (r_info & 0xFFFFFFFF) as u32,
                    r_addend: value.r_addend,
                },
            }
        }
    }

    impl From<GroupedRelocation> for Rel {
        fn from(value: GroupedRelocation) -> Self {
            let r_info = value.r_info;
            match value.class {
                Class::ELF32 => Rel {
                    r_offset: value.r_offset,
                    r_sym: (r_info >> 8) as u32,
                    r_type: (r_info & 0xFF) as u32,
                },
                Class::ELF64 => Rel {
                    r_offset: value.r_offset,
                    r_sym: (r_info >> 32) as u32,
                    r_type: (r_info & 0xFFFFFFFF) as u32,
                },
            }
        }
    }

    /// | relocation_count | r_offset |
    /// |          group              |
    /// |          group              |
    /// |           ...               |
    #[derive(Debug)]
    pub struct ParsingIterator<'data, const RELA: bool> {
        class: Class,

        data: &'data [u8],
        offset: usize,

        relocation_index: usize,
        relocation_count: usize,

        group_relocation_index: usize,
        group_relocation_count: usize,

        group_flags: GroupFlag,
        group_r_offset_delta: u64,

        relocation: GroupedRelocation,
    }

    impl<'data, const RELA: bool> ParsingIterator<'data, RELA> {
        pub fn new(class: Class, data: &'data [u8]) -> Result<Self, ParseError> {
            if data.len() < 4 {
                return Err(ParseError::SliceReadError((0, 4)));
            }
            if data[..4] != MAGIC_PREFIX {
                return Err(ParseError::BadMagic([data[0], data[1], data[2], data[3]]));
            }

            let mut iter = Self {
                class,
                data: &data[4..],
                offset: 0,

                relocation_index: 0,
                relocation_count: 0,

                group_relocation_index: 0,
                group_relocation_count: 0,
                group_flags: GroupFlag(0),
                group_r_offset_delta: 0,

                relocation: GroupedRelocation {
                    class,
                    r_offset: 0,
                    r_info: 0,
                    r_addend: 0,
                },
            };
            iter.init()?;

            Ok(iter)
        }

        fn init(&mut self) -> Result<(), ParseError> {
            self.relocation_count = self.read_signed_leb128()? as usize;

            // initial r_offset
            self.relocation.r_offset = self.read_signed_leb128()? as u64;
            Ok(())
        }

        fn read_signed_leb128(&mut self) -> Result<i64, ParseError> {
            match self.class {
                Class::ELF32 => {
                    let (data, offset) = leb128::int32(&self.data[self.offset..])?;
                    self.offset += offset;
                    Ok(data as i64)
                }
                Class::ELF64 => {
                    let (data, offset) = leb128::int64(&self.data[self.offset..])?;
                    self.offset += offset;
                    Ok(data)
                }
            }
        }

        fn read_group_fields(&mut self) -> Result<(), ParseError> {
            self.group_relocation_count = self.read_signed_leb128()? as usize;
            self.group_flags = self.read_signed_leb128()?.into();

            if self.group_flags.is_relocation_grouped_by_offset_delta() {
                self.group_r_offset_delta = self.read_signed_leb128()? as u64;
            }

            if self.group_flags.is_relocation_grouped_by_info() {
                self.relocation.r_info = self.read_signed_leb128()? as u64;
            }

            if self.group_flags.is_relocation_grouped_by_addend()
                && self.group_flags.is_relocation_group_has_addend()
            {
                if !RELA {
                    return Err(ParseError::UnexpectedRelocationAddend);
                }
                self.relocation.r_addend = self
                    .relocation
                    .r_addend
                    .wrapping_add(self.read_signed_leb128()?);
            } else if !self.group_flags.is_relocation_group_has_addend() && RELA {
                self.relocation.r_addend = 0;
            }

            self.group_relocation_index = 0;
            Ok(())
        }

        fn read_group_relocation(&mut self) -> Result<(), ParseError> {
            if self.group_flags.is_relocation_grouped_by_offset_delta() {
                self.relocation.r_offset = self
                    .relocation
                    .r_offset
                    .wrapping_add(self.group_r_offset_delta);
            } else {
                // may overflow
                self.relocation.r_offset = self
                    .relocation
                    .r_offset
                    .wrapping_add(self.read_signed_leb128()? as u64);
            };

            if !self.group_flags.is_relocation_grouped_by_info() {
                self.relocation.r_info = self.read_signed_leb128()? as u64;
            }

            if self.group_flags.is_relocation_group_has_addend()
                && !self.group_flags.is_relocation_grouped_by_addend()
            {
                if !RELA {
                    return Err(ParseError::UnexpectedRelocationAddend);
                }
                self.relocation.r_addend = self
                    .relocation
                    .r_addend
                    .wrapping_add(self.read_signed_leb128()?);
            }

            self.relocation_index += 1;
            self.group_relocation_index += 1;

            Ok(())
        }
    }

    impl<'data> Iterator for ParsingIterator<'data, true> {
        type Item = Result<Rela, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.relocation_index >= self.relocation_count {
                return None;
            }

            if self.group_relocation_index >= self.group_relocation_count {
                match self.read_group_fields() {
                    Ok(_) => {}
                    Err(e) => return Some(Err(e)),
                }
            }

            match self.read_group_relocation() {
                Ok(_) => Some(Ok(self.relocation.clone().into())),
                Err(e) => Some(Err(e)),
            }
        }
    }

    impl<'data> Iterator for ParsingIterator<'data, false> {
        type Item = Result<Rel, ParseError>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.relocation_index >= self.relocation_count {
                return None;
            }

            if self.group_relocation_index >= self.group_relocation_count {
                match self.read_group_fields() {
                    Ok(_) => {}
                    Err(e) => return Some(Err(e)),
                }
            }

            match self.read_group_relocation() {
                Ok(_) => Some(Ok(self.relocation.clone().into())),
                Err(e) => Some(Err(e)),
            }
        }
    }
}

/// RELR is what Chrome OS uses, and is supported in Android P+ (tracking bug for enabling).
/// It encodes only relative relocations and uses a bitmask to do so (which works well since all symbols that require relocations live in .data.rel.ro).
/// format: https://maskray.me/blog/2021-10-31-relative-relocations-and-relr
/// llvm implementation: https://github.com/llvm/llvm-project/blob/3ef64f7ab5b8651eab500cd944984379fce5f639/llvm/lib/Object/ELF.cpp#L334
pub mod relr {
    use crate::abi;
    use crate::endian::EndianParse;
    use crate::file::Class;
    use crate::parse::ParseError;
    use crate::relocation::Rel;

    #[cfg(feature = "std")]
    pub fn decode_relocations<E>(machine: u16, class: Class, endian: E, data: &[u8]) -> Vec<Rel>
        where E: EndianParse
    {
        let typ = get_relocation_type(machine);
        let entry_sz = match class{
            Class::ELF32 => 4,
            Class::ELF64 => 8,
        };

        let mut relocations = Vec::new();

        let mut offset = 0;
        let mut base = 0;

        while offset < data.len(){
            let entry = match class{
                Class::ELF32 => endian.parse_u32_at(&mut offset, data).unwrap() as u64,
                Class::ELF64 => endian.parse_u64_at(&mut offset, data).unwrap(),
            };
            
            if entry & 1 == 0{
                relocations.push(Rel{
                    r_offset: entry,
                    r_sym: 0,
                    r_type: typ,
                });
                base = entry + entry_sz;
            } else {
                let mut offset = base;
                let mut entry = entry;
                entry >>= 1;
                while entry != 0{
                    if entry & 1 != 0{
                        relocations.push(Rel{
                            r_offset: offset,
                            r_sym: 0,
                            r_type: typ,
                        });
                    }
                    offset += entry_sz;
                    entry >>= 1;
                }
                base += (8 * entry_sz - 1) * entry_sz;
            }
        }
        relocations
    }

    #[derive(Debug)]
    pub struct RelativeRelocationIterator<'data, E: EndianParse> {
        class: Class,
        endian: E,

        data: &'data [u8],
        offset: usize,

        typ: u32,
        state: IterState,
    }

    #[derive(Debug, Clone, Copy)]
    struct IterState {
        bitmap: bool,
        base: u64,
        entry: u64,
        offset: u64,
    }

    fn get_relocation_type(machine: u16) -> u32 {
        match machine {
            abi::EM_X86_64 => abi::R_X86_64_RELATIVE,
            abi::EM_386 | abi::EM_IAMCU => abi::R_386_RELATIVE,
            abi::EM_AARCH64 => abi::R_AARCH64_RELATIVE,
            abi::EM_ARM => abi::R_ARM_RELATIVE,
            abi::EM_ARC_COMPACT | abi::EM_ARC_COMPACT2 => abi::R_ARC_RELATIVE,
            abi::EM_QDSP6 => abi::R_HEX_RELATIVE,
            abi::EM_PPC64 => abi::R_PPC64_RELATIVE,
            abi::EM_RISCV => abi::R_RISCV_RELATIVE,
            abi::EM_S390 => abi::R_390_RELATIVE,
            abi::EM_SPARC | abi::EM_SPARC32PLUS | abi::EM_SPARCV9 => abi::R_SPARC_RELATIVE,
            abi::EM_CSKY => abi::R_CKCORE_RELATIVE,
            abi::EM_VE => abi::R_VE_RELATIVE,
            abi::EM_LOONGARCH => abi::R_LARCH_RELATIVE,
            _ => 0,
        }
    }

    impl<'data, E: EndianParse> RelativeRelocationIterator<'data, E> {
        const BYTE_BITS: u64 = 8;

        pub fn new(machine: u16, class: Class, endian: E, data: &'data [u8]) -> Self {
            Self {
                class,
                endian,

                data,
                offset: 0,

                typ: get_relocation_type(machine),
                state: IterState {
                    bitmap: false,
                    base: 0,
                    entry: 0,
                    offset: 0,
                },
            }
        }

        fn read_entry(&mut self) -> Result<u64, ParseError> {
            match self.class {
                Class::ELF32 => self
                    .endian
                    .parse_u32_at(&mut self.offset, self.data)
                    .map(|v| v as u64),
                Class::ELF64 => self.endian.parse_u64_at(&mut self.offset, self.data),
            }
        }

        #[inline(always)]
        fn entry_size(&self) -> u64 {
            match self.class {
                Class::ELF32 => 4,
                Class::ELF64 => 8,
            }
        }

        fn read_r_offset(&mut self) -> Result<u64, ParseError> {
            if !self.state.bitmap{
                let entry = self.read_entry()?;
                if entry & 1 == 0 {
                    self.state.base = entry + self.entry_size();
                    return Ok(entry);
                }

                self.state.bitmap = true;
                self.state.entry = entry;
                self.state.offset = self.state.base;
            }

            self.state.entry >>= 1;
            if self.state.entry == 0 {
                self.state.base += (Self::BYTE_BITS * self.entry_size() - 1) * self.entry_size();
                self.state.bitmap = false;
                return self.read_r_offset();
            }

            let offset = self.state.offset;
            self.state.offset += self.entry_size();

            if self.state.entry & 1 != 0 {
                return Ok(offset);
            }
            self.read_r_offset()
        }
    }

    impl<'data, E: EndianParse> Iterator for RelativeRelocationIterator<'data, E> {
        type Item = Rel;

        fn next(&mut self) -> Option<Self::Item> {
            if !self.state.bitmap && self.offset >= self.data.len(){
                return None;
            }

            match self.read_r_offset() {
                Ok(rel) => Some(Rel{
                    r_offset: rel,
                    r_sym: 0,
                    r_type: self.typ,
                }),
                Err(_) => None,
            }
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
