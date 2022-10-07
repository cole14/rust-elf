use crate::file::Class;
use crate::gabi;
use crate::parse::{Endian, Parse};
use crate::utils::{read_u32, read_u64};

/// Encapsulates the contents of an ELF Section Header
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SectionHeader {
    /// Section Name
    pub sh_name: u32,
    /// Section Type
    pub sh_type: SectionType,
    /// Section Flags
    pub sh_flags: SectionFlag,
    /// in-memory address where this section is loaded
    pub sh_addr: u64,
    /// Byte-offset into the file where this section starts
    pub sh_offset: u64,
    /// Section size in bytes
    pub sh_size: u64,
    /// Defined by section type
    pub sh_link: u32,
    /// Defined by section type
    pub sh_info: u32,
    /// address alignment
    pub sh_addralign: u64,
    /// size of an entry if section data is an array of entries
    pub sh_entsize: u64,
}

impl<R> Parse<R> for SectionHeader
where
    R: std::io::Read,
{
    fn parse(endian: Endian, class: Class, reader: &mut R) -> Result<Self, crate::ParseError> {
        if class == gabi::ELFCLASS32 {
            return Ok(SectionHeader {
                sh_name: read_u32(endian, reader)?,
                sh_type: SectionType(read_u32(endian, reader)?),
                sh_flags: SectionFlag(read_u32(endian, reader)? as u64),
                sh_addr: read_u32(endian, reader)? as u64,
                sh_offset: read_u32(endian, reader)? as u64,
                sh_size: read_u32(endian, reader)? as u64,
                sh_link: read_u32(endian, reader)?,
                sh_info: read_u32(endian, reader)?,
                sh_addralign: read_u32(endian, reader)? as u64,
                sh_entsize: read_u32(endian, reader)? as u64,
            });
        }

        Ok(SectionHeader {
            sh_name: read_u32(endian, reader)?,
            sh_type: SectionType(read_u32(endian, reader)?),
            sh_flags: SectionFlag(read_u64(endian, reader)?),
            sh_addr: read_u64(endian, reader)?,
            sh_offset: read_u64(endian, reader)?,
            sh_size: read_u64(endian, reader)?,
            sh_link: read_u32(endian, reader)?,
            sh_info: read_u32(endian, reader)?,
            sh_addralign: read_u64(endian, reader)?,
            sh_entsize: read_u64(endian, reader)?,
        })
    }
}

impl std::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Section Header: Name: {} Type: {} Flags: {} Addr: {:#010x} Offset: {:#06x} Size: {:#06x} Link: {} Info: {:#x} AddrAlign: {} EntSize: {}",
            self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset,
            self.sh_size, self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize)
    }
}

/// Represens ELF Section type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SectionType(pub u32);

impl std::fmt::Debug for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::SHT_NULL => "SHT_NULL",
            gabi::SHT_PROGBITS => "SHT_PROGBITS",
            gabi::SHT_SYMTAB => "SHT_SYMTAB",
            gabi::SHT_STRTAB => "SHT_STRTAB",
            gabi::SHT_RELA => "SHT_RELA",
            gabi::SHT_HASH => "SHT_HASH",
            gabi::SHT_DYNAMIC => "SHT_DYNAMIC",
            gabi::SHT_NOTE => "SHT_NOTE",
            gabi::SHT_NOBITS => "SHT_NOBITS",
            gabi::SHT_REL => "SHT_REL",
            gabi::SHT_SHLIB => "SHT_SHLIB",
            gabi::SHT_DYNSYM => "SHT_DYNSYM",
            gabi::SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            gabi::SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            gabi::SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
            gabi::SHT_GROUP => "SHT_GROUP",
            gabi::SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
            gabi::SHT_NUM => "SHT_NUM",
            gabi::SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
            gabi::SHT_GNU_HASH => "SHT_GNU_HASH",
            gabi::SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
            gabi::SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            gabi::SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            gabi::SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

///
/// Wrapper type for SectionFlag
///
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SectionFlag(pub u64);

impl std::fmt::Debug for SectionFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for SectionFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::file::Class;
    use crate::gabi;
    use crate::parse::{Endian, Parse};
    use crate::section::{SectionFlag, SectionHeader, SectionType};

    #[test]
    fn parse_shdr32_fuzz_too_short() {
        let data = [0u8; 40];
        for n in 0..40 {
            let slice = data.split_at(n).0;
            assert!(SectionHeader::parse(
                Endian::Little,
                Class(gabi::ELFCLASS32),
                &mut slice.as_ref()
            )
            .is_err());
        }
    }

    #[test]
    fn parse_shdr32_works() {
        let mut data = [0u8; 40];
        for n in 0u8..40 {
            data[n as usize] = n;
        }

        assert_eq!(
            SectionHeader::parse(
                Endian::Little,
                Class(gabi::ELFCLASS32),
                &mut data.as_ref()
            )
            .unwrap(),
            SectionHeader {
                sh_name: 0x03020100,
                sh_type: SectionType(0x07060504),
                sh_flags: SectionFlag(0xB0A0908),
                sh_addr: 0x0F0E0D0C,
                sh_offset: 0x13121110,
                sh_size: 0x17161514,
                sh_link: 0x1B1A1918,
                sh_info: 0x1F1E1D1C,
                sh_addralign: 0x23222120,
                sh_entsize: 0x27262524,
            }
        );
    }

    #[test]
    fn parse_shdr64_fuzz_too_short() {
        let data = [0u8; 64];
        for n in 0..64 {
            let slice = data.split_at(n).0;
            assert!(SectionHeader::parse(
                Endian::Big,
                Class(gabi::ELFCLASS64),
                &mut slice.as_ref()
            )
            .is_err());
        }
    }

    #[test]
    fn parse_shdr64_works() {
        let mut data = [0u8; 64];
        for n in 0u8..64 {
            data[n as usize] = n;
        }

        assert_eq!(
            SectionHeader::parse(
                Endian::Big,
                Class(gabi::ELFCLASS64),
                &mut data.as_ref()
            )
            .unwrap(),
            SectionHeader {
                sh_name: 0x00010203,
                sh_type: SectionType(0x04050607),
                sh_flags: SectionFlag(0x08090A0B0C0D0E0F),
                sh_addr: 0x1011121314151617,
                sh_offset: 0x18191A1B1C1D1E1F,
                sh_size: 0x2021222324252627,
                sh_link: 0x28292A2B,
                sh_info: 0x2C2D2E2F,
                sh_addralign: 0x3031323334353637,
                sh_entsize: 0x38393A3B3C3D3E3F,
            }
        );
    }
}
