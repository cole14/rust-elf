use gabi;
use parse::Parse;
use types;
use utils;

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
    fn parse(
        endian: types::Endian,
        class: types::Class,
        reader: &mut R,
    ) -> Result<Self, crate::ParseError> {
        if class == gabi::ELFCLASS32 {
            return Ok(SectionHeader {
                sh_name: utils::read_u32(endian, reader)?,
                sh_type: SectionType(utils::read_u32(endian, reader)?),
                sh_flags: SectionFlag(utils::read_u32(endian, reader)? as u64),
                sh_addr: utils::read_u32(endian, reader)? as u64,
                sh_offset: utils::read_u32(endian, reader)? as u64,
                sh_size: utils::read_u32(endian, reader)? as u64,
                sh_link: utils::read_u32(endian, reader)?,
                sh_info: utils::read_u32(endian, reader)?,
                sh_addralign: utils::read_u32(endian, reader)? as u64,
                sh_entsize: utils::read_u32(endian, reader)? as u64,
            });
        }

        Ok(SectionHeader {
            sh_name: utils::read_u32(endian, reader)?,
            sh_type: SectionType(utils::read_u32(endian, reader)?),
            sh_flags: SectionFlag(utils::read_u64(endian, reader)?),
            sh_addr: utils::read_u64(endian, reader)?,
            sh_offset: utils::read_u64(endian, reader)?,
            sh_size: utils::read_u64(endian, reader)?,
            sh_link: utils::read_u32(endian, reader)?,
            sh_info: utils::read_u32(endian, reader)?,
            sh_addralign: utils::read_u64(endian, reader)?,
            sh_entsize: utils::read_u64(endian, reader)?,
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
/// Inactive section with undefined values
pub const SHT_NULL: SectionType = SectionType(0);
/// Information defined by the program, includes executable code and data
pub const SHT_PROGBITS: SectionType = SectionType(1);
/// Section data contains a symbol table
pub const SHT_SYMTAB: SectionType = SectionType(2);
/// Section data contains a string table
pub const SHT_STRTAB: SectionType = SectionType(3);
/// Section data contains relocation entries with explicit addends
pub const SHT_RELA: SectionType = SectionType(4);
/// Section data contains a symbol hash table. Must be present for dynamic linking
pub const SHT_HASH: SectionType = SectionType(5);
/// Section data contains information for dynamic linking
pub const SHT_DYNAMIC: SectionType = SectionType(6);
/// Section data contains information that marks the file in some way
pub const SHT_NOTE: SectionType = SectionType(7);
/// Section data occupies no space in the file but otherwise resembles SHT_PROGBITS
pub const SHT_NOBITS: SectionType = SectionType(8);
/// Section data contains relocation entries without explicit addends
pub const SHT_REL: SectionType = SectionType(9);
/// Section is reserved but has unspecified semantics
pub const SHT_SHLIB: SectionType = SectionType(10);
/// Section data contains a minimal set of dynamic linking symbols
pub const SHT_DYNSYM: SectionType = SectionType(11);
/// Section data contains an array of constructors
pub const SHT_INIT_ARRAY: SectionType = SectionType(14);
/// Section data contains an array of destructors
pub const SHT_FINI_ARRAY: SectionType = SectionType(15);
/// Section data contains an array of pre-constructors
pub const SHT_PREINIT_ARRAY: SectionType = SectionType(16);
/// Section group
pub const SHT_GROUP: SectionType = SectionType(17);
/// Extended symbol table section index
pub const SHT_SYMTAB_SHNDX: SectionType = SectionType(18);
/// Number of reserved SHT_* values
pub const SHT_NUM: SectionType = SectionType(19);
/// Object attributes
pub const SHT_GNU_ATTRIBUTES: SectionType = SectionType(0x6ffffff5);
/// GNU-style hash section
pub const SHT_GNU_HASH: SectionType = SectionType(0x6ffffff6);
/// Pre-link library list
pub const SHT_GNU_LIBLIST: SectionType = SectionType(0x6ffffff7);
/// Version definition section
pub const SHT_GNU_VERDEF: SectionType = SectionType(0x6ffffffd);
/// Version needs section
pub const SHT_GNU_VERNEED: SectionType = SectionType(0x6ffffffe);
/// Version symbol table
pub const SHT_GNU_VERSYM: SectionType = SectionType(0x6fffffff);

impl std::fmt::Debug for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for SectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match *self {
            SHT_NULL => "SHT_NULL",
            SHT_PROGBITS => "SHT_PROGBITS",
            SHT_SYMTAB => "SHT_SYMTAB",
            SHT_STRTAB => "SHT_STRTAB",
            SHT_RELA => "SHT_RELA",
            SHT_HASH => "SHT_HASH",
            SHT_DYNAMIC => "SHT_DYNAMIC",
            SHT_NOTE => "SHT_NOTE",
            SHT_NOBITS => "SHT_NOBITS",
            SHT_REL => "SHT_REL",
            SHT_SHLIB => "SHT_SHLIB",
            SHT_DYNSYM => "SHT_DYNSYM",
            SHT_INIT_ARRAY => "SHT_INIT_ARRAY",
            SHT_FINI_ARRAY => "SHT_FINI_ARRAY",
            SHT_PREINIT_ARRAY => "SHT_PREINIT_ARRAY",
            SHT_GROUP => "SHT_GROUP",
            SHT_SYMTAB_SHNDX => "SHT_SYMTAB_SHNDX",
            SHT_NUM => "SHT_NUM",
            SHT_GNU_ATTRIBUTES => "SHT_GNU_ATTRIBUTES",
            SHT_GNU_HASH => "SHT_GNU_HASH",
            SHT_GNU_LIBLIST => "SHT_GNU_LIBLIST",
            SHT_GNU_VERDEF => "SHT_GNU_VERDEF",
            SHT_GNU_VERNEED => "SHT_GNU_VERNEED",
            SHT_GNU_VERSYM => "SHT_GNU_VERSYM",
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
/// Empty flags
pub const SHF_NONE: SectionFlag = SectionFlag(0);
/// Writable
pub const SHF_WRITE: SectionFlag = SectionFlag(1);
/// Occupies memory during execution
pub const SHF_ALLOC: SectionFlag = SectionFlag(2);
/// Executable
pub const SHF_EXECINSTR: SectionFlag = SectionFlag(4);
/// Might be merged
pub const SHF_MERGE: SectionFlag = SectionFlag(16);
/// Contains nul-terminated strings
pub const SHF_STRINGS: SectionFlag = SectionFlag(32);
/// `sh_info' contains SHT index
pub const SHF_INFO_LINK: SectionFlag = SectionFlag(64);
/// Preserve order after combining
pub const SHF_LINK_ORDER: SectionFlag = SectionFlag(128);
/// Non-standard OS specific handling required
pub const SHF_OS_NONCONFORMING: SectionFlag = SectionFlag(256);
/// Section is member of a group
pub const SHF_GROUP: SectionFlag = SectionFlag(512);
/// Section hold thread-local data
pub const SHF_TLS: SectionFlag = SectionFlag(1024);

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
    use gabi;
    use parse::Parse;
    use section::{SectionFlag, SectionHeader, SectionType};
    use types::{Class, Endian};

    #[test]
    fn parse_shdr32_fuzz_too_short() {
        let data = [0u8; 40];
        for n in 0..40 {
            let slice = data.split_at(n).0;
            assert!(SectionHeader::parse(
                Endian(gabi::ELFDATA2LSB),
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
                Endian(gabi::ELFDATA2LSB),
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
                Endian(gabi::ELFDATA2LSB),
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
                Endian(gabi::ELFDATA2MSB),
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
