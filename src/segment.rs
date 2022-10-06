use gabi;
use parse::Parse;
use types;
use utils;

/// Encapsulates the contents of an ELF Program Header
///
/// The program header table is an array of program header structures describing
/// the various segments for program execution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    /// Program segment type
    pub progtype: ProgType,
    /// Offset into the ELF file where this segment begins
    pub offset: u64,
    /// Virtual adress where this segment should be loaded
    pub vaddr: u64,
    /// Physical address where this segment should be loaded
    pub paddr: u64,
    /// Size of this segment in the file
    pub filesz: u64,
    /// Size of this segment in memory
    pub memsz: u64,
    /// Flags for this segment
    pub flags: ProgFlag,
    /// file and memory alignment
    pub align: u64,
}

impl<R> Parse<R> for ProgramHeader
where
    R: std::io::Read,
{
    fn parse(
        endian: types::Endian,
        class: types::Class,
        reader: &mut R,
    ) -> Result<Self, crate::ParseError> {
        if class == gabi::ELFCLASS32 {
            let p_type = utils::read_u32(endian, reader)?;
            let p_offset = utils::read_u32(endian, reader)?;
            let p_vaddr = utils::read_u32(endian, reader)?;
            let p_paddr = utils::read_u32(endian, reader)?;
            let p_filesz = utils::read_u32(endian, reader)?;
            let p_memsz = utils::read_u32(endian, reader)?;
            let p_flags = utils::read_u32(endian, reader)?;
            let p_align = utils::read_u32(endian, reader)?;
            return Ok(ProgramHeader {
                progtype: ProgType(p_type),
                offset: p_offset as u64,
                vaddr: p_vaddr as u64,
                paddr: p_paddr as u64,
                filesz: p_filesz as u64,
                memsz: p_memsz as u64,
                flags: ProgFlag(p_flags),
                align: p_align as u64,
            });
        }

        let p_type = utils::read_u32(endian, reader)?;
        let p_flags = utils::read_u32(endian, reader)?;
        let p_offset = utils::read_u64(endian, reader)?;
        let p_vaddr = utils::read_u64(endian, reader)?;
        let p_paddr = utils::read_u64(endian, reader)?;
        let p_filesz = utils::read_u64(endian, reader)?;
        let p_memsz = utils::read_u64(endian, reader)?;
        let p_align = utils::read_u64(endian, reader)?;
        Ok(ProgramHeader {
            progtype: ProgType(p_type),
            offset: p_offset,
            vaddr: p_vaddr,
            paddr: p_paddr,
            filesz: p_filesz,
            memsz: p_memsz,
            flags: ProgFlag(p_flags),
            align: p_align,
        })
    }
}

impl std::fmt::Display for ProgramHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Program Header: Type: {} Offset: {:#010x} VirtAddr: {:#010x} PhysAddr: {:#010x} FileSize: {:#06x} MemSize: {:#06x} Flags: {} Align: {:#x}",
            self.progtype, self.offset, self.vaddr, self.paddr, self.filesz,
            self.memsz, self.flags, self.align)
    }
}

/// Represents ELF Program Header flags
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgFlag(pub u32);
pub const PF_NONE: ProgFlag = ProgFlag(0);
/// Executable program segment
pub const PF_X: ProgFlag = ProgFlag(1);
/// Writable program segment
pub const PF_W: ProgFlag = ProgFlag(2);
/// Readable program segment
pub const PF_R: ProgFlag = ProgFlag(4);

impl std::fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if (self.0 & PF_R.0) != 0 {
            write!(f, "R")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & PF_W.0) != 0 {
            write!(f, "W")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & PF_X.0) != 0 {
            write!(f, "E")
        } else {
            write!(f, " ")
        }
    }
}

/// Represents ELF Program Header type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgType(pub u32);
/// Program header table entry unused
pub const PT_NULL: ProgType = ProgType(0);
/// Loadable program segment
pub const PT_LOAD: ProgType = ProgType(1);
/// Dynamic linking information
pub const PT_DYNAMIC: ProgType = ProgType(2);
/// Program interpreter
pub const PT_INTERP: ProgType = ProgType(3);
/// Auxiliary information
pub const PT_NOTE: ProgType = ProgType(4);
/// Unused
pub const PT_SHLIB: ProgType = ProgType(5);
/// The program header table
pub const PT_PHDR: ProgType = ProgType(6);
/// Thread-local storage segment
pub const PT_TLS: ProgType = ProgType(7);
/// GCC .eh_frame_hdr segment
pub const PT_GNU_EH_FRAME: ProgType = ProgType(0x6474e550);
/// Indicates stack executability
pub const PT_GNU_STACK: ProgType = ProgType(0x6474e551);
/// Read-only after relocation
pub const PT_GNU_RELRO: ProgType = ProgType(0x6474e552);

impl std::fmt::Debug for ProgType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for ProgType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match *self {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_SHLIB => "SHLIB",
            PT_PHDR => "PHDR",
            PT_TLS => "TLS",
            PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            PT_GNU_STACK => "GNU_STACK",
            PT_GNU_RELRO => "GNU_RELRO",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod tests {
    use gabi;
    use parse::Parse;
    use segment::{ProgFlag, ProgType, ProgramHeader};
    use types::{Class, Endian};

    #[test]
    fn parse_phdr32_fuzz_too_short() {
        let data = [0u8; 32];
        for n in 0..32 {
            let slice = data.split_at(n).0;
            assert!(ProgramHeader::parse(
                Endian(gabi::ELFDATA2LSB),
                Class(gabi::ELFCLASS32),
                &mut slice.as_ref()
            )
            .is_err());
        }
    }

    #[test]
    fn parse_phdr32_works() {
        let mut data = [0u8; 32];
        for n in 0u8..32 {
            data[n as usize] = n;
        }

        assert_eq!(
            ProgramHeader::parse(
                Endian(gabi::ELFDATA2LSB),
                Class(gabi::ELFCLASS32),
                &mut data.as_ref()
            )
            .unwrap(),
            ProgramHeader {
                progtype: ProgType(0x03020100),
                offset: 0x07060504,
                vaddr: 0xB0A0908,
                paddr: 0x0F0E0D0C,
                filesz: 0x13121110,
                memsz: 0x17161514,
                flags: ProgFlag(0x1B1A1918),
                align: 0x1F1E1D1C,
            }
        );
    }

    #[test]
    fn parse_phdr64_fuzz_too_short() {
        let data = [0u8; 56];
        for n in 0..56 {
            let slice = data.split_at(n).0;
            assert!(ProgramHeader::parse(
                Endian(gabi::ELFDATA2LSB),
                Class(gabi::ELFCLASS64),
                &mut slice.as_ref()
            )
            .is_err());
        }
    }

    #[test]
    fn parse_phdr64_works() {
        let mut data = [0u8; 56];
        for n in 0u8..56 {
            data[n as usize] = n;
        }

        assert_eq!(
            ProgramHeader::parse(
                Endian(gabi::ELFDATA2MSB),
                Class(gabi::ELFCLASS64),
                &mut data.as_ref()
            )
            .unwrap(),
            ProgramHeader {
                progtype: ProgType(0x00010203),
                offset: 0x08090A0B0C0D0E0F,
                vaddr: 0x1011121314151617,
                paddr: 0x18191A1B1C1D1E1F,
                filesz: 0x2021222324252627,
                memsz: 0x28292A2B2C2D2E2F,
                flags: ProgFlag(0x04050607),
                align: 0x3031323334353637,
            }
        );
    }
}
