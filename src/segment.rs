use crate::file::Class;
use crate::gabi;
use crate::parse::{Parse, ParseError, ReadExt};

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
    R: ReadExt,
{
    fn parse(class: Class, reader: &mut R) -> Result<Self, ParseError> {
        if class == gabi::ELFCLASS32 {
            let p_type = reader.read_u32()?;
            let p_offset = reader.read_u32()?;
            let p_vaddr = reader.read_u32()?;
            let p_paddr = reader.read_u32()?;
            let p_filesz = reader.read_u32()?;
            let p_memsz = reader.read_u32()?;
            let p_flags = reader.read_u32()?;
            let p_align = reader.read_u32()?;
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

        let p_type = reader.read_u32()?;
        let p_flags = reader.read_u32()?;
        let p_offset = reader.read_u64()?;
        let p_vaddr = reader.read_u64()?;
        let p_paddr = reader.read_u64()?;
        let p_filesz = reader.read_u64()?;
        let p_memsz = reader.read_u64()?;
        let p_align = reader.read_u64()?;
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

impl std::fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if (self.0 & gabi::PF_R) != 0 {
            write!(f, "R")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & gabi::PF_W) != 0 {
            write!(f, "W")?;
        } else {
            write!(f, " ")?;
        }
        if (self.0 & gabi::PF_X) != 0 {
            write!(f, "E")
        } else {
            write!(f, " ")
        }
    }
}

/// Represents ELF Program Header type
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgType(pub u32);

impl std::fmt::Debug for ProgType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl std::fmt::Display for ProgType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self.0 {
            gabi::PT_NULL => "NULL",
            gabi::PT_LOAD => "LOAD",
            gabi::PT_DYNAMIC => "DYNAMIC",
            gabi::PT_INTERP => "INTERP",
            gabi::PT_NOTE => "NOTE",
            gabi::PT_SHLIB => "SHLIB",
            gabi::PT_PHDR => "PHDR",
            gabi::PT_TLS => "TLS",
            gabi::PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            gabi::PT_GNU_STACK => "GNU_STACK",
            gabi::PT_GNU_RELRO => "GNU_RELRO",
            _ => "Unknown",
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod tests {
    use crate::file::Class;
    use crate::gabi;
    use crate::parse::{Endian, Parse, Reader};
    use crate::segment::{ProgFlag, ProgType, ProgramHeader};
    use std::io::Cursor;

    #[test]
    fn parse_phdr32_fuzz_too_short() {
        let data = [0u8; 32];
        for n in 0..32 {
            let mut cur = Cursor::new(data.split_at(n).0.as_ref());
            let mut reader = Reader::new(&mut cur, Endian::Little);
            assert!(ProgramHeader::parse(Class(gabi::ELFCLASS32), &mut reader).is_err());
        }
    }

    #[test]
    fn parse_phdr32_works() {
        let mut data = [0u8; 32];
        for n in 0u8..32 {
            data[n as usize] = n;
        }

        let mut cur = Cursor::new(data.as_ref());
        let mut reader = Reader::new(&mut cur, Endian::Little);
        assert_eq!(
            ProgramHeader::parse(Class(gabi::ELFCLASS32), &mut reader).unwrap(),
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
            let mut cur = Cursor::new(data.split_at(n).0.as_ref());
            let mut reader = Reader::new(&mut cur, Endian::Big);
            assert!(ProgramHeader::parse(Class(gabi::ELFCLASS64), &mut reader).is_err());
        }
    }

    #[test]
    fn parse_phdr64_works() {
        let mut data = [0u8; 56];
        for n in 0u8..56 {
            data[n as usize] = n;
        }

        let mut cur = Cursor::new(data.as_ref());
        let mut reader = Reader::new(&mut cur, Endian::Big);
        assert_eq!(
            ProgramHeader::parse(Class(gabi::ELFCLASS64), &mut reader).unwrap(),
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
