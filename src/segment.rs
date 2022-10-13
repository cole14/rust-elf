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
    pub p_type: ProgType,
    /// Offset into the ELF file where this segment begins
    pub p_offset: u64,
    /// Virtual adress where this segment should be loaded
    pub p_vaddr: u64,
    /// Physical address where this segment should be loaded
    pub p_paddr: u64,
    /// Size of this segment in the file
    pub p_filesz: u64,
    /// Size of this segment in memory
    pub p_memsz: u64,
    /// Flags for this segment
    pub p_flags: ProgFlag,
    /// file and memory alignment
    pub p_align: u64,
}

impl<R> Parse<R> for ProgramHeader
where
    R: ReadExt,
{
    fn parse(class: Class, reader: &mut R) -> Result<Self, ParseError> {
        if class == gabi::ELFCLASS32 {
            return Ok(ProgramHeader {
                p_type: ProgType(reader.read_u32()?),
                p_offset: reader.read_u32()? as u64,
                p_vaddr: reader.read_u32()? as u64,
                p_paddr: reader.read_u32()? as u64,
                p_filesz: reader.read_u32()? as u64,
                p_memsz: reader.read_u32()? as u64,
                p_flags: ProgFlag(reader.read_u32()?),
                p_align: reader.read_u32()? as u64,
            });
        }

        // Note: 64-bit fields are in a different order
        let p_type = reader.read_u32()?;
        let p_flags = reader.read_u32()?;
        let p_offset = reader.read_u64()?;
        let p_vaddr = reader.read_u64()?;
        let p_paddr = reader.read_u64()?;
        let p_filesz = reader.read_u64()?;
        let p_memsz = reader.read_u64()?;
        let p_align = reader.read_u64()?;
        Ok(ProgramHeader {
            p_type: ProgType(p_type),
            p_offset: p_offset,
            p_vaddr: p_vaddr,
            p_paddr: p_paddr,
            p_filesz: p_filesz,
            p_memsz: p_memsz,
            p_flags: ProgFlag(p_flags),
            p_align: p_align,
        })
    }
}

impl core::fmt::Display for ProgramHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Program Header: Type: {} Offset: {:#010x} VirtAddr: {:#010x} PhysAddr: {:#010x} FileSize: {:#06x} MemSize: {:#06x} Flags: {} Align: {:#x}",
            self.p_type, self.p_offset, self.p_vaddr, self.p_paddr, self.p_filesz,
            self.p_memsz, self.p_flags, self.p_align)
    }
}

/// Represents ELF Program Header flags
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct ProgFlag(pub u32);

impl core::fmt::Debug for ProgFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for ProgFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
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

impl core::fmt::Debug for ProgType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl core::fmt::Display for ProgType {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
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
                p_type: ProgType(0x03020100),
                p_offset: 0x07060504,
                p_vaddr: 0xB0A0908,
                p_paddr: 0x0F0E0D0C,
                p_filesz: 0x13121110,
                p_memsz: 0x17161514,
                p_flags: ProgFlag(0x1B1A1918),
                p_align: 0x1F1E1D1C,
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
                p_type: ProgType(0x00010203),
                p_offset: 0x08090A0B0C0D0E0F,
                p_vaddr: 0x1011121314151617,
                p_paddr: 0x18191A1B1C1D1E1F,
                p_filesz: 0x2021222324252627,
                p_memsz: 0x28292A2B2C2D2E2F,
                p_flags: ProgFlag(0x04050607),
                p_align: 0x3031323334353637,
            }
        );
    }
}
