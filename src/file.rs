//! Parsing the ELF File Header
use crate::abi;
use crate::endian::EndianParse;
use crate::parse::ParseError;

/// Represents the ELF file word size (32-bit vs 64-bit)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Class {
    ELF32,
    ELF64,
}

/// C-style 32-bit ELF File Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf32_Ehdr {
    pub e_ident: [u8; abi::EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// C-style 64-bit ELF File Header definition
///
/// These C-style definitions are for users who want to implement their own ELF manipulation logic.
#[derive(Debug)]
#[repr(C)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; abi::EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Encapsulates the contents of the ELF File Header
///
/// The ELF File Header starts off every ELF file and both identifies the
/// file contents and informs how to interpret said contents. This includes
/// the width of certain fields (32-bit vs 64-bit), the data endianness, the
/// file type, and more.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileHeader<E: EndianParse> {
    /// 32-bit vs 64-bit
    pub class: Class,
    // file byte order
    pub endianness: E,
    /// elf version
    pub version: u32,
    /// OS ABI
    pub osabi: u8,
    /// Version of the OS ABI
    pub abiversion: u8,
    /// ELF file type
    pub e_type: u16,
    /// Target machine architecture
    pub e_machine: u16,
    /// Virtual address of program entry point
    /// This member gives the virtual address to which the system first transfers control,
    /// thus starting the process. If the file has no associated entry point, this member holds zero.
    ///
    /// Note: Type is Elf32_Addr or Elf64_Addr which are either 4 or 8 bytes. We aren't trying to zero-copy
    /// parse the FileHeader since there's only one per file and its only ~45 bytes anyway, so we use
    /// u64 for the three Elf*_Addr and Elf*_Off fields here.
    pub e_entry: u64,
    /// This member holds the program header table's file offset in bytes. If the file has no program header
    /// table, this member holds zero.
    pub e_phoff: u64,
    /// This member holds the section header table's file offset in bytes. If the file has no section header
    /// table, this member holds zero.
    pub e_shoff: u64,
    /// This member holds processor-specific flags associated with the file. Flag names take the form EF_machine_flag.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table. Thus the product of e_phentsize and e_phnum
    /// gives the table's size in bytes. If a file has no program header table, e_phnum holds the value zero.
    pub e_phnum: u16,
    /// This member holds a section header's size in bytes. A section header is one entry in the section header table;
    /// all entries are the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table. Thus the product of e_shentsize and e_shnum
    /// gives the section header table's size in bytes. If a file has no section header table, e_shnum holds the value zero.
    ///
    /// If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), this member has the value zero and
    /// the actual number of section header table entries is contained in the sh_size field of the section header at index 0.
    /// (Otherwise, the sh_size member of the initial entry contains 0.)
    pub e_shnum: u16,
    /// This member holds the section header table index of the entry associated with the section name string table. If the
    /// file has no section name string table, this member holds the value SHN_UNDEF.
    ///
    /// If the section name string table section index is greater than or equal to SHN_LORESERVE (0xff00), this member has
    /// the value SHN_XINDEX (0xffff) and the actual index of the section name string table section is contained in the
    /// sh_link field of the section header at index 0. (Otherwise, the sh_link member of the initial entry contains 0.)
    pub e_shstrndx: u16,
}

pub const ELF32_EHDR_TAILSIZE: usize = 36;
pub const ELF64_EHDR_TAILSIZE: usize = 48;

fn verify_ident(buf: &[u8]) -> Result<(), ParseError> {
    // Verify the magic number
    let magic = buf.split_at(abi::EI_CLASS).0;
    if magic != abi::ELFMAGIC {
        return Err(ParseError::BadMagic([
            magic[0], magic[1], magic[2], magic[3],
        ]));
    }

    // Verify ELF Version
    let version = buf[abi::EI_VERSION];
    if version != abi::EV_CURRENT {
        return Err(ParseError::UnsupportedVersion((
            version as u64,
            abi::EV_CURRENT as u64,
        )));
    }

    Ok(())
}

pub fn parse_ident<E: EndianParse>(data: &[u8]) -> Result<(E, Class, u8, u8), ParseError> {
    verify_ident(data)?;

    let e_class = data[abi::EI_CLASS];
    let class = match e_class {
        abi::ELFCLASS32 => Class::ELF32,
        abi::ELFCLASS64 => Class::ELF64,
        _ => {
            return Err(ParseError::UnsupportedElfClass(e_class));
        }
    };

    // Verify endianness is something we know how to parse
    let file_endian = E::from_ei_data(data[abi::EI_DATA])?;

    Ok((
        file_endian,
        class,
        data[abi::EI_OSABI],
        data[abi::EI_ABIVERSION],
    ))
}

impl<E: EndianParse> FileHeader<E> {
    pub fn parse_tail(ident: (E, Class, u8, u8), data: &[u8]) -> Result<FileHeader<E>, ParseError> {
        let (file_endian, class, osabi, abiversion) = ident;

        let mut offset = 0;
        let e_type = file_endian.parse_u16_at(&mut offset, data)?;
        let e_machine = file_endian.parse_u16_at(&mut offset, data)?;
        let version = file_endian.parse_u32_at(&mut offset, data)?;

        let e_entry: u64;
        let e_phoff: u64;
        let e_shoff: u64;

        if class == Class::ELF32 {
            e_entry = file_endian.parse_u32_at(&mut offset, data)? as u64;
            e_phoff = file_endian.parse_u32_at(&mut offset, data)? as u64;
            e_shoff = file_endian.parse_u32_at(&mut offset, data)? as u64;
        } else {
            e_entry = file_endian.parse_u64_at(&mut offset, data)?;
            e_phoff = file_endian.parse_u64_at(&mut offset, data)?;
            e_shoff = file_endian.parse_u64_at(&mut offset, data)?;
        }

        let e_flags = file_endian.parse_u32_at(&mut offset, data)?;
        let e_ehsize = file_endian.parse_u16_at(&mut offset, data)?;
        let e_phentsize = file_endian.parse_u16_at(&mut offset, data)?;
        let e_phnum = file_endian.parse_u16_at(&mut offset, data)?;
        let e_shentsize = file_endian.parse_u16_at(&mut offset, data)?;
        let e_shnum = file_endian.parse_u16_at(&mut offset, data)?;
        let e_shstrndx = file_endian.parse_u16_at(&mut offset, data)?;

        Ok(FileHeader {
            class,
            endianness: file_endian,
            version,
            e_type,
            e_machine,
            osabi,
            abiversion,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;
    use crate::endian::AnyEndian;

    #[test]
    fn test_verify_ident_valid() {
        let data: [u8; abi::EI_NIDENT] = [
            abi::ELFMAG0,
            abi::ELFMAG1,
            abi::ELFMAG2,
            abi::ELFMAG3,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            abi::EV_CURRENT,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        verify_ident(data.as_ref()).expect("Expected Ok result");
    }

    #[test]
    fn test_verify_ident_invalid_mag0() {
        let data: [u8; abi::EI_NIDENT] = [
            0xFF,
            abi::ELFMAG1,
            abi::ELFMAG2,
            abi::ELFMAG3,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            abi::EV_CURRENT,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = verify_ident(data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag1() {
        let data: [u8; abi::EI_NIDENT] = [
            abi::ELFMAG0,
            0xFF,
            abi::ELFMAG2,
            abi::ELFMAG3,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            abi::EV_CURRENT,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = verify_ident(data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag2() {
        let data: [u8; abi::EI_NIDENT] = [
            abi::ELFMAG0,
            abi::ELFMAG1,
            0xFF,
            abi::ELFMAG3,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            abi::EV_CURRENT,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = verify_ident(data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_verify_ident_invalid_mag3() {
        let data: [u8; abi::EI_NIDENT] = [
            abi::ELFMAG0,
            abi::ELFMAG1,
            abi::ELFMAG2,
            0xFF,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            abi::EV_CURRENT,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = verify_ident(data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::BadMagic(_)),
            "Unexpected Error type found: {result}"
        );
    }

    #[allow(deprecated)]
    #[test]
    fn test_verify_ident_invalid_version() {
        let data: [u8; abi::EI_NIDENT] = [
            abi::ELFMAG0,
            abi::ELFMAG1,
            abi::ELFMAG2,
            abi::ELFMAG3,
            abi::ELFCLASS32,
            abi::ELFDATA2LSB,
            42,
            abi::ELFOSABI_LINUX,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let result = verify_ident(data.as_ref()).expect_err("Expected an error");
        assert!(
            matches!(result, ParseError::UnsupportedVersion((42, 1))),
            "Unexpected Error type found: {result}"
        );
    }

    #[test]
    fn test_parse_ehdr32_works() {
        let ident = (AnyEndian::Little, Class::ELF32, abi::ELFOSABI_LINUX, 7u8);
        let mut tail = [0u8; ELF64_EHDR_TAILSIZE];
        for (n, elem) in tail.iter_mut().enumerate().take(ELF64_EHDR_TAILSIZE) {
            *elem = n as u8;
        }

        assert_eq!(
            FileHeader::parse_tail(ident, &tail).unwrap(),
            FileHeader {
                class: Class::ELF32,
                endianness: AnyEndian::Little,
                version: 0x7060504,
                osabi: abi::ELFOSABI_LINUX,
                abiversion: 7,
                e_type: 0x100,
                e_machine: 0x302,
                e_entry: 0x0B0A0908,
                e_phoff: 0x0F0E0D0C,
                e_shoff: 0x13121110,
                e_flags: 0x17161514,
                e_ehsize: 0x1918,
                e_phentsize: 0x1B1A,
                e_phnum: 0x1D1C,
                e_shentsize: 0x1F1E,
                e_shnum: 0x2120,
                e_shstrndx: 0x2322,
            }
        );
    }

    #[test]
    fn test_parse_ehdr32_fuzz_too_short() {
        let ident = (AnyEndian::Little, Class::ELF32, abi::ELFOSABI_LINUX, 7u8);
        let tail = [0u8; ELF32_EHDR_TAILSIZE];

        for n in 0..ELF32_EHDR_TAILSIZE {
            let buf = tail.split_at(n).0;
            let result = FileHeader::parse_tail(ident, buf).expect_err("Expected an error");
            assert!(
                matches!(result, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {result:?}"
            );
        }
    }

    #[test]
    fn test_parse_ehdr64_works() {
        let ident = (AnyEndian::Big, Class::ELF64, abi::ELFOSABI_LINUX, 7u8);
        let mut tail = [0u8; ELF64_EHDR_TAILSIZE];
        for (n, elem) in tail.iter_mut().enumerate().take(ELF64_EHDR_TAILSIZE) {
            *elem = n as u8;
        }

        assert_eq!(
            FileHeader::parse_tail(ident, &tail).unwrap(),
            FileHeader {
                class: Class::ELF64,
                endianness: AnyEndian::Big,
                version: 0x04050607,
                osabi: abi::ELFOSABI_LINUX,
                abiversion: 7,
                e_type: 0x0001,
                e_machine: 0x0203,
                e_entry: 0x08090A0B0C0D0E0F,
                e_phoff: 0x1011121314151617,
                e_shoff: 0x18191A1B1C1D1E1F,
                e_flags: 0x20212223,
                e_ehsize: 0x2425,
                e_phentsize: 0x2627,
                e_phnum: 0x2829,
                e_shentsize: 0x2A2B,
                e_shnum: 0x2C2D,
                e_shstrndx: 0x2E2F,
            }
        );
    }

    #[test]
    fn test_parse_ehdr64_fuzz_too_short() {
        let ident = (AnyEndian::Little, Class::ELF64, abi::ELFOSABI_LINUX, 7u8);
        let tail = [0u8; ELF64_EHDR_TAILSIZE];

        for n in 0..ELF64_EHDR_TAILSIZE {
            let buf = tail.split_at(n).0;
            let result = FileHeader::parse_tail(ident, buf).expect_err("Expected an error");
            assert!(
                matches!(result, ParseError::SliceReadError(_)),
                "Unexpected Error type found: {result:?}"
            );
        }
    }
}
