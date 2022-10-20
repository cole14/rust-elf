use core::ops::Range;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug)]
pub enum ParseError {
    /// Returned when the ELF File Header's magic bytes weren't ELF's defined
    /// magic bytes
    BadMagic([u8; 4]),
    /// Returned when the ELF File Header's `e_ident[EI_CLASS]` wasn't one of the
    /// defined `ELFCLASS*` constants
    UnsupportedElfClass(u8),
    /// Returned when the ELF File Header's `e_ident[EI_DATA]` wasn't one of the
    /// defined `ELFDATA*` constants
    UnsupportedElfEndianness(u8),
    /// Returned when the ELF File Header's `e_ident[EI_VERSION]` wasn't
    /// `EV_CURRENT(1)`
    UnsupportedElfVersion(u8),
    /// Returned when parsing an ELF structure resulted in an offset which fell
    /// out of bounds of the requested structure
    BadOffset(u64),
    /// Returned when parsing a string out of a StringTable failed to find the
    /// terminating NUL byte
    StringTableMissingNul(u64),
    /// Returned when parsing a table of ELF structures and the file specified
    /// an entry size for that table that was different than what we had
    /// expected
    BadEntsize((u64, u64)),
    /// Returned when parsing an ELF structure out of an in-memory `&[u8]`
    /// resulted in a request for a section of file bytes outside the range of
    /// the slice. Commonly caused by truncated file contents.
    SliceReadError((usize, usize)),
    /// Returned when parsing a string out of a StringTable that contained
    /// invalid Utf8
    Utf8Error(core::str::Utf8Error),
    /// Returned when parsing an ELF structure and the underlying structure data
    /// was truncated and thus the full structure contents could not be parsed.
    TryFromSliceError(core::array::TryFromSliceError),
    /// Returned when parsing an ELF structure out of an io stream encountered
    /// an io error.
    IOError(std::io::Error),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ParseError::BadMagic(_) => None,
            ParseError::UnsupportedElfClass(_) => None,
            ParseError::UnsupportedElfEndianness(_) => None,
            ParseError::UnsupportedElfVersion(_) => None,
            ParseError::BadOffset(_) => None,
            ParseError::StringTableMissingNul(_) => None,
            ParseError::BadEntsize(_) => None,
            ParseError::SliceReadError(_) => None,
            ParseError::Utf8Error(ref err) => Some(err),
            ParseError::TryFromSliceError(ref err) => Some(err),
            ParseError::IOError(ref err) => Some(err),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            ParseError::BadMagic(ref magic) => {
                write!(f, "Invalid Magic Bytes: {magic:X?}")
            }
            ParseError::UnsupportedElfClass(class) => {
                write!(f, "Unsupported ELF Class: {class}")
            }
            ParseError::UnsupportedElfEndianness(endianness) => {
                write!(f, "Unsupported ELF Endianness: {endianness}")
            }
            ParseError::UnsupportedElfVersion(version) => {
                write!(f, "Unsupported ELF Version: {version}")
            }
            ParseError::BadOffset(offset) => {
                write!(f, "Bad offset: {offset:#X}")
            }
            ParseError::StringTableMissingNul(offset) => {
                write!(
                    f,
                    "Could not find terminating NUL byte starting at offset: {offset:#X}"
                )
            }
            ParseError::BadEntsize((found, expected)) => {
                write!(
                    f,
                    "Invalid entsize. Expected: {expected:#X}, Found: {found:#X}"
                )
            }
            ParseError::SliceReadError((start, end)) => {
                write!(f, "Could not read bytes in range [{start:#X}, {end:#X})")
            }
            ParseError::Utf8Error(ref err) => err.fmt(f),
            ParseError::TryFromSliceError(ref err) => err.fmt(f),
            ParseError::IOError(ref err) => err.fmt(f),
        }
    }
}

impl From<core::str::Utf8Error> for ParseError {
    fn from(err: core::str::Utf8Error) -> Self {
        ParseError::Utf8Error(err)
    }
}

impl From<core::array::TryFromSliceError> for ParseError {
    fn from(err: core::array::TryFromSliceError) -> Self {
        ParseError::TryFromSliceError(err)
    }
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IOError(err)
    }
}

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl core::fmt::Display for Endian {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self {
            Endian::Little => "2's complement, little endian",
            Endian::Big => "2's complement, big endian",
        };
        write!(f, "{}", str)
    }
}

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Class {
    ELF32,
    ELF64,
}

impl core::fmt::Display for Class {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let str = match self {
            Class::ELF32 => "32-bit",
            Class::ELF64 => "64-bit",
        };
        write!(f, "{}", str)
    }
}

/// Trait which exposes an interface for getting a block of bytes from a data source.
/// This is the basic reading method for getting a chunk of in-memory ELF data from which
/// to parse.
pub trait ReadBytesAt {
    fn read_bytes_at(&mut self, range: Range<usize>) -> Result<&[u8], ParseError>;
}

impl ReadBytesAt for &[u8] {
    fn read_bytes_at(&mut self, range: Range<usize>) -> Result<&[u8], ParseError> {
        let start = range.start;
        let end = range.end;
        self.get(range)
            .ok_or(ParseError::SliceReadError((start, end)))
    }
}

pub struct CachedReadBytes<R: Read + Seek> {
    reader: R,
    bufs: HashMap<(u64, u64), Box<[u8]>>,
}

impl<R: Read + Seek> CachedReadBytes<R> {
    pub fn new(reader: R) -> Self {
        CachedReadBytes {
            reader,
            bufs: HashMap::<(u64, u64), Box<[u8]>>::default(),
        }
    }
}

impl<R: Read + Seek> ReadBytesAt for &mut CachedReadBytes<R> {
    fn read_bytes_at(&mut self, range: Range<usize>) -> Result<&[u8], ParseError> {
        if range.len() == 0 {
            return Ok(&[]);
        }

        let start = range.start as u64;
        let size = range.len() as u64;

        Ok(match self.bufs.entry((start, size)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.reader.seek(SeekFrom::Start(start))?;
                let mut bytes = vec![0; size as usize].into_boxed_slice();
                self.reader.read_exact(&mut bytes)?;
                entry.insert(bytes)
            }
        })
    }
}

/// Trait for endian-aware parsing of integer types.
pub trait ParseAtExt {
    fn parse_u8_at(&self, offset: &mut usize) -> Result<u8, ParseError>;
    fn parse_u16_at(&self, endian: Endian, offset: &mut usize) -> Result<u16, ParseError>;
    fn parse_u32_at(&self, endian: Endian, offset: &mut usize) -> Result<u32, ParseError>;
    fn parse_u64_at(&self, endian: Endian, offset: &mut usize) -> Result<u64, ParseError>;
}

/// Extend the byte slice type with endian-aware parsing. These are the basic parsing methods
/// for our parser-combinator approach to parsing ELF structures from in-memory byte buffers.
impl ParseAtExt for &[u8] {
    fn parse_u8_at(&self, offset: &mut usize) -> Result<u8, ParseError> {
        let data = self
            .get(*offset)
            .ok_or(ParseError::BadOffset(*offset as u64))?;
        *offset += 1;
        Ok(*data)
    }

    fn parse_u16_at(&self, endian: Endian, offset: &mut usize) -> Result<u16, ParseError> {
        let range = *offset..*offset + 2;
        let data: [u8; 2] = self
            .get(range)
            .ok_or(ParseError::BadOffset(*offset as u64))?
            .try_into()?;
        *offset += 2;
        match endian {
            Endian::Little => Ok(u16::from_le_bytes(data)),
            Endian::Big => Ok(u16::from_be_bytes(data)),
        }
    }

    fn parse_u32_at(&self, endian: Endian, offset: &mut usize) -> Result<u32, ParseError> {
        let range = *offset..*offset + 4;
        let data: [u8; 4] = self
            .get(range)
            .ok_or(ParseError::BadOffset(*offset as u64))?
            .try_into()?;
        *offset += 4;
        match endian {
            Endian::Little => Ok(u32::from_le_bytes(data)),
            Endian::Big => Ok(u32::from_be_bytes(data)),
        }
    }

    fn parse_u64_at(&self, endian: Endian, offset: &mut usize) -> Result<u64, ParseError> {
        let range = *offset..*offset + 8;
        let data: [u8; 8] = self
            .get(range)
            .ok_or(ParseError::BadOffset(*offset as u64))?
            .try_into()?;
        *offset += 8;
        match endian {
            Endian::Little => Ok(u64::from_le_bytes(data)),
            Endian::Big => Ok(u64::from_be_bytes(data)),
        }
    }
}

#[cfg(test)]
mod read_bytes_tests {
    use super::ReadBytesAt;
    use super::*;
    use std::io::Cursor;

    #[test]
    fn byte_slice_read_bytes_at_works() {
        let data = [1u8, 2u8, 3u8, 4u8];
        let slice = &mut data.as_slice();
        let bytes = slice
            .read_bytes_at(1..3)
            .expect("Failed to get expected bytes");
        assert_eq!(bytes, [2u8, 3u8]);
    }

    #[test]
    fn byte_slice_read_bytes_at_empty_buffer() {
        let data = [];
        assert!(matches!(
            data.as_ref().read_bytes_at(1..3),
            Err(ParseError::SliceReadError(_))
        ));
    }

    #[test]
    fn byte_slice_read_bytes_at_past_end_of_buffer() {
        let data = [1u8, 2u8];
        assert!(matches!(
            data.as_ref().read_bytes_at(1..3),
            Err(ParseError::SliceReadError(_))
        ));
    }

    #[test]
    fn cached_read_bytes_at_works() {
        let data = [1u8, 2u8, 3u8, 4u8];
        let cur = Cursor::new(data);
        let mut cached = &mut CachedReadBytes::new(cur);

        let bytes1 = cached
            .read_bytes_at(0..2)
            .expect("Failed to get expected bytes");
        assert_eq!(bytes1, [1u8, 2u8]);
        let bytes2 = cached
            .read_bytes_at(2..4)
            .expect("Failed to get expected bytes");
        assert_eq!(bytes2, [3u8, 4u8]);
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn parse_u16_lsb() {
        let data = [0x10u8, 0x20u8];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u16_at(Endian::Little, &mut offset)
            .expect("Failed to parse u16");
        assert_eq!(result, 0x2010u16);
        assert_eq!(offset, 2);
    }

    #[test]
    fn parse_u16_msb() {
        let data = [0x10u8, 0x20u8];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u16_at(Endian::Big, &mut offset)
            .expect("Failed to parse u16");
        assert_eq!(result, 0x1020u16);
        assert_eq!(offset, 2);
    }

    #[test]
    fn parse_u16_too_short() {
        let data = [0x10u8];
        let mut offset = 0;
        let result = data.as_ref().parse_u16_at(Endian::Big, &mut offset);
        assert!(
            matches!(result, Err(ParseError::BadOffset(0))),
            "Unexpected Error type found: {result:?}"
        );
        assert_eq!(offset, 0);
    }

    #[test]
    fn parse_u32_lsb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u32_at(Endian::Little, &mut offset)
            .expect("Failed to parse u32");
        assert_eq!(result, 0x40302010u32);
        assert_eq!(offset, 4);
    }

    #[test]
    fn parse_u32_msb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u32_at(Endian::Big, &mut offset)
            .expect("Failed to parse u32");
        assert_eq!(result, 0x10203040u32);
        assert_eq!(offset, 4);
    }

    #[test]
    fn parse_u32_too_short() {
        let data = [0x10u8, 0x20u8];
        let mut offset = 0;
        let result = data.as_ref().parse_u32_at(Endian::Little, &mut offset);
        assert!(
            matches!(result, Err(ParseError::BadOffset(0))),
            "Unexpected Error type found: {result:?}"
        );
        assert_eq!(offset, 0);
    }

    #[test]
    fn parse_u64_lsb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u64_at(Endian::Little, &mut offset)
            .expect("Failed to parse u64");
        assert_eq!(result, 0x8070605040302010u64);
        assert_eq!(offset, 8);
    }

    #[test]
    fn parse_u64_msb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let mut offset = 0;
        let result = data
            .as_ref()
            .parse_u64_at(Endian::Big, &mut offset)
            .expect("Failed to parse u32");
        assert_eq!(result, 0x1020304050607080u64);
        assert_eq!(offset, 8);
    }

    #[test]
    fn parse_u64_too_short() {
        let data = [0x10u8, 0x20u8];
        let mut offset = 0;
        let result = data.as_ref().parse_u64_at(Endian::Little, &mut offset);
        assert!(
            matches!(result, Err(ParseError::BadOffset(0))),
            "Unexpected Error type found: {result:?}"
        );
        assert_eq!(offset, 0);
    }
}
