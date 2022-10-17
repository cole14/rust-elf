use core::array::TryFromSliceError;
use core::ops::Range;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

impl core::convert::From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError(e.to_string())
    }
}

impl core::convert::From<core::str::Utf8Error> for ParseError {
    fn from(e: core::str::Utf8Error) -> Self {
        ParseError(e.to_string())
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
    fn read_bytes_at<'data>(&'data self, range: Range<usize>) -> Result<&'data [u8], ParseError>;
}

impl ReadBytesAt for &[u8] {
    fn read_bytes_at<'data>(&'data self, range: Range<usize>) -> Result<&'data [u8], ParseError> {
        let start = range.start;
        let end = range.end;
        self.get(range).ok_or(ParseError(format!(
            "Could not read bytes in range [{start}, {end})"
        )))
    }
}

/// Trait for endian-aware parsing of integer types.
pub trait ParseAtExt {
    fn parse_u8_at(&self, offset: &mut usize) -> Result<u8, ParseError>;
    fn parse_u16_at(&self, endian: Endian, offset: &mut usize) -> Result<u16, ParseError>;
    fn parse_u32_at(&self, endian: Endian, offset: &mut usize) -> Result<u32, ParseError>;
    fn parse_u64_at(&self, endian: Endian, offset: &mut usize) -> Result<u64, ParseError>;
}

#[inline]
fn parse_error(offset: &usize) -> ParseError {
    ParseError(format!("Could not parse at {offset}: buffer too small"))
}

/// Extend the byte slice type with endian-aware parsing. These are the basic parsing methods
/// for our parser-combinator approach to parsing ELF structures from in-memory byte buffers.
impl ParseAtExt for &[u8] {
    fn parse_u8_at(&self, offset: &mut usize) -> Result<u8, ParseError> {
        let data = self.get(*offset).ok_or(parse_error(offset))?;
        *offset += 1;
        Ok(*data)
    }

    fn parse_u16_at(&self, endian: Endian, offset: &mut usize) -> Result<u16, ParseError> {
        let range = *offset..*offset + 2;
        let data: [u8; 2] = self
            .get(range)
            .ok_or(parse_error(offset))?
            .try_into()
            .map_err(|e: TryFromSliceError| ParseError(e.to_string()))?;
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
            .ok_or(parse_error(offset))?
            .try_into()
            .map_err(|e: TryFromSliceError| ParseError(e.to_string()))?;
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
            .ok_or(parse_error(offset))?
            .try_into()
            .map_err(|e: TryFromSliceError| ParseError(e.to_string()))?;
        *offset += 8;
        match endian {
            Endian::Little => Ok(u64::from_le_bytes(data)),
            Endian::Big => Ok(u64::from_be_bytes(data)),
        }
    }
}

pub trait ReadExt {
    fn read_u16(&mut self) -> Result<u16, ParseError>;
    fn read_u32(&mut self) -> Result<u32, ParseError>;
    fn read_u64(&mut self) -> Result<u64, ParseError>;
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error>;
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), std::io::Error>;
}

pub struct Reader<'data, D: Read + Seek> {
    delegate: &'data mut D,
    endian: Endian,
}

impl<'data, D: Read + Seek> Reader<'data, D> {
    pub fn new(delegate: &'data mut D, endian: Endian) -> Reader<'data, D> {
        Reader {
            delegate: delegate,
            endian: endian,
        }
    }
}

impl<'data, D: Read + Seek> ReadExt for Reader<'data, D> {
    #[inline]
    fn read_u16(&mut self) -> Result<u16, ParseError> {
        let mut buf = [0u8; 2];
        self.delegate.read_exact(&mut buf)?;
        match self.endian {
            Endian::Little => Ok(u16::from_le_bytes(buf)),
            Endian::Big => Ok(u16::from_be_bytes(buf)),
        }
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let mut buf = [0u8; 4];
        self.delegate.read_exact(&mut buf)?;
        match self.endian {
            Endian::Little => Ok(u32::from_le_bytes(buf)),
            Endian::Big => Ok(u32::from_be_bytes(buf)),
        }
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64, ParseError> {
        let mut buf = [0u8; 8];
        self.delegate.read_exact(&mut buf)?;
        match self.endian {
            Endian::Little => Ok(u64::from_le_bytes(buf)),
            Endian::Big => Ok(u64::from_be_bytes(buf)),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), std::io::Error> {
        self.delegate.read_exact(buf)
    }

    fn seek(&mut self, pos: SeekFrom) -> Result<u64, std::io::Error> {
        self.delegate.seek(pos)
    }
}

pub trait Parse<R>: Sized {
    fn parse(class: Class, reader: &mut R) -> Result<Self, ParseError>
    where
        R: ReadExt;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_lsb() {
        let data = [0x10u8, 0x20u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u16().unwrap();
        assert_eq!(result, 0x2010u16);
    }

    #[test]
    fn test_read_u16_msb() {
        let data = [0x10u8, 0x20u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Big,
        };
        let result = reader.read_u16().unwrap();
        assert_eq!(result, 0x1020u16);
    }

    #[test]
    fn test_read_u16_too_short() {
        let data = [0x10u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u16();
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_lsb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u32().unwrap();
        assert_eq!(result, 0x40302010u32);
    }

    #[test]
    fn test_read_u32_msb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Big,
        };
        let result = reader.read_u32().unwrap();
        assert_eq!(result, 0x10203040u32);
    }

    #[test]
    fn test_read_u32_too_short() {
        let data = [0x10u8, 0x20u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u32();
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_lsb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u64().unwrap();
        assert_eq!(result, 0x8070605040302010u64);
    }

    #[test]
    fn test_read_u64_msb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Big,
        };
        let result = reader.read_u64().unwrap();
        assert_eq!(result, 0x1020304050607080u64);
    }

    #[test]
    fn test_read_u64_too_short() {
        let data = [0x10u8, 0x20u8];
        let mut cur = std::io::Cursor::new(data.as_ref());
        let mut reader = Reader {
            delegate: &mut cur,
            endian: Endian::Little,
        };
        let result = reader.read_u64();
        assert!(result.is_err());
    }
}
