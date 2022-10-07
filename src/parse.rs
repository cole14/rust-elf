use crate::file::Class;
use crate::ParseError;
use std::io::{Read, Seek};

/// Represents the ELF file data format (little-endian vs big-endian)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let str = match self {
            Endian::Little => "2's complement, little endian",
            Endian::Big => "2's complement, big endian",
        };
        write!(f, "{}", str)
    }
}

pub trait ReadExt {
    fn read_u16(&mut self) -> Result<u16, ParseError>;
    fn read_u32(&mut self) -> Result<u32, ParseError>;
    fn read_u64(&mut self) -> Result<u64, ParseError>;
}

pub struct Reader<'data, D: Read + Seek> {
    delegate: &'data mut D,
    endian: Endian,
}

impl<'data, D: Read + Seek> Reader<'data, D> {
    pub fn new(delegate: &'data mut D, endian: Endian) -> Reader<'data, D> {
        Reader{delegate: delegate, endian: endian}
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
}

#[inline]
pub fn read_u16<T: std::io::Read>(endian: Endian, io: &mut T) -> Result<u16, ParseError> {
    let mut buf = [0u8; 2];
    io.read_exact(&mut buf)?;
    match endian {
        Endian::Little => Ok(u16::from_le_bytes(buf)),
        Endian::Big => Ok(u16::from_be_bytes(buf)),
    }
}

#[inline]
pub fn read_u32<T: std::io::Read>(endian: Endian, io: &mut T) -> Result<u32, ParseError> {
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf)?;
    match endian {
        Endian::Little => Ok(u32::from_le_bytes(buf)),
        Endian::Big => Ok(u32::from_be_bytes(buf)),
    }
}

#[inline]
pub fn read_u64<T: std::io::Read>(endian: Endian, io: &mut T) -> Result<u64, ParseError> {
    let mut buf = [0u8; 8];
    io.read_exact(&mut buf)?;
    match endian {
        Endian::Little => Ok(u64::from_le_bytes(buf)),
        Endian::Big => Ok(u64::from_be_bytes(buf)),
    }
}

pub trait Parse<R>: Copy {
    fn parse(class: Class, reader: &mut R) -> Result<Self, crate::ParseError>
    where
        R: ReadExt;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_lsb() {
        let data = [0x10u8, 0x20u8];
        let result = read_u16(Endian::Little, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x2010u16);
    }

    #[test]
    fn test_read_u16_msb() {
        let data = [0x10u8, 0x20u8];
        let result = read_u16(Endian::Big, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x1020u16);
    }

    #[test]
    fn test_read_u16_too_short() {
        let data = [0x10u8];
        let result: Result<u16, ParseError> = read_u16(Endian::Little, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_lsb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result = read_u32(Endian::Little, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x40302010u32);
    }

    #[test]
    fn test_read_u32_msb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result = read_u32(Endian::Big, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x10203040u32);
    }

    #[test]
    fn test_read_u32_too_short() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u32, ParseError> = read_u32(Endian::Little, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_lsb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result = read_u64(Endian::Little, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x8070605040302010u64);
    }

    #[test]
    fn test_read_u64_msb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result = read_u64(Endian::Big, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x1020304050607080u64);
    }

    #[test]
    fn test_read_u64_too_short() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u64, ParseError> = read_u64(Endian::Little, &mut data.as_ref());
        assert!(result.is_err());
    }
}