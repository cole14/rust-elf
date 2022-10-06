use file::Endian;
use gabi;
use std::io;
use ParseError;

#[inline]
pub fn read_u16<T: io::Read>(endian: Endian, io: &mut T) -> Result<u16, ParseError> {
    let mut buf = [0u8; 2];
    io.read_exact(&mut buf)?;
    match endian.0 {
        gabi::ELFDATA2LSB => Ok(u16::from_le_bytes(buf)),
        gabi::ELFDATA2MSB => Ok(u16::from_be_bytes(buf)),
        gabi::ELFDATANONE => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
        _ => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
    }
}

#[inline]
pub fn read_u32<T: io::Read>(endian: Endian, io: &mut T) -> Result<u32, ParseError> {
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf)?;
    match endian.0 {
        gabi::ELFDATA2LSB => Ok(u32::from_le_bytes(buf)),
        gabi::ELFDATA2MSB => Ok(u32::from_be_bytes(buf)),
        gabi::ELFDATANONE => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
        _ => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
    }
}

#[inline]
pub fn read_u64<T: io::Read>(endian: Endian, io: &mut T) -> Result<u64, ParseError> {
    let mut buf = [0u8; 8];
    io.read_exact(&mut buf)?;
    match endian.0 {
        gabi::ELFDATA2LSB => Ok(u64::from_le_bytes(buf)),
        gabi::ELFDATA2MSB => Ok(u64::from_be_bytes(buf)),
        gabi::ELFDATANONE => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
        _ => {
            return Err(ParseError(format!("Unsupported Endianness: {endian}")));
        }
    }
}

use std;
pub fn get_string(data: &[u8], start: usize) -> Result<String, std::string::FromUtf8Error> {
    let mut end: usize = 0;
    for i in start..data.len() {
        if data[i] == 0u8 {
            end = i;
            break;
        }
    }
    let mut rtn = String::with_capacity(end - start);
    for i in start..end {
        rtn.push(data[i] as char);
    }
    Ok(rtn)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Endian = Endian(gabi::ELFDATANONE);
    const LITTLE: Endian = Endian(gabi::ELFDATA2LSB);
    const BIG: Endian = Endian(gabi::ELFDATA2MSB);
    const INVALID: Endian = Endian(42);

    #[test]
    fn test_read_u16_lsb() {
        let data = [0x10u8, 0x20u8];
        let result = read_u16(LITTLE, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x2010u16);
    }

    #[test]
    fn test_read_u16_msb() {
        let data = [0x10u8, 0x20u8];
        let result = read_u16(BIG, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x1020u16);
    }

    #[test]
    fn test_read_u16_none() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u16, ParseError> = read_u16(NONE, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u16_invalid_endianness() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u16, ParseError> = read_u16(INVALID, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u16_too_short() {
        let data = [0x10u8];
        let result: Result<u16, ParseError> = read_u16(LITTLE, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_lsb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result = read_u32(LITTLE, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x40302010u32);
    }

    #[test]
    fn test_read_u32_msb() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result = read_u32(BIG, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x10203040u32);
    }

    #[test]
    fn test_read_u32_none() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result = read_u32(NONE, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_invalid_endianness() {
        let data = [0x10u8, 0x20u8, 0x30u8, 0x40u8];
        let result: Result<u32, ParseError> = read_u32(INVALID, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_too_short() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u32, ParseError> = read_u32(LITTLE, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_lsb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result = read_u64(LITTLE, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x8070605040302010u64);
    }

    #[test]
    fn test_read_u64_msb() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result = read_u64(BIG, &mut data.as_ref()).unwrap();
        assert_eq!(result, 0x1020304050607080u64);
    }

    #[test]
    fn test_read_u64_none() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result: Result<u64, ParseError> = read_u64(NONE, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_invalid_endianness() {
        let data = [
            0x10u8, 0x20u8, 0x30u8, 0x40u8, 0x50u8, 0x60u8, 0x70u8, 0x80u8,
        ];
        let result: Result<u64, ParseError> = read_u64(INVALID, &mut data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u64_too_short() {
        let data = [0x10u8, 0x20u8];
        let result: Result<u64, ParseError> = read_u64(LITTLE, &mut data.as_ref());
        assert!(result.is_err());
    }
}
