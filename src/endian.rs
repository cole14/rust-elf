use crate::gabi;
use crate::parse::ParseError;

/// A safe endian-aware integer parsing trait.
///
/// See implementors below for details.
pub trait EndianParse: Clone + Copy + PartialEq + Eq {
    fn parse_u8_at(self, offset: &mut usize, data: &[u8]) -> Result<u8, ParseError>;
    fn parse_u16_at(self, offset: &mut usize, data: &[u8]) -> Result<u16, ParseError>;
    fn parse_u32_at(self, offset: &mut usize, data: &[u8]) -> Result<u32, ParseError>;
    fn parse_u64_at(self, offset: &mut usize, data: &[u8]) -> Result<u64, ParseError>;
    fn parse_i32_at(self, offset: &mut usize, data: &[u8]) -> Result<i32, ParseError>;
    fn parse_i64_at(self, offset: &mut usize, data: &[u8]) -> Result<i64, ParseError>;
}

/// An endian parsing type that can choose at runtime which byte order to parse as
/// This is useful for scenarios where a single compiled binary wants to dynamically
/// interpret ELF files of any byte order.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum AnyEndian {
    Little,
    Big,
}

impl AnyEndian {
    #[allow(dead_code)]
    pub fn from_ei_data(ei_data: u8) -> Result<AnyEndian, ParseError> {
        match ei_data {
            gabi::ELFDATA2LSB => Ok(AnyEndian::Little),
            gabi::ELFDATA2MSB => Ok(AnyEndian::Big),
            _ => Err(ParseError::UnsupportedElfEndianness(ei_data)),
        }
    }
}

/// A zero-sized type that always parses integers as if they're in little-endian order.
/// This is useful for scenarios where a combiled binary knows it only wants to interpret
/// little-endian ELF files and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LittleEndian;

/// A zero-sized type that always parses integers as if they're in big-endian order.
/// This is useful for scenarios where a combiled binary knows it only wants to interpret
/// big-endian ELF files and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BigEndian;

// This macro writes out safe code to get a subslice from the the byte slice $data
// at the given $off as a [u8; size_of<$typ>], then calls the corresponding safe
// endian-aware conversion $method on it.
//
// This uses safe integer math and returns a ParseError on overflow or if $data did
// not contain enough bytes at $off to perform the conversion.
macro_rules! safe_from {
    ( $typ:ty, $method:ident, $off:ident, $data:ident) => {{
        const SIZE: usize = core::mem::size_of::<$typ>();

        let end = (*$off)
            .checked_add(SIZE)
            .ok_or(ParseError::IntegerOverflow)?;

        let buf: [u8; SIZE] = $data
            .get(*$off..end)
            .ok_or(ParseError::BadOffset(*$off as u64))?
            .try_into()?;

        *$off = end;
        Ok(<$typ>::$method(buf))
    }};
}

impl EndianParse for LittleEndian {
    fn parse_u8_at(self, offset: &mut usize, data: &[u8]) -> Result<u8, ParseError> {
        safe_from!(u8, from_le_bytes, offset, data)
    }

    fn parse_u16_at(self, offset: &mut usize, data: &[u8]) -> Result<u16, ParseError> {
        safe_from!(u16, from_le_bytes, offset, data)
    }

    fn parse_u32_at(self, offset: &mut usize, data: &[u8]) -> Result<u32, ParseError> {
        safe_from!(u32, from_le_bytes, offset, data)
    }

    fn parse_u64_at(self, offset: &mut usize, data: &[u8]) -> Result<u64, ParseError> {
        safe_from!(u64, from_le_bytes, offset, data)
    }

    fn parse_i32_at(self, offset: &mut usize, data: &[u8]) -> Result<i32, ParseError> {
        safe_from!(i32, from_le_bytes, offset, data)
    }

    fn parse_i64_at(self, offset: &mut usize, data: &[u8]) -> Result<i64, ParseError> {
        safe_from!(i64, from_le_bytes, offset, data)
    }
}

impl EndianParse for BigEndian {
    fn parse_u8_at(self, offset: &mut usize, data: &[u8]) -> Result<u8, ParseError> {
        safe_from!(u8, from_be_bytes, offset, data)
    }

    fn parse_u16_at(self, offset: &mut usize, data: &[u8]) -> Result<u16, ParseError> {
        safe_from!(u16, from_be_bytes, offset, data)
    }

    fn parse_u32_at(self, offset: &mut usize, data: &[u8]) -> Result<u32, ParseError> {
        safe_from!(u32, from_be_bytes, offset, data)
    }

    fn parse_u64_at(self, offset: &mut usize, data: &[u8]) -> Result<u64, ParseError> {
        safe_from!(u64, from_be_bytes, offset, data)
    }

    fn parse_i32_at(self, offset: &mut usize, data: &[u8]) -> Result<i32, ParseError> {
        safe_from!(i32, from_be_bytes, offset, data)
    }

    fn parse_i64_at(self, offset: &mut usize, data: &[u8]) -> Result<i64, ParseError> {
        safe_from!(i64, from_be_bytes, offset, data)
    }
}

impl EndianParse for AnyEndian {
    fn parse_u8_at(self, offset: &mut usize, data: &[u8]) -> Result<u8, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_u8_at(offset, data),
            Self::Big => BigEndian.parse_u8_at(offset, data),
        }
    }

    fn parse_u16_at(self, offset: &mut usize, data: &[u8]) -> Result<u16, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_u16_at(offset, data),
            Self::Big => BigEndian.parse_u16_at(offset, data),
        }
    }

    fn parse_u32_at(self, offset: &mut usize, data: &[u8]) -> Result<u32, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_u32_at(offset, data),
            Self::Big => BigEndian.parse_u32_at(offset, data),
        }
    }

    fn parse_u64_at(self, offset: &mut usize, data: &[u8]) -> Result<u64, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_u64_at(offset, data),
            Self::Big => BigEndian.parse_u64_at(offset, data),
        }
    }

    fn parse_i32_at(self, offset: &mut usize, data: &[u8]) -> Result<i32, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_i32_at(offset, data),
            Self::Big => BigEndian.parse_i32_at(offset, data),
        }
    }

    fn parse_i64_at(self, offset: &mut usize, data: &[u8]) -> Result<i64, ParseError> {
        match self {
            Self::Little => LittleEndian.parse_i64_at(offset, data),
            Self::Big => BigEndian.parse_i64_at(offset, data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! parse_test {
        ( $endian:expr, $res_typ:ty, $method:ident, $expect:expr) => {{
            let bytes = [
                0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8, 0x08u8,
            ];
            let mut offset = 0;
            let result = $endian.$method(&mut offset, &bytes).unwrap();
            assert_eq!(result, $expect);
            assert_eq!(offset, core::mem::size_of::<$res_typ>());
        }};
    }

    macro_rules! fuzz_too_short_test {
        ( $endian:expr, $res_typ:ty, $method:ident) => {{
            let bytes = [
                0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8, 0x08u8,
            ];
            let size = core::mem::size_of::<$res_typ>();
            for n in 0..size {
                let buf = bytes.split_at(n).0.as_ref();
                let mut offset: usize = 0;
                let error = $endian
                    .$method(&mut offset, buf)
                    .expect_err("Expected an error, but parsed: ");
                assert!(
                    matches!(error, ParseError::BadOffset(_)),
                    "Unexpected Error type found: {error}"
                );
            }
        }};
    }

    #[test]
    fn parse_u8_at() {
        parse_test!(LittleEndian, u8, parse_u8_at, 0x01u8);
        parse_test!(BigEndian, u8, parse_u8_at, 0x01u8);
        parse_test!(AnyEndian::Little, u8, parse_u8_at, 0x01u8);
        parse_test!(AnyEndian::Big, u8, parse_u8_at, 0x01u8);
    }

    #[test]
    fn parse_u16_at() {
        parse_test!(LittleEndian, u16, parse_u16_at, 0x0201u16);
        parse_test!(BigEndian, u16, parse_u16_at, 0x0102u16);
        parse_test!(AnyEndian::Little, u16, parse_u16_at, 0x0201u16);
        parse_test!(AnyEndian::Big, u16, parse_u16_at, 0x0102u16);
    }

    #[test]
    fn parse_u32_at() {
        parse_test!(LittleEndian, u32, parse_u32_at, 0x04030201u32);
        parse_test!(BigEndian, u32, parse_u32_at, 0x01020304u32);
        parse_test!(AnyEndian::Little, u32, parse_u32_at, 0x04030201u32);
        parse_test!(AnyEndian::Big, u32, parse_u32_at, 0x01020304u32);
    }

    #[test]
    fn parse_u64_at() {
        parse_test!(LittleEndian, u64, parse_u64_at, 0x0807060504030201u64);
        parse_test!(BigEndian, u64, parse_u64_at, 0x0102030405060708u64);
        parse_test!(AnyEndian::Little, u64, parse_u64_at, 0x0807060504030201u64);
        parse_test!(AnyEndian::Big, u64, parse_u64_at, 0x0102030405060708u64);
    }

    #[test]
    fn parse_i32_at() {
        parse_test!(LittleEndian, i32, parse_i32_at, 0x04030201i32);
        parse_test!(BigEndian, i32, parse_i32_at, 0x01020304i32);
        parse_test!(AnyEndian::Little, i32, parse_i32_at, 0x04030201i32);
        parse_test!(AnyEndian::Big, i32, parse_i32_at, 0x01020304i32);
    }

    #[test]
    fn parse_i64_at() {
        parse_test!(LittleEndian, i64, parse_i64_at, 0x0807060504030201i64);
        parse_test!(BigEndian, i64, parse_i64_at, 0x0102030405060708i64);
        parse_test!(AnyEndian::Little, i64, parse_i64_at, 0x0807060504030201i64);
        parse_test!(AnyEndian::Big, i64, parse_i64_at, 0x0102030405060708i64);
    }

    #[test]
    fn fuzz_u8_too_short() {
        fuzz_too_short_test!(LittleEndian, u8, parse_u8_at);
        fuzz_too_short_test!(BigEndian, u8, parse_u8_at);
        fuzz_too_short_test!(AnyEndian::Little, u8, parse_u8_at);
        fuzz_too_short_test!(AnyEndian::Big, u8, parse_u8_at);
    }

    #[test]
    fn fuzz_u16_too_short() {
        fuzz_too_short_test!(LittleEndian, u16, parse_u16_at);
        fuzz_too_short_test!(BigEndian, u16, parse_u16_at);
        fuzz_too_short_test!(AnyEndian::Little, u16, parse_u16_at);
        fuzz_too_short_test!(AnyEndian::Big, u16, parse_u16_at);
    }

    #[test]
    fn fuzz_u32_too_short() {
        fuzz_too_short_test!(LittleEndian, u32, parse_u32_at);
        fuzz_too_short_test!(BigEndian, u32, parse_u32_at);
        fuzz_too_short_test!(AnyEndian::Little, u32, parse_u32_at);
        fuzz_too_short_test!(AnyEndian::Big, u32, parse_u32_at);
    }

    #[test]
    fn fuzz_i32_too_short() {
        fuzz_too_short_test!(LittleEndian, i32, parse_i32_at);
        fuzz_too_short_test!(BigEndian, i32, parse_i32_at);
        fuzz_too_short_test!(AnyEndian::Little, i32, parse_i32_at);
        fuzz_too_short_test!(AnyEndian::Big, i32, parse_i32_at);
    }

    #[test]
    fn fuzz_u64_too_short() {
        fuzz_too_short_test!(LittleEndian, u64, parse_u64_at);
        fuzz_too_short_test!(BigEndian, u64, parse_u64_at);
        fuzz_too_short_test!(AnyEndian::Little, u64, parse_u64_at);
        fuzz_too_short_test!(AnyEndian::Big, u64, parse_u64_at);
    }

    #[test]
    fn fuzz_i64_too_short() {
        fuzz_too_short_test!(LittleEndian, i64, parse_i64_at);
        fuzz_too_short_test!(BigEndian, i64, parse_i64_at);
        fuzz_too_short_test!(AnyEndian::Little, i64, parse_i64_at);
        fuzz_too_short_test!(AnyEndian::Big, i64, parse_i64_at);
    }
}
