//! An all-safe-code endian-aware integer parsing implementation via the
//! [EndianParse] trait.
//!
//! This module provides four endian parsing implementations optimized to support the different
//! common use-cases for an ELF parsing library.  Each trait impl represents a
//! specification that encapsulates an interface for parsing integers from some
//! set of allowed byte orderings.
//!
//! * [AnyEndian]: Dynamically parsing either byte order at runtime based on the type of ELF object being parsed.
//! * [BigEndian]/[LittleEndian]: For tools that know they only want to parse a single given byte order known at compile time.
//! * [type@NativeEndian]: For tools that know they want to parse the same byte order as the target's byte order.
//
// Note:
//   I'd love to see this get replaced with safe transmutes, if that RFC ever gets formalized.
//   Until then, this crate serves as an example implementation for what's possible with purely safe rust.
use crate::abi;
use crate::parse::ParseError;

/// This macro writes out safe code to get a subslice from the the byte slice $data
/// at the given $off as a [u8; size_of<$typ>], then calls the corresponding safe
/// endian-aware conversion on it.
///
/// This uses safe integer math and returns a ParseError on overflow or if $data did
/// not contain enough bytes at $off to perform the conversion.
macro_rules! safe_from {
    ( $self:ident, $typ:ty, $off:ident, $data:ident) => {{
        const SIZE: usize = core::mem::size_of::<$typ>();

        let end = (*$off)
            .checked_add(SIZE)
            .ok_or(ParseError::IntegerOverflow)?;

        let buf: [u8; SIZE] = $data
            .get(*$off..end)
            .ok_or(ParseError::SliceReadError((*$off, end)))?
            .try_into()?;

        *$off = end;

        // Note: This check evaluates to a constant true/false for the "fixed" types
        // so the compiler should optimize out the check (LittleEndian, BigEndian, NativeEndian)
        if $self.is_little() {
            Ok(<$typ>::from_le_bytes(buf))
        } else {
            Ok(<$typ>::from_be_bytes(buf))
        }
    }};
}

/// An all-safe-code endian-aware integer parsing trait.
///
/// These methods use safe code to get a subslice from the the byte slice $data
/// at the given $off as a [u8; size_of<$typ>], then calls the corresponding safe
/// endian-aware conversion on it.
///
/// These use checked integer math and returns a ParseError on overflow or if $data did
/// not contain enough bytes at $off to perform the conversion.
pub trait EndianParse: Clone + Copy + Default + PartialEq + Eq {
    fn parse_u8_at(self, offset: &mut usize, data: &[u8]) -> Result<u8, ParseError> {
        safe_from!(self, u8, offset, data)
    }

    fn parse_u16_at(self, offset: &mut usize, data: &[u8]) -> Result<u16, ParseError> {
        safe_from!(self, u16, offset, data)
    }

    fn parse_u32_at(self, offset: &mut usize, data: &[u8]) -> Result<u32, ParseError> {
        safe_from!(self, u32, offset, data)
    }

    fn parse_u64_at(self, offset: &mut usize, data: &[u8]) -> Result<u64, ParseError> {
        safe_from!(self, u64, offset, data)
    }

    fn parse_i32_at(self, offset: &mut usize, data: &[u8]) -> Result<i32, ParseError> {
        safe_from!(self, i32, offset, data)
    }

    fn parse_i64_at(self, offset: &mut usize, data: &[u8]) -> Result<i64, ParseError> {
        safe_from!(self, i64, offset, data)
    }

    /// Get an endian-aware integer parsing spec for an ELF [FileHeader](crate::file::FileHeader)'s
    /// `ident[EI_DATA]` byte.
    ///
    /// Returns an [UnsupportedElfEndianness](ParseError::UnsupportedElfEndianness) if this spec
    /// doesn't support parsing the byte-order represented by ei_data. If you're
    /// seeing this error, are you trying to read files of any endianness? i.e.
    /// did you want to use AnyEndian?
    fn from_ei_data(ei_data: u8) -> Result<Self, ParseError>;

    fn is_little(self) -> bool;

    #[inline(always)]
    fn is_big(self) -> bool {
        !self.is_little()
    }
}

/// An endian parsing type that can choose at runtime which byte order to parse integers as.
/// This is useful for scenarios where a single compiled binary wants to dynamically
/// interpret ELF files of any byte order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AnyEndian {
    /// Used for a little-endian ELF structures that have been parsed with AnyEndian
    #[default]
    Little,
    /// Used for a big-endian ELF structures that have been parsed with AnyEndian
    Big,
}

/// A zero-sized type that always parses integers as if they're in little-endian order.
/// This is useful for scenarios where a combiled binary knows it only wants to interpret
/// little-endian ELF files and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LittleEndian;

/// A zero-sized type that always parses integers as if they're in big-endian order.
/// This is useful for scenarios where a combiled binary knows it only wants to interpret
/// big-endian ELF files and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BigEndian;

/// A zero-sized type that always parses integers as if they're in the compilation target's native-endian order.
/// This is useful for toolchain scenarios where a combiled binary knows it only wants to interpret
/// ELF files compiled for the same target and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;

#[cfg(target_endian = "little")]
#[allow(non_upper_case_globals)]
#[doc(hidden)]
pub const NativeEndian: LittleEndian = LittleEndian;

/// A zero-sized type that always parses integers as if they're in the compilation target's native-endian order.
/// This is useful for toolchain scenarios where a combiled binary knows it only wants to interpret
/// ELF files compiled for the same target and doesn't want the performance penalty of evaluating a match
/// each time it parses an integer.
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

#[cfg(target_endian = "big")]
#[allow(non_upper_case_globals)]
#[doc(hidden)]
pub const NativeEndian: BigEndian = BigEndian;

impl EndianParse for LittleEndian {
    fn from_ei_data(ei_data: u8) -> Result<Self, ParseError> {
        match ei_data {
            abi::ELFDATA2LSB => Ok(LittleEndian),
            _ => Err(ParseError::UnsupportedElfEndianness(ei_data)),
        }
    }

    #[inline(always)]
    fn is_little(self) -> bool {
        true
    }
}

impl EndianParse for BigEndian {
    fn from_ei_data(ei_data: u8) -> Result<Self, ParseError> {
        match ei_data {
            abi::ELFDATA2MSB => Ok(BigEndian),
            _ => Err(ParseError::UnsupportedElfEndianness(ei_data)),
        }
    }

    #[inline(always)]
    fn is_little(self) -> bool {
        false
    }
}

impl EndianParse for AnyEndian {
    fn from_ei_data(ei_data: u8) -> Result<Self, ParseError> {
        match ei_data {
            abi::ELFDATA2LSB => Ok(AnyEndian::Little),
            abi::ELFDATA2MSB => Ok(AnyEndian::Big),
            _ => Err(ParseError::UnsupportedElfEndianness(ei_data)),
        }
    }

    #[inline(always)]
    fn is_little(self) -> bool {
        match self {
            AnyEndian::Little => true,
            AnyEndian::Big => false,
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
                    matches!(error, ParseError::SliceReadError(_)),
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
