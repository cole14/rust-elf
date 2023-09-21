//! Utilities to drive safe and lazy parsing of ELF structures.
use core::{marker::PhantomData, ops::Range};

use crate::endian::EndianParse;
use crate::file::Class;

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
    /// Returned when parsing an ELF struct with a version field whose value wasn't
    /// something we support and know how to parse.
    UnsupportedVersion((u64, u64)),
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
    /// Returned when trying to interpret a section's data as the wrong type.
    /// For example, trying to treat an SHT_PROGBIGS section as a SHT_STRTAB.
    UnexpectedSectionType((u32, u32)),
    /// Returned when trying to interpret a segment's data as the wrong type.
    /// For example, trying to treat an PT_LOAD section as a PT_NOTE.
    UnexpectedSegmentType((u32, u32)),
    /// Returned when a section has a sh_addralign value that was different
    /// than we expected.
    UnexpectedAlignment(usize),
    /// Returned when parsing an ELF structure out of an in-memory `&[u8]`
    /// resulted in a request for a section of file bytes outside the range of
    /// the slice. Commonly caused by truncated file contents.
    SliceReadError((usize, usize)),
    /// Returned when doing math with parsed elf fields that resulted in integer overflow.
    IntegerOverflow,
    /// Returned when parsing a string out of a StringTable that contained
    /// invalid Utf8
    Utf8Error(core::str::Utf8Error),
    /// Returned when parsing an ELF structure and the underlying structure data
    /// was truncated and thus the full structure contents could not be parsed.
    TryFromSliceError(core::array::TryFromSliceError),
    /// Returned when parsing an ELF structure whose on-disk fields were too big
    /// to represent in the native machine's usize type for in-memory processing.
    /// This could be the case when processessing large 64-bit files on a 32-bit machine.
    TryFromIntError(core::num::TryFromIntError),
    #[cfg(feature = "std")]
    /// Returned when parsing an ELF structure out of an io stream encountered
    /// an io error.
    IOError(std::io::Error),
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ParseError::BadMagic(_) => None,
            ParseError::UnsupportedElfClass(_) => None,
            ParseError::UnsupportedElfEndianness(_) => None,
            ParseError::UnsupportedVersion(_) => None,
            ParseError::BadOffset(_) => None,
            ParseError::StringTableMissingNul(_) => None,
            ParseError::BadEntsize(_) => None,
            ParseError::UnexpectedSectionType(_) => None,
            ParseError::UnexpectedSegmentType(_) => None,
            ParseError::UnexpectedAlignment(_) => None,
            ParseError::SliceReadError(_) => None,
            ParseError::IntegerOverflow => None,
            ParseError::Utf8Error(ref err) => Some(err),
            ParseError::TryFromSliceError(ref err) => Some(err),
            ParseError::TryFromIntError(ref err) => Some(err),
            ParseError::IOError(ref err) => Some(err),
        }
    }
}

#[cfg(all(feature = "nightly", not(feature = "std")))]
impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match *self {
            ParseError::BadMagic(_) => None,
            ParseError::UnsupportedElfClass(_) => None,
            ParseError::UnsupportedElfEndianness(_) => None,
            ParseError::UnsupportedVersion(_) => None,
            ParseError::BadOffset(_) => None,
            ParseError::StringTableMissingNul(_) => None,
            ParseError::BadEntsize(_) => None,
            ParseError::UnexpectedSectionType(_) => None,
            ParseError::UnexpectedSegmentType(_) => None,
            ParseError::UnexpectedAlignment(_) => None,
            ParseError::SliceReadError(_) => None,
            ParseError::IntegerOverflow => None,
            ParseError::Utf8Error(ref err) => Some(err),
            ParseError::TryFromSliceError(ref err) => Some(err),
            ParseError::TryFromIntError(ref err) => Some(err),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            ParseError::UnsupportedVersion((found, expected)) => {
                write!(
                    f,
                    "Unsupported ELF Version field found: {found} expected: {expected}"
                )
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
            ParseError::UnexpectedSectionType((found, expected)) => {
                write!(
                    f,
                    "Could not interpret section of type {found} as type {expected}"
                )
            }
            ParseError::UnexpectedSegmentType((found, expected)) => {
                write!(
                    f,
                    "Could not interpret section of type {found} as type {expected}"
                )
            }
            ParseError::UnexpectedAlignment(align) => {
                write!(
                    f,
                    "Could not interpret section with unexpected alignment of {align}"
                )
            }
            ParseError::SliceReadError((start, end)) => {
                write!(f, "Could not read bytes in range [{start:#X}, {end:#X})")
            }
            ParseError::IntegerOverflow => {
                write!(f, "Integer overflow detected")
            }
            ParseError::Utf8Error(ref err) => err.fmt(f),
            ParseError::TryFromSliceError(ref err) => err.fmt(f),
            ParseError::TryFromIntError(ref err) => err.fmt(f),
            #[cfg(feature = "std")]
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

impl From<core::num::TryFromIntError> for ParseError {
    fn from(err: core::num::TryFromIntError) -> Self {
        ParseError::TryFromIntError(err)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IOError(err)
    }
}

/// Trait for safely parsing an ELF structure of a given class (32/64 bit) with
/// an given endian-awareness at the given offset into the data buffer.
///
/// This is the trait that drives our elf parser, where the various ELF
/// structures implement ParseAt in order to parse their Rust-native representation
/// from a buffer, all using safe code.
pub trait ParseAt: Sized {
    /// Parse this type by using the given endian-awareness and ELF class layout.
    /// This is generic on EndianParse in order to allow users to optimize for
    /// their expectations of data layout. See EndianParse for more details.
    fn parse_at<E: EndianParse>(
        endian: E,
        class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError>;

    /// Returns the expected size of the type being parsed for the given ELF class
    fn size_for(class: Class) -> usize;

    /// Checks whether the given entsize matches what we need to parse this type
    ///
    /// Returns a ParseError for bad/unexpected entsizes that don't match what this type parses.
    fn validate_entsize(class: Class, entsize: usize) -> Result<usize, ParseError> {
        let expected = Self::size_for(class);
        match entsize == expected {
            true => Ok(entsize),
            false => Err(ParseError::BadEntsize((entsize as u64, expected as u64))),
        }
    }
}

/// Lazy-parsing iterator which wraps bytes and parses out a `P: ParseAt` on each `next()`
#[derive(Debug)]
pub struct ParsingIterator<'data, E: EndianParse, P: ParseAt> {
    endian: E,
    class: Class,
    data: &'data [u8],
    offset: usize,
    // This struct doesn't technically own a P, but it yields them
    // as it iterates
    pd: PhantomData<&'data P>,
}

impl<'data, E: EndianParse, P: ParseAt> ParsingIterator<'data, E, P> {
    pub fn new(endian: E, class: Class, data: &'data [u8]) -> Self {
        ParsingIterator {
            endian,
            class,
            data,
            offset: 0,
            pd: PhantomData,
        }
    }
}

impl<'data, E: EndianParse, P: ParseAt> Iterator for ParsingIterator<'data, E, P> {
    type Item = P;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        Self::Item::parse_at(self.endian, self.class, &mut self.offset, self.data).ok()
    }
}

/// Lazy-parsing table which wraps bytes and parses out a `P: ParseAt` at a given index into
/// the table on each `get()`.
#[derive(Debug, Clone, Copy)]
pub struct ParsingTable<'data, E: EndianParse, P: ParseAt> {
    endian: E,
    class: Class,
    data: &'data [u8],
    // This struct doesn't technically own a P, but it yields them
    pd: PhantomData<&'data P>,
}

impl<'data, E: EndianParse, P: ParseAt> ParsingTable<'data, E, P> {
    pub fn new(endian: E, class: Class, data: &'data [u8]) -> Self {
        ParsingTable {
            endian,
            class,
            data,
            pd: PhantomData,
        }
    }

    /// Get a lazy-parsing iterator for the table's bytes
    pub fn iter(&self) -> ParsingIterator<'data, E, P> {
        ParsingIterator::new(self.endian, self.class, self.data)
    }

    /// Returns the number of elements of type P in the table.
    pub fn len(&self) -> usize {
        self.data.len() / P::size_for(self.class)
    }

    /// Returns whether the table is empty (contains zero elements).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parse the element at `index` in the table.
    pub fn get(&self, index: usize) -> Result<P, ParseError> {
        if self.data.is_empty() {
            return Err(ParseError::BadOffset(index as u64));
        }

        let entsize = P::size_for(self.class);
        let mut start = index
            .checked_mul(entsize)
            .ok_or(ParseError::IntegerOverflow)?;
        if start > self.data.len() {
            return Err(ParseError::BadOffset(index as u64));
        }

        P::parse_at(self.endian, self.class, &mut start, self.data)
    }
}

impl<'data, E: EndianParse, P: ParseAt> IntoIterator for ParsingTable<'data, E, P> {
    type IntoIter = ParsingIterator<'data, E, P>;
    type Item = P;

    fn into_iter(self) -> Self::IntoIter {
        ParsingIterator::new(self.endian, self.class, self.data)
    }
}

// Simple convenience extension trait to wrap get() with .ok_or(SliceReadError)
pub(crate) trait ReadBytesExt<'data> {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError>;
}

impl<'data> ReadBytesExt<'data> for &'data [u8] {
    fn get_bytes(self, range: Range<usize>) -> Result<&'data [u8], ParseError> {
        let start = range.start;
        let end = range.end;
        self.get(range)
            .ok_or(ParseError::SliceReadError((start, end)))
    }
}

#[cfg(test)]
pub(crate) fn test_parse_for<E: EndianParse, P: ParseAt + core::fmt::Debug + PartialEq>(
    endian: E,
    class: Class,
    expected: P,
) {
    let size = P::size_for(class);
    let mut data = vec![0u8; size];
    for (n, elem) in data.iter_mut().enumerate().take(size) {
        *elem = n as u8;
    }

    let mut offset = 0;
    let entry = P::parse_at(endian, class, &mut offset, data.as_ref()).expect("Failed to parse");

    assert_eq!(entry, expected);
    assert_eq!(offset, size);
}

#[cfg(test)]
pub(crate) fn test_parse_fuzz_too_short<E: EndianParse, P: ParseAt + core::fmt::Debug>(
    endian: E,
    class: Class,
) {
    let size = P::size_for(class);
    let data = vec![0u8; size];
    for n in 0..size {
        let buf = data.split_at(n).0;
        let mut offset: usize = 0;
        let error = P::parse_at(endian, class, &mut offset, buf).expect_err("Expected an error");
        assert!(
            matches!(error, ParseError::SliceReadError(_)),
            "Unexpected Error type found: {error}"
        );
    }
}

#[cfg(test)]
mod read_bytes_tests {
    use super::ParseError;
    use super::ReadBytesExt;

    #[test]
    fn get_bytes_works() {
        let data = &[0u8, 1, 2, 3];
        let subslice = data.get_bytes(1..3).expect("should be within range");
        assert_eq!(subslice, [1, 2]);
    }

    #[test]
    fn get_bytes_out_of_range_errors() {
        let data = &[0u8, 1, 2, 3];
        let err = data.get_bytes(3..9).expect_err("should be out of range");
        assert!(
            matches!(err, ParseError::SliceReadError((3, 9))),
            "Unexpected Error type found: {err}"
        );
    }
}

#[cfg(test)]
mod parsing_table_tests {
    use crate::endian::{AnyEndian, BigEndian, LittleEndian};

    use super::*;

    type U32Table<'data, E> = ParsingTable<'data, E, u32>;

    #[test]
    fn test_u32_validate_entsize() {
        assert!(matches!(u32::validate_entsize(Class::ELF32, 4), Ok(4)));
        assert!(matches!(
            u32::validate_entsize(Class::ELF32, 8),
            Err(ParseError::BadEntsize((8, 4)))
        ));
    }

    #[test]
    fn test_u32_parse_at() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let mut offset = 2;
        let result = u32::parse_at(LittleEndian, Class::ELF32, &mut offset, data.as_ref())
            .expect("Expected to parse but:");
        assert_eq!(result, 0x05040302);
    }

    #[test]
    fn test_u32_table_len() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(LittleEndian, Class::ELF32, data.as_ref());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_u32_table_is_empty() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(LittleEndian, Class::ELF32, data.as_ref());
        assert!(!table.is_empty());

        let table = U32Table::new(LittleEndian, Class::ELF32, &[]);
        assert!(table.is_empty());

        let table = U32Table::new(LittleEndian, Class::ELF32, data.get(0..1).unwrap());
        assert!(table.is_empty());
    }

    #[test]
    fn test_u32_table_get_parse_failure() {
        let data = vec![0u8, 1];
        let table = U32Table::new(LittleEndian, Class::ELF32, data.as_ref());
        assert!(matches!(
            table.get(0),
            Err(ParseError::SliceReadError((0, 4)))
        ));
    }

    #[test]
    fn test_lsb_u32_table_get() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(LittleEndian, Class::ELF32, data.as_ref());
        assert!(matches!(table.get(0), Ok(0x03020100)));
        assert!(matches!(table.get(1), Ok(0x07060504)));
        assert!(matches!(table.get(7), Err(ParseError::BadOffset(7))));
    }

    #[test]
    fn test_any_lsb_u32_table_get() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(AnyEndian::Little, Class::ELF32, data.as_ref());
        assert!(matches!(table.get(0), Ok(0x03020100)));
        assert!(matches!(table.get(1), Ok(0x07060504)));
        assert!(matches!(table.get(7), Err(ParseError::BadOffset(7))));
    }

    #[test]
    fn test_msb_u32_table_get() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(BigEndian, Class::ELF32, data.as_ref());
        assert!(matches!(table.get(0), Ok(0x00010203)));
        assert!(matches!(table.get(1), Ok(0x04050607)));
        assert!(matches!(table.get(7), Err(ParseError::BadOffset(7))));
    }

    #[test]
    fn test_any_msb_u32_table_get() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(AnyEndian::Big, Class::ELF32, data.as_ref());
        assert!(matches!(table.get(0), Ok(0x00010203)));
        assert!(matches!(table.get(1), Ok(0x04050607)));
        assert!(matches!(table.get(7), Err(ParseError::BadOffset(7))));
    }

    #[test]
    fn test_u32_table_get_unaligned() {
        let data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let table = U32Table::new(LittleEndian, Class::ELF32, data.get(1..).unwrap());
        assert!(matches!(table.get(0), Ok(0x04030201)));
    }
}
