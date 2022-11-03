use core::marker::PhantomData;
use core::ops::Range;

#[cfg(feature = "std")]
use std::collections::hash_map::Entry;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};

use crate::endian::EndianParse;

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
            #[cfg(feature = "std")]
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

/// Trait which exposes an interface for getting blocks of bytes from a data source.
pub trait ReadBytesAt {
    /// This is the standard reading method for getting a chunk of in-memory ELF
    /// data from which to parse.
    ///
    /// Note that self is mut here, as this method acts as a "read and return" combination
    /// where the "read" step allows implementers to mutate internal state to serve the read,
    /// and the "return" step returns a reference to the read data.
    ///
    /// If you're wanting to read multiple disjoint chunks of data then the borrowing
    /// semantics here won't let you keep a reference to the first chunk while reading
    /// the next. If you want to do that, try the load_bytes_at() + get_loaded_bytes_at() pairing.
    fn read_bytes_at(&mut self, range: Range<usize>) -> Result<&[u8], ParseError>;

    /// Load a chunk of data from the underlying data source, but don't return a reference to it.
    /// The loaded chunk can be requested by get_loaded_bytes_at().
    ///
    /// This method allows implementers to do multiple disjoint mutating reads on the
    /// underlying data source in a row in order to later provide concurrent immuntable
    /// references to those disjoint chunks of data via get_loaded_bytes_at().
    fn load_bytes_at(&mut self, range: Range<usize>) -> Result<(), ParseError> {
        // Validate that the underlying data does in fact contain the requested range
        self.read_bytes_at(range)?;

        // Now that we did the load/validate step, we're done
        Ok(())
    }

    /// Get a reference to a chunk of data that was previously loaded by load_bytes_at()
    ///
    /// This method allows implementers to do multiple disjoint mutating reads on the
    /// underlying data source in a row in order to later provide concurrent immuntable
    /// references to those disjoint chunks of data via get_loaded_bytes_at().
    ///
    /// Panics if the range was not previously loaded via load_bytes_at()
    /// (logic bug when using this interface)
    fn get_loaded_bytes_at(&self, range: Range<usize>) -> &[u8];
}

impl ReadBytesAt for &[u8] {
    fn read_bytes_at(&mut self, range: Range<usize>) -> Result<&[u8], ParseError> {
        let start = range.start;
        let end = range.end;
        self.get(range)
            .ok_or(ParseError::SliceReadError((start, end)))
    }

    fn get_loaded_bytes_at(&self, range: Range<usize>) -> &[u8] {
        let start = range.start;
        let end = range.end;
        self.get(range)
            .ok_or(ParseError::SliceReadError((start, end)))
            .unwrap()
    }
}

#[cfg(feature = "std")]
pub struct CachedReadBytes<R: Read + Seek> {
    reader: R,
    bufs: HashMap<(u64, u64), Box<[u8]>>,
}

#[cfg(feature = "std")]
impl<R: Read + Seek> CachedReadBytes<R> {
    pub fn new(reader: R) -> Self {
        CachedReadBytes {
            reader,
            bufs: HashMap::<(u64, u64), Box<[u8]>>::default(),
        }
    }
}

#[cfg(feature = "std")]
impl<R: Read + Seek> ReadBytesAt for CachedReadBytes<R> {
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

    fn get_loaded_bytes_at(&self, range: Range<usize>) -> &[u8] {
        let start = range.start as u64;
        let size = range.len() as u64;
        self.bufs.get(&(start, size)).unwrap()
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
        if self.data.len() == 0 {
            return None;
        }

        Self::Item::parse_at(self.endian, self.class, &mut self.offset, self.data).ok()
    }
}

#[derive(Debug)]
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

    pub fn iter(&self) -> ParsingIterator<'data, E, P> {
        ParsingIterator::new(self.endian, self.class, self.data)
    }

    /// Returns the number of elements of type P in the table.
    pub fn len(&self) -> usize {
        self.data.len() / P::size_for(self.class)
    }

    pub fn get(&self, index: usize) -> Result<P, ParseError> {
        if self.data.len() == 0 {
            return Err(ParseError::BadOffset(index as u64));
        }

        let entsize = P::size_for(self.class);
        let mut start = index
            .checked_mul(entsize)
            .ok_or(ParseError::IntegerOverflow)?;
        if start > self.data.len() {
            return Err(ParseError::BadOffset(index as u64));
        }

        Ok(P::parse_at(self.endian, self.class, &mut start, self.data)?)
    }
}

impl<'data, E: EndianParse, P: ParseAt> IntoIterator for ParsingTable<'data, E, P> {
    type IntoIter = ParsingIterator<'data, E, P>;
    type Item = P;

    fn into_iter(self) -> Self::IntoIter {
        ParsingIterator::new(self.endian, self.class, self.data)
    }
}

impl ParseAt for u32 {
    fn parse_at<E: EndianParse>(
        endian: E,
        _class: Class,
        offset: &mut usize,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        Ok(endian.parse_u32_at(offset, data)?)
    }

    #[inline]
    fn size_for(_class: Class) -> usize {
        core::mem::size_of::<u32>()
    }
}

pub type U32Table<'data, E> = ParsingTable<'data, E, u32>;

#[cfg(test)]
pub fn test_parse_for<E: EndianParse, P: ParseAt + core::fmt::Debug + PartialEq>(
    endian: E,
    class: Class,
    expected: P,
) {
    let size = P::size_for(class);
    let mut data = vec![0u8; size];
    for n in 0..size {
        data[n] = n as u8;
    }

    let mut offset = 0;
    let entry = P::parse_at(endian, class, &mut offset, data.as_ref()).expect("Failed to parse");

    assert_eq!(entry, expected);
    assert_eq!(offset, size);
}

#[cfg(test)]
pub fn test_parse_fuzz_too_short<E: EndianParse, P: ParseAt + core::fmt::Debug>(
    endian: E,
    class: Class,
) {
    let size = P::size_for(class);
    let data = vec![0u8; size];
    for n in 0..size {
        let buf = data.split_at(n).0.as_ref();
        let mut offset: usize = 0;
        let error = P::parse_at(endian, class, &mut offset, buf).expect_err("Expected an error");
        assert!(
            matches!(error, ParseError::BadOffset(_)),
            "Unexpected Error type found: {error}"
        );
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
    fn byte_slice_multiple_overlapping_reference_lifetimes() {
        let data = [1u8, 2u8, 3u8, 4u8];
        let slice = data.as_ref();

        slice
            .as_ref()
            .load_bytes_at(0..2)
            .expect("Failed to get expected bytes");
        slice
            .as_ref()
            .load_bytes_at(2..4)
            .expect("Failed to get expected bytes");

        let bytes1 = slice.get_loaded_bytes_at(0..2);
        let bytes2 = slice.get_loaded_bytes_at(2..4);
        assert_eq!(bytes1, [1u8, 2u8]);
        assert_eq!(bytes2, [3u8, 4u8]);
    }

    #[test]
    fn cached_read_bytes_multiple_non_overlapping_reference_lifetimes() {
        let data = [1u8, 2u8, 3u8, 4u8];
        let cur = Cursor::new(data);
        let cached = &mut CachedReadBytes::new(cur);

        let bytes1 = cached
            .read_bytes_at(0..2)
            .expect("Failed to get expected bytes");
        assert_eq!(bytes1, [1u8, 2u8]);
        let bytes2 = cached
            .read_bytes_at(2..4)
            .expect("Failed to get expected bytes");
        assert_eq!(bytes2, [3u8, 4u8]);
    }

    #[test]
    fn cached_read_bytes_multiple_overlapping_reference_lifetimes() {
        let data = [1u8, 2u8, 3u8, 4u8];
        let cur = Cursor::new(data);
        let cached = &mut CachedReadBytes::new(cur);

        cached
            .load_bytes_at(0..2)
            .expect("Failed to get expected bytes");
        cached
            .load_bytes_at(2..4)
            .expect("Failed to get expected bytes");

        let bytes1 = cached.get_loaded_bytes_at(0..2);
        let bytes2 = cached.get_loaded_bytes_at(2..4);
        assert_eq!(bytes1, [1u8, 2u8]);
        assert_eq!(bytes2, [3u8, 4u8]);
    }
}

#[cfg(test)]
mod parsing_table_tests {
    use crate::endian::{AnyEndian, BigEndian, LittleEndian};

    use super::*;

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
}
