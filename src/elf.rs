use core::ops::Range;

use crate::endian::EndianParse;
use crate::file::FileHeader;
use crate::gabi;
use crate::parse::{Class, ParseError};
use crate::segment::SegmentTable;

//  _____ _     _____ ____
// | ____| |   |  ___|  _ \ __ _ _ __ ___  ___ _ __
// |  _| | |   | |_  | |_) / _` | '__/ __|/ _ \ '__|
// | |___| |___|  _| |  __/ (_| | |  \__ \  __/ |
// |_____|_____|_|   |_|   \__,_|_|  |___/\___|_|
//

pub trait ElfParser<'data, E: EndianParse> {
    fn segments(self) -> Result<Option<SegmentTable<'data, E>>, ParseError>;
}

pub trait ReadBytes {
    fn get_bytes(&self, range: Range<usize>) -> Option<&[u8]>;
}

//  _____ _     _____ ____        _
// | ____| |   |  ___| __ ) _   _| |_ ___  ___
// |  _| | |   | |_  |  _ \| | | | __/ _ \/ __|
// | |___| |___|  _| | |_) | |_| | ||  __/\__ \
// |_____|_____|_|   |____/ \__, |\__\___||___/
//                          |___/
//

pub fn from_bytes<'data, E: EndianParse>(
    data: &'data [u8],
) -> Result<ElfBytes<'data, E>, ParseError> {
    let ident_buf = data
        .get_bytes(0..gabi::EI_NIDENT)
        .ok_or(ParseError::SliceReadError((0, gabi::EI_NIDENT)))?;
    let ident = FileHeader::parse_ident(ident_buf)?;

    let tail_start = gabi::EI_NIDENT;
    let tail_end = match ident.1 {
        Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
        Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
    };
    let tail_buf = data
        .get_bytes(tail_start..tail_end)
        .ok_or(ParseError::SliceReadError((tail_start, tail_end)))?;

    let ehdr = FileHeader::parse_tail(ident, tail_buf)?;
    let endian = E::from_ei_data(ehdr.ei_data)?;
    Ok(ElfBytes { ehdr, data, endian })
}

pub struct ElfBytes<'data, E: EndianParse> {
    ehdr: FileHeader,
    data: &'data [u8],
    endian: E,
}

impl<'data, E: EndianParse> ElfParser<'data, E> for &'data ElfBytes<'data, E> {
    fn segments(self) -> Result<Option<SegmentTable<'data, E>>, ParseError> {
        match self.ehdr.get_phdrs_data_range()? {
            Some((start, end)) => {
                let buf = self
                    .data
                    .get_bytes(start..end)
                    .ok_or(ParseError::SliceReadError((start, end)))?;
                Ok(Some(SegmentTable::new(self.endian, self.ehdr.class, buf)))
            }
            None => Ok(None),
        }
    }
}

impl ReadBytes for &[u8] {
    fn get_bytes(&self, range: Range<usize>) -> Option<&[u8]> {
        self.get(range)
    }
}

//  _____ _     _____ ____  _
// | ____| |   |  ___/ ___|| |_ _ __ ___  __ _ _ __ ___
// |  _| | |   | |_  \___ \| __| '__/ _ \/ _` | '_ ` _ \
// | |___| |___|  _|  ___) | |_| | |  __/ (_| | | | | | |
// |_____|_____|_|   |____/ \__|_|  \___|\__,_|_| |_| |_|

#[cfg(feature = "std")]
pub fn from_stream<'data, E: EndianParse, R: std::io::Read + std::io::Seek>(
    reader: R,
) -> Result<ElfStream<E, R>, ParseError> {
    let mut cr = CachingReader::new(reader);
    cr.load_bytes(0..gabi::EI_NIDENT)?;
    let ident_buf = cr
        .get_bytes(0..gabi::EI_NIDENT)
        .ok_or(ParseError::SliceReadError((0, gabi::EI_NIDENT)))?;
    let ident = FileHeader::parse_ident(ident_buf)?;

    let tail_start = gabi::EI_NIDENT;
    let tail_end = match ident.1 {
        Class::ELF32 => tail_start + crate::file::ELF32_EHDR_TAILSIZE,
        Class::ELF64 => tail_start + crate::file::ELF64_EHDR_TAILSIZE,
    };
    cr.load_bytes(tail_start..tail_end)?;
    let tail_buf = cr
        .get_bytes(tail_start..tail_end)
        .ok_or(ParseError::SliceReadError((tail_start, tail_end)))?;

    let ehdr = FileHeader::parse_tail(ident, tail_buf)?;
    let endian = E::from_ei_data(ehdr.ei_data)?;
    Ok(ElfStream {
        reader: cr,
        ehdr,
        endian,
    })
}

#[cfg(feature = "std")]
pub struct ElfStream<E: EndianParse, R: std::io::Read + std::io::Seek> {
    ehdr: FileHeader,
    reader: CachingReader<R>,
    endian: E,
}

#[cfg(feature = "std")]
impl<'data, E: EndianParse, R: std::io::Read + std::io::Seek> ElfParser<'data, E>
    for &'data mut ElfStream<E, R>
{
    fn segments(self) -> Result<Option<SegmentTable<'data, E>>, ParseError> {
        match self.ehdr.get_phdrs_data_range()? {
            Some((start, end)) => {
                self.reader.load_bytes(start..end)?;
                let buf = self
                    .reader
                    .get_bytes(start..end)
                    .ok_or(ParseError::SliceReadError((start, end)))?;
                Ok(Some(SegmentTable::new(self.endian, self.ehdr.class, buf)))
            }
            None => Ok(None),
        }
    }
}

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::io::{Read, Seek, SeekFrom};

#[cfg(feature = "std")]
pub struct CachingReader<R: Read + Seek> {
    reader: R,
    bufs: HashMap<(usize, usize), Box<[u8]>>,
}

#[cfg(feature = "std")]
impl<R: Read + Seek> CachingReader<R> {
    pub fn new(reader: R) -> Self {
        CachingReader {
            reader,
            bufs: HashMap::<(usize, usize), Box<[u8]>>::default(),
        }
    }
}

#[cfg(feature = "std")]
impl<R: Read + Seek> ReadBytes for CachingReader<R> {
    fn get_bytes(&self, range: Range<usize>) -> Option<&[u8]> {
        match self.bufs.get(&(range.start, range.end)) {
            Some(b) => Some(b),
            None => None,
        }
    }
}

#[cfg(feature = "std")]
impl<R: Read + Seek> CachingReader<R> {
    pub fn load_bytes(&mut self, range: Range<usize>) -> Result<(), ParseError> {
        if self.bufs.contains_key(&(range.start, range.end)) {
            return Ok(());
        }

        // Seek before allocating so we error early on bad read requests.
        self.reader.seek(SeekFrom::Start(range.start as u64))?;
        let mut bytes = vec![0; range.len()].into_boxed_slice();
        self.reader.read_exact(&mut bytes)?;
        self.bufs.insert((range.start, range.end), bytes);
        Ok(())
    }
}

//  _            _
// | |_ ___  ___| |_ ___
// | __/ _ \/ __| __/ __|
// | ||  __/\__ \ |_\__ \
//  \__\___||___/\__|___/
//

#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::endian::AnyEndian;
    use crate::segment::ProgramHeader;

    #[test]
    fn segments() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::File::open(path).expect("Could not open file.");
        let mut file = from_stream::<AnyEndian, _>(file_data).expect("Open test1");
        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable")
            .iter()
            .collect();
        assert_eq!(
            segments[0],
            ProgramHeader {
                p_type: gabi::PT_PHDR,
                p_offset: 64,
                p_vaddr: 4194368,
                p_paddr: 4194368,
                p_filesz: 448,
                p_memsz: 448,
                p_flags: 5,
                p_align: 8,
            }
        );
    }
}

#[cfg(test)]
mod bytes_tests {
    use super::*;
    use crate::endian::AnyEndian;
    use crate::segment::ProgramHeader;

    #[test]
    fn segments() {
        let path = std::path::PathBuf::from("tests/samples/test1");
        let file_data = std::fs::read(path).expect("Could not read file.");
        let mut slice = file_data.as_slice();
        let file = from_bytes::<AnyEndian>(&mut slice).expect("Open test1");

        // With the bytes interface, we should be able to get multiple lazy-parsing types concurrently,
        // since the trait is implemented for shared references.
        //
        // Get the segment table
        let iter = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable");

        // Concurrently get the segment table again as an iterator and collect the headers into a vec
        let segments: Vec<ProgramHeader> = file
            .segments()
            .expect("File should have a segment table")
            .expect("Segment table should be parsable")
            .iter()
            .collect();

        let expected_phdr = ProgramHeader {
            p_type: gabi::PT_PHDR,
            p_offset: 64,
            p_vaddr: 4194368,
            p_paddr: 4194368,
            p_filesz: 448,
            p_memsz: 448,
            p_flags: 5,
            p_align: 8,
        };

        // Assert we parsed the first header correctly
        assert_eq!(segments[0], expected_phdr);

        // Now use the original lazy-parsing table to parse out the first entry
        assert_eq!(
            iter.get(0).expect("should be able to parse phdr"),
            expected_phdr
        )
    }
}
